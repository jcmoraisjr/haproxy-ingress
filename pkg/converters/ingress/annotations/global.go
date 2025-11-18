/*
Copyright 2019 The HAProxy Ingress Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package annotations

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func buildGlobalVars(global *hatypes.Global) map[string]string {
	return map[string]string{
		"%[peers_group_global]": hatypes.PeersGroupNameGlobal,
		"%[peers_table_global]": buildPeersTableName(hatypes.PeersGroupNameGlobal, global.Peers.LocalPeer.BESuffix),
	}
}

func (c *updater) buildGlobalAcme(d *globalData) {
	endpoint := d.mapper.Get(ingtypes.GlobalAcmeEndpoint).Value
	if endpoint == "" {
		return
	}
	emails := d.mapper.Get(ingtypes.GlobalAcmeEmails).Value
	if emails == "" {
		c.logger.Warn("skipping acme config, missing email account")
		return
	}
	termsAgreed := d.mapper.Get(ingtypes.GlobalAcmeTermsAgreed).Bool()
	if !termsAgreed {
		c.logger.Warn("acme terms was not agreed, configure '%s' with \"true\" value", ingtypes.GlobalAcmeTermsAgreed)
		return
	}
	d.acmeData.Emails = emails
	d.acmeData.Endpoint = endpoint
	d.acmeData.Expiring = time.Duration(d.mapper.Get(ingtypes.GlobalAcmeExpiring).Int()) * 24 * time.Hour
	d.acmeData.TermsAgreed = termsAgreed
	d.global.Acme.Prefix = "/.well-known/acme-challenge/"
	d.global.Acme.Socket = c.options.AcmeSocket
	d.global.Acme.Enabled = true
	d.global.Acme.Shared = d.mapper.Get(ingtypes.GlobalAcmeShared).Bool()
}

var authProxyRegex = regexp.MustCompile(`^([A-Za-z_-]+):([0-9]{1,5})-([0-9]{1,5})$`)

func (c *updater) buildGlobalAuthProxy(d *globalData) {
	proxystr := d.mapper.Get(ingtypes.GlobalAuthProxy).Value
	proxy := authProxyRegex.FindStringSubmatch(proxystr)
	authproxy := &c.haproxy.Frontends().AuthProxy
	if len(proxy) < 4 {
		c.logger.Warn("invalid auth proxy configuration: %s", proxystr)
		// start>end ensures that trying to create a frontend bind will fail
		authproxy.RangeStart = 0
		authproxy.RangeEnd = -1
		return
	}
	authproxy.Name = proxy[1]
	authproxy.RangeStart, _ = strconv.Atoi(proxy[2])
	authproxy.RangeEnd, _ = strconv.Atoi(proxy[3])
}

func (c *updater) buildGlobalCloseSessions(d *globalData) {
	durationCfg := d.mapper.Get(ingtypes.GlobalCloseSessionsDuration).Value
	if durationCfg == "" {
		return
	}
	if !c.options.TrackInstances {
		c.logger.Warn("ignoring close-sessions-duration config: tracking old instances is disabled")
		return
	}
	timeoutCfg := d.mapper.Get(ingtypes.GlobalTimeoutStop).Value
	if timeoutCfg == "" {
		c.logger.Warn("ignoring close-sessions-duration config: timeout-stop need to be configured")
		return
	}
	timeout, err := time.ParseDuration(timeoutCfg)
	if err != nil {
		c.logger.Warn("ignoring close-sessions-duration due to invalid timeout-stop config: %v", err)
		return
	}
	var duration time.Duration
	if strings.HasSuffix(durationCfg, "%") {
		pct, _ := strconv.Atoi(durationCfg[:len(durationCfg)-1])
		if pct < 2 || pct > 98 {
			c.logger.Warn("ignoring '%s' for close-sessions-duration value: value should be between 5%% and 95%%", durationCfg)
			return
		}
		duration = timeout * time.Duration(pct) / 100
	} else {
		duration, err = time.ParseDuration(durationCfg)
		if err == nil {
			if duration >= timeout {
				err = fmt.Errorf("close-sessions-duration should be lower than timeout-stop")
			}
		}
		if err != nil {
			c.logger.Warn("ignoring invalid close-sessions-duration config: %v", err)
			return
		}
	}
	d.global.CloseSessionsDuration = duration
	d.global.Timeout.Stats = timeoutCfg
}

func (c *updater) buildGlobalPathTypeOrder(d *globalData) {
	matchTypes := make(map[hatypes.MatchType]struct{}, len(hatypes.DefaultMatchOrder))
	for _, match := range hatypes.DefaultMatchOrder {
		matchTypes[match] = struct{}{}
	}
	orderStr := d.mapper.Get(ingtypes.GlobalPathTypeOrder).Value
	orderSlice := strings.Split(orderStr, ",")
	order := make([]hatypes.MatchType, len(orderSlice))
	d.global.MatchOrder = hatypes.DefaultMatchOrder
	for i, matchStr := range orderSlice {
		// 1) filling final `order` slice, 2) identifying invalid and 3) not used matches
		match := hatypes.MatchType(matchStr)
		if _, found := matchTypes[match]; found {
			order[i] = match
			delete(matchTypes, match)
		} else {
			c.logger.Warn("invalid or duplicated path type '%s', using default order %v", matchStr, hatypes.DefaultMatchOrder)
			return
		}
	}
	if len(matchTypes) > 0 {
		c.logger.Warn("all path types should be used in %v, using default order %v", order, hatypes.DefaultMatchOrder)
		return
	}
	d.global.MatchOrder = order
}

func (c *updater) buildGlobalPeers(d *globalData) {
	port := d.mapper.Get(ingtypes.GlobalPeersPort).Int()
	if port == 0 {
		return
	}

	var peers []hatypes.PeersServer
	var localPeer *hatypes.PeersServer
	localPod := c.cache.GetControllerPod()
	if pods, err := c.cache.GetControllerPodList(); err == nil {
		var peerNames []string
		for _, pod := range pods {
			if pod.Status.PodIP == "" {
				c.logger.InfoV(2, "ignoring pod %s, missing IP address", pod.Name)
				continue
			}
			if pod.DeletionTimestamp != nil {
				c.logger.InfoV(2, "ignoring pod %s, deleting", pod.Name)
				continue
			}
			peer := hatypes.PeersServer{
				Name:     pod.Name,
				Endpoint: fmt.Sprintf("%s:%d", pod.Status.PodIP, port),
			}
			peers = append(peers, peer)
			if pod.Name == localPod.Name {
				localPeer = &peer
			}
			peerNames = append(peerNames, peer.Name)
		}
		if len(pods) == 0 {
			// maybe an issue on our side, like not using proper labels when filtering,
			// or cluster is bootstrapping, new reconciliations should fix.
			c.logger.Error("error building peers config: no controller pod was found")
		}
		var localPeerName string
		if localPeer != nil {
			localPeerName = localPeer.Name
		} else {
			localPeerName = "<not-found>"
			// this might happen in the very beginning, when this instance does not have an IP address,
			// or in the end, just after this instance is scheduled to be deleted.
			c.logger.Warn(
				"current pod '%s' was not found in the list of configured peers: %s",
				localPod.String(), strings.Join(peerNames, ","))
		}
		c.logger.Info("updating peers - local: '%s' list: '%s'", localPeerName, strings.Join(peerNames, ","))
	} else {
		c.logger.Error("error building peers config: error reading controller pods: %s", err.Error())
	}

	// default config in the case of any issue, so a bare minimum section
	// is created and we avoid errors on stick tables pointing to it.
	if localPeer == nil || len(peers) == 0 {
		localPeer = &hatypes.PeersServer{
			Name:     localPod.Name,
			Endpoint: fmt.Sprintf(":%d", port),
		}
		peers = []hatypes.PeersServer{*localPeer}
	}

	// predictable output, and same order on all haproxy instances
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })

	for i := range peers {
		id := fmt.Sprintf("proxy%02d", i+1) // used to name local backend/stick tables, avoiding too long names
		peers[i].BESuffix = id
		if localPeer.Name == peers[i].Name {
			localPeer.BESuffix = id
		}
	}

	// this is being called on partial parsing without a previous cleanup, so it should be idempotent
	globalPeers := &c.haproxy.Global().Peers
	globalPeers.SectionName = d.mapper.Get(ingtypes.GlobalPeersName).Value
	globalPeers.GlobalTable = d.mapper.Get(ingtypes.GlobalPeersTableGlobal).Value
	globalPeers.LocalPeer = *localPeer
	globalPeers.Servers = peers
	globalPeers.Tables = nil // config.SyncConfig() takes care of this one, after running all the backend updaters
}

func (c *updater) buildGlobalProc(d *globalData) {
	balance := d.mapper.Get(ingtypes.GlobalNbprocBalance).Int()
	if balance < 1 {
		c.logger.Warn("invalid value of nbproc-balance configmap option (%v), using 1", balance)
		balance = 1
	}
	if balance > 1 {
		// need to visit (at least) statistics and healthz bindings as well
		// as admin socket before using more than one balance backend
		c.logger.Warn("nbproc-balance configmap option (%v) greater than 1 is not yet supported, using 1", balance)
		balance = 1
	}
	ssl := d.mapper.Get(ingtypes.GlobalNbprocSSL).Int()
	if ssl < 0 {
		c.logger.Warn("invalid value of nbproc-ssl configmap option (%v), using 0", ssl)
		ssl = 0
	}
	if ssl > 0 {
		c.logger.Warn("v08 controller does not support nbproc-ssl, using 0")
		ssl = 0
	}
	procs := balance + ssl
	threads := d.mapper.Get(ingtypes.GlobalNbthread).Int()
	if threads < 0 {
		c.logger.Warn("ignoring invalid value of nbthread: %d", threads)
		threads = 0
	}
	bindprocBalance := "1"
	if balance > 1 {
		bindprocBalance = fmt.Sprintf("1-%v", balance)
	}
	bindprocSSL := ""
	if ssl == 0 {
		bindprocSSL = bindprocBalance
	} else if ssl == 1 {
		bindprocSSL = fmt.Sprintf("%v", balance+1)
	} else if ssl > 1 {
		bindprocSSL = fmt.Sprintf("%v-%v", balance+1, procs)
	}
	useCPUMap := d.mapper.Get(ingtypes.GlobalUseCPUMap).Bool()
	cpumap := ""
	if useCPUMap {
		cpumap = d.mapper.Get(ingtypes.GlobalCPUMap).Value
		if cpumap == "" {
			if threads > 1 {
				if procs == 1 {
					cpumap = fmt.Sprintf("auto:1/1-%v 0-%v", threads, threads-1)
				}
			} else if procs > 1 {
				cpumap = fmt.Sprintf("auto:1-%v 0-%v", procs, procs-1)
			}
		}
	}
	d.global.Procs.Nbproc = procs
	d.global.Procs.Nbthread = threads
	d.global.Procs.NbprocBalance = balance
	d.global.Procs.NbprocSSL = ssl
	d.global.Procs.BindprocBalance = bindprocBalance
	d.global.Procs.BindprocSSL = bindprocSSL
	d.global.Procs.CPUMap = cpumap
}

func (c *updater) buildGlobalStats(d *globalData) {
	// healthz
	d.global.Healthz.BindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrHealthz).Value
	d.global.Healthz.Port = d.mapper.Get(ingtypes.GlobalHealthzPort).Int()
	// prometheus
	d.global.Prometheus.BindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrPrometheus).Value
	d.global.Prometheus.Port = d.mapper.Get(ingtypes.GlobalPrometheusPort).Int()
	// stats
	d.global.Stats.AcceptProxy = d.mapper.Get(ingtypes.GlobalStatsProxyProtocol).Bool()
	d.global.Stats.Auth = d.mapper.Get(ingtypes.GlobalStatsAuth).Value
	d.global.Stats.BindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrStats).Value
	d.global.Stats.Port = d.mapper.Get(ingtypes.GlobalStatsPort).Int()
	if tlsSecret := d.mapper.Get(ingtypes.GlobalStatsSSLCert).Value; tlsSecret != "" {
		if tls, err := c.cache.GetTLSSecretPath("", tlsSecret, nil); err == nil {
			d.global.Stats.TLSFilename = tls.Filename
			d.global.Stats.TLSHash = tls.SHA1Hash
		} else {
			c.logger.Warn("ignore TLS config on stats endpoint: %v", err)
		}
	}
}

func (c *updater) buildGlobalSyslog(d *globalData) {
	d.global.Syslog.Endpoint = d.mapper.Get(ingtypes.GlobalSyslogEndpoint).Value
	d.global.Syslog.Format = d.mapper.Get(ingtypes.GlobalSyslogFormat).Value
	d.global.Syslog.Length = d.mapper.Get(ingtypes.GlobalSyslogLength).Int()
	d.global.Syslog.Tag = d.mapper.Get(ingtypes.GlobalSyslogTag).Value
	//
	d.global.Syslog.AuthLogFormat = d.mapper.Get(ingtypes.GlobalAuthLogFormat).Value
	d.global.Syslog.HTTPLogFormat = d.mapper.Get(ingtypes.GlobalHTTPLogFormat).Value
	d.global.Syslog.HTTPSLogFormat = d.mapper.Get(ingtypes.GlobalHTTPSLogFormat).Value
	d.global.Syslog.TCPLogFormat = d.mapper.Get(ingtypes.GlobalTCPLogFormat).Value
}

func (c *updater) buildGlobalTimeout(d *globalData) {
	d.global.Timeout.Client = c.validateTime(d.mapper.Get(ingtypes.GlobalTimeoutClient))
	d.global.Timeout.ClientFin = c.validateTime(d.mapper.Get(ingtypes.GlobalTimeoutClientFin))
	d.global.Timeout.Connect = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutConnect))
	d.global.Timeout.HTTPRequest = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutHTTPRequest))
	d.global.Timeout.KeepAlive = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutKeepAlive))
	d.global.Timeout.Queue = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutQueue))
	d.global.Timeout.Server = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutServer))
	d.global.Timeout.ServerFin = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutServerFin))
	d.global.Timeout.Stop = c.validateTime(d.mapper.Get(ingtypes.GlobalTimeoutStop))
	d.global.Timeout.Tunnel = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutTunnel))
	if timeoutStop, err := time.ParseDuration(d.global.Timeout.Stop); err == nil {
		d.global.TimeoutStopDuration = timeoutStop
	}
}

func (c *updater) buildGlobalSecurity(d *globalData) {
	username := d.mapper.Get(ingtypes.GlobalUsername).Value
	groupname := d.mapper.Get(ingtypes.GlobalGroupname).Value
	if (username == "") != (groupname == "") {
		c.logger.Warn("if configuring non root user, both username and groupname must be defined")
		username = ""
		groupname = ""
	}
	haproxy := "haproxy"
	useHaproxyUser := d.mapper.Get(ingtypes.GlobalUseHAProxyUser).Bool()
	if useHaproxyUser {
		if username == "" {
			username, groupname = haproxy, haproxy
		} else if username != haproxy || groupname != haproxy {
			c.logger.Warn("username and groupname are already defined as '%s' and '%s', ignoring '%s' config", username, groupname, ingtypes.GlobalUseHAProxyUser)
		}
	}
	d.global.Security.Username = username
	d.global.Security.Groupname = groupname
	d.global.Security.UseChroot = d.mapper.Get(ingtypes.GlobalUseChroot).Bool()
}

func (c *updater) buildGlobalSSL(d *globalData) {
	ssl := &d.global.SSL
	ssl.ALPN = d.mapper.Get(ingtypes.HostTLSALPN).Value
	ssl.Ciphers = d.mapper.Get(ingtypes.HostSSLCiphers).Value
	ssl.CipherSuites = d.mapper.Get(ingtypes.HostSSLCipherSuites).Value
	ssl.BackendCiphers = d.mapper.Get(ingtypes.BackSSLCiphersBackend).Value
	ssl.BackendCipherSuites = d.mapper.Get(ingtypes.BackSSLCipherSuitesBackend).Value
	if sslDHParam := d.mapper.Get(ingtypes.GlobalSSLDHParam).Value; sslDHParam != "" {
		if dhFile, err := c.cache.GetDHSecretPath("", sslDHParam); err == nil {
			ssl.DHParam.Filename = dhFile.Filename
		} else {
			c.logger.Error("error reading DH params: %v", err)
		}
	}
	ssl.DHParam.DefaultMaxSize = d.mapper.Get(ingtypes.GlobalSSLDHDefaultMaxSize).Int()
	ssl.Engine = d.mapper.Get(ingtypes.GlobalSSLEngine).Value
	ssl.HeadersPrefix = d.mapper.Get(ingtypes.GlobalSSLHeadersPrefix).Value
	ssl.ModeAsync = d.mapper.Get(ingtypes.GlobalSSLModeAsync).Bool()
	ssl.Options = d.mapper.Get(ingtypes.GlobalSSLOptions).Value
	ssl.RedirectCode = d.mapper.Get(ingtypes.GlobalSSLRedirectCode).Int()
	ssl.SSLRedirect = d.mapper.Get(ingtypes.BackSSLRedirect).Bool()
}

func (c *updater) buildGlobalModSecurity(d *globalData) {
	d.global.ModSecurity.Endpoints = utils.Split(d.mapper.Get(ingtypes.GlobalModsecurityEndpoints).Value, ",")
	d.global.ModSecurity.Timeout.Connect = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutConnect))
	d.global.ModSecurity.Timeout.Hello = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutHello))
	d.global.ModSecurity.Timeout.Idle = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutIdle))
	d.global.ModSecurity.Timeout.Processing = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutProcessing))
	d.global.ModSecurity.Timeout.Server = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutServer))
	d.global.ModSecurity.Args = utils.Split(d.mapper.Get(ingtypes.GlobalModsecurityArgs).Value, " ")
	d.global.ModSecurity.UseCoraza = d.mapper.Get(ingtypes.GlobalModsecurityUseCoraza).Bool()
}

func (c *updater) buildGlobalDNS(d *globalData) {
	resolvers := d.mapper.Get(ingtypes.GlobalDNSResolvers).Value
	if resolvers == "" {
		return
	}
	payloadSize := d.mapper.Get(ingtypes.GlobalDNSAcceptedPayloadSize).Int()
	holdObsolete := c.validateTime(d.mapper.Get(ingtypes.GlobalDNSHoldObsolete))
	holdValid := c.validateTime(d.mapper.Get(ingtypes.GlobalDNSHoldValid))
	timeoutRetry := c.validateTime(d.mapper.Get(ingtypes.GlobalDNSTimeoutRetry))
	for _, resolver := range utils.LineToSlice(resolvers) {
		if resolver == "" {
			continue
		}
		resolverData := strings.Split(resolver, "=")
		if len(resolverData) != 2 {
			c.logger.Warn("ignoring misconfigured resolver: %s", resolver)
			continue
		}
		dnsResolver := &hatypes.DNSResolver{
			Name:                resolverData[0],
			AcceptedPayloadSize: payloadSize,
			HoldObsolete:        holdObsolete,
			HoldValid:           holdValid,
			TimeoutRetry:        timeoutRetry,
		}
		var i int
		for _, ns := range strings.Split(resolverData[1], ",") {
			if ns == "" {
				continue
			}
			if !strings.Contains(ns, ":") {
				// missing port number
				ns += ":53"
			}
			i++
			dnsResolver.Nameservers = append(dnsResolver.Nameservers, &hatypes.DNSNameserver{
				Name:     fmt.Sprintf("ns%02d", i),
				Endpoint: ns,
			})
		}
		d.global.DNS.Resolvers = append(d.global.DNS.Resolvers, dnsResolver)
	}
	d.global.DNS.ClusterDomain = d.mapper.Get(ingtypes.GlobalDNSClusterDomain).Value
}

func (c *updater) buildGlobalDynamic(d *globalData) {
	// Secrets
	staticSecrets := c.options.DynamicConfig.StaticCrossNamespaceSecrets
	c.options.DynamicConfig.CrossNamespaceSecretCA =
		staticSecrets || c.validateAllowDeny(d, ingtypes.GlobalCrossNamespaceSecretsCA)
	c.options.DynamicConfig.CrossNamespaceSecretCertificate =
		staticSecrets || c.validateAllowDeny(d, ingtypes.GlobalCrossNamespaceSecretsCrt)
	c.options.DynamicConfig.CrossNamespaceSecretPasswd =
		staticSecrets || c.validateAllowDeny(d, ingtypes.GlobalCrossNamespaceSecretsPasswd)

	// Services
	c.options.DynamicConfig.CrossNamespaceServices =
		c.validateAllowDeny(d, ingtypes.GlobalCrossNamespaceServices)
}

var forwardRegex = regexp.MustCompile(`^(add|update|ignore|ifmissing)$`)
var headerNameRegex = regexp.MustCompile(`^[A-Za-z0-9-]*$`)

func (c *updater) buildGlobalForwardFor(d *globalData) {
	// TODO: need a small refactor on map builder and ingress converter creation,
	// so that globals can be validated via validator as any other annotation based config
	validateString := func(regex *regexp.Regexp, key, defaultValue string) string {
		value := d.mapper.Get(key).Value
		if !regex.MatchString(value) {
			c.logger.Warn("Invalid %s value option on ConfigMap: '%s'. Using '%s' instead", key, value, defaultValue)
			return defaultValue
		}
		return value
	}
	d.global.ForwardFor = validateString(forwardRegex, ingtypes.GlobalForwardfor, "add")
	d.global.OriginalForwardedForHdr = validateString(headerNameRegex, ingtypes.GlobalOriginalForwardedForHdr, "X-Original-Forwarded-For")
	d.global.RealIPHdr = validateString(headerNameRegex, ingtypes.GlobalRealIPHdr, "X-Real-IP")
}

func (c *updater) buildGlobalCustomConfig(d *globalData) {
	d.global.CustomConfig = utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigGlobal).Value)
	d.global.CustomDefaults = utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigDefaults).Value)
	d.global.CustomFrontendEarly = utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigFrontendEarly).Value)
	// Keep old behavior for config-frontend mapping it to config-frontend-late
	// If both are specified a warning is returned and config-frontend-late is used instead
	customFrontendLate := utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigFrontendLate).Value)
	customFrontend := utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigFrontend).Value)
	selectedCustomFrontendConf := customFrontendLate

	if len(customFrontendLate) == 0 {
		selectedCustomFrontendConf = customFrontend
	} else if len(customFrontend) > 0 {
		c.logger.Warn("both config-frontend and config-frontend-late were used, ignoring config-frontend")
	}
	d.global.CustomFrontendLate = selectedCustomFrontendConf

	d.global.CustomPeers = utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigPeers).Value)
	d.global.CustomSections = utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigSections).Value)
	d.global.CustomTCP = utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigTCP).Value)
	proxy := map[string][]string{}
	var curSection string
	for _, line := range utils.PatternLineToSlice(c.vars, d.mapper.Get(ingtypes.GlobalConfigProxy).Value) {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			curSection = line
			continue
		}
		proxy[curSection] = append(proxy[curSection], strings.TrimSpace(line))
	}
	if lines, hasEmpty := proxy[""]; hasEmpty {
		c.logger.Warn("non scoped %d line(s) in the config-proxy configuration were ignored", len(lines))
		delete(proxy, "")
	}
	d.global.CustomProxy = proxy
}

func (c *updater) buildGlobalCustomResponses(d *globalData) {
	res := c.buildHTTPResponses(d.mapper, keyScopeGlobal)
	res.ID = hatypes.HTTPResponseGlobalID
	d.global.CustomHTTPResponses = res
}

func (c *updater) buildGlobalFastCGI(d *globalData) {
	var configuredApps []string
	for _, line := range utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigSections).Value) {
		keywords := strings.Fields(line)
		if len(keywords) >= 2 && keywords[0] == "fcgi-app" {
			configuredApps = append(configuredApps, keywords[1])
		}
	}
	var enabledApps, notFoundApps []string
	if apps := d.mapper.Get(ingtypes.GlobalFCGIEnabledApps).Value; apps == "*" {
		enabledApps = configuredApps
	} else {
		for _, app := range utils.Split(apps, ",") {
			if slices.Contains(configuredApps, app) {
				enabledApps = append(enabledApps, app)
			} else {
				notFoundApps = append(notFoundApps, app)
			}
		}
	}
	if len(notFoundApps) > 0 {
		c.logger.Warn("ignoring FastCGI app(s) declared as enabled but not configured via config-sections: %s", strings.Join(notFoundApps, ", "))
	}
	d.global.FastCGIApps = enabledApps
}

// TODO these defaults should be in default.go but currently ingress parsing
// doesn't preserve the hardcoded default, overwriting it with the user's
// provided one. We need it in the case that the user input has some error.
// Need to improve this behavior and then we can move this to the defaults.
const (
	httpResponse404 = `404
Content-Type: text/html
Cache-Control: no-cache

<html><body><h1>404 Not Found</h1>
The requested URL was not found.
</body></html>
`

	httpResponse413 = `413
Content-Type: text/html
Cache-Control: no-cache

<html><body><h1>413 Request Entity Too Large</h1>
The request is too large.
</body></html>
`

	httpResponse421 = `421
Content-Type: text/html
Cache-Control: no-cache

<html><body><h1>421 Misdirected Request</h1>
Request sent to a non-authoritative server.
</body></html>
`

	httpResponse495 = `495
Content-Type: text/html
Cache-Control: no-cache

<html><body><h1>495 SSL Certificate Error</h1>
An invalid certificate has been provided.
</body></html>
`

	httpResponse496 = `496
Content-Type: text/html
Cache-Control: no-cache

<html><body><h1>496 SSL Certificate Required</h1>
A client certificate must be provided.
</body></html>
`

	httpResponsePrometheusRoot = `200
Content-Type: text/html
Cache-Control: no-cache

<html>
<head><title>HAProxy Exporter</title></head>
<body><h1>HAProxy Exporter</h1>
<a href='/metrics'>Metrics</a>
</body></html>
`
)

type keyScope int

const (
	keyScopeHost keyScope = iota
	keyScopeBackend
	keyScopeGlobal
)

var customHTTPResponses = []struct {
	name   string
	code   int
	scope  keyScope
	reason string
	key    string
	def    string
}{
	// Lua based
	{"send-prometheus-root", 200, keyScopeGlobal, "OK", ingtypes.GlobalHTTPResponsePrometheusRoot, httpResponsePrometheusRoot},
	{"send-404", 404, keyScopeGlobal, "Not Found", ingtypes.GlobalHTTPResponse404, httpResponse404},
	{"send-413", 413, keyScopeBackend, "Payload Too Large", ingtypes.BackHTTPResponse413, httpResponse413},
	{"send-421", 421, keyScopeHost, "Misdirected Request", ingtypes.HostHTTPResponse421, httpResponse421},
	{"send-495", 495, keyScopeHost, "SSL Certificate Error", ingtypes.HostHTTPResponse495, httpResponse495},
	{"send-496", 496, keyScopeHost, "SSL Certificate Required", ingtypes.HostHTTPResponse496, httpResponse496},
	// HAProxy based, default isn't used because the response will be ignored if conf is missing
	// This configuration assumes that:
	//  - `name` will be used as the internal status code, `code` is the real status that should be returned
	//  - `def` should always be empty, this is used to distinguish between Lua and HAProxy based config
	{"200", 200, keyScopeBackend, "OK", ingtypes.BackHTTPResponse200, ""},
	{"400", 400, keyScopeBackend, "Bad Request", ingtypes.BackHTTPResponse400, ""},
	{"401", 401, keyScopeBackend, "Unauthorized", ingtypes.BackHTTPResponse401, ""},
	{"403", 403, keyScopeBackend, "Forbidden", ingtypes.BackHTTPResponse403, ""},
	{"405", 405, keyScopeBackend, "Method Not Allowed", ingtypes.BackHTTPResponse405, ""},
	{"407", 407, keyScopeBackend, "Proxy Authentication Required", ingtypes.BackHTTPResponse407, ""},
	{"408", 408, keyScopeBackend, "Request Timeout", ingtypes.BackHTTPResponse408, ""},
	{"410", 410, keyScopeBackend, "Gone", ingtypes.BackHTTPResponse410, ""},
	{"425", 425, keyScopeBackend, "Too Early", ingtypes.BackHTTPResponse425, ""},
	{"429", 429, keyScopeBackend, "Too Many Requests", ingtypes.BackHTTPResponse429, ""},
	{"500", 500, keyScopeBackend, "Internal Server Error", ingtypes.BackHTTPResponse500, ""},
	{"501", 501, keyScopeBackend, "Not Implemented", ingtypes.BackHTTPResponse501, ""},
	{"502", 502, keyScopeBackend, "Bad Gateway", ingtypes.BackHTTPResponse502, ""},
	{"503", 503, keyScopeBackend, "Service Unavailable", ingtypes.BackHTTPResponse503, ""},
	{"504", 504, keyScopeBackend, "Gateway Timeout", ingtypes.BackHTTPResponse504, ""},
}

func (c *updater) buildHTTPResponses(mapper *Mapper, scope keyScope) hatypes.HTTPResponses {
	var haResponses, luaResponses []hatypes.HTTPResponse
	for _, data := range customHTTPResponses {
		if scope != keyScopeGlobal && data.scope != scope {
			continue
		}
		var response *hatypes.HTTPResponse
		var err error
		if content := mapper.Get(data.key); content.Value != "" {
			response, err = parseHeadAndBody(content.Value)
			if err != nil {
				c.logger.Warn("ignoring '%s' on %s due to a malformed response: %s", data.key, content.Source.String(), err.Error())
			}
		}
		if scope == keyScopeGlobal && data.def != "" {
			// there is a default value, so a valid response should
			// always be provided -- used by Lua script based responses
			if response == nil || err != nil {
				response, err = parseHeadAndBody(data.def)
			}
			if err != nil {
				// this means that the default is broken
				panic(err)
			}
		}
		if response == nil {
			// response is optional and wasn't created, just skip
			continue
		}
		response.Name = data.name
		if response.StatusCode == 0 {
			response.StatusCode = data.code
		}
		if response.StatusReason == "" {
			response.StatusReason = data.reason
		}
		if data.def == "" {
			// this is currently the simplest way to distinguish between
			// Lua and HAProxy based responses
			haResponses = append(haResponses, *response)
		} else {
			luaResponses = append(luaResponses, *response)
		}
	}
	var res hatypes.HTTPResponses
	if len(haResponses) > 0 || len(luaResponses) > 0 {
		res = hatypes.HTTPResponses{
			ID:      "", // this is being configured when listed on Frontends()/Backends().BuildHTTPResponses(), which is closer to the real usage
			HAProxy: haResponses,
			Lua:     luaResponses,
		}
	}
	return res
}

var statusCodeRegex = regexp.MustCompile(`^([0-9]{3})( [A-Za-z ]+)?$`)

func parseHeadAndBody(content string) (*hatypes.HTTPResponse, error) {
	body := false
	bodysize := 0
	response := &hatypes.HTTPResponse{}
	response.Headers = []hatypes.HTTPHeader{{Name: "Content-Length"}}
	for i, line := range utils.LineToSlice(content) {
		line = strings.TrimRight(line, " ")
		if i == 0 && statusCodeRegex.MatchString(line) {
			// very first line with status code pattern
			status := statusCodeRegex.FindStringSubmatch(line)
			code, _ := strconv.Atoi(status[1])
			if code < 101 || code > 599 {
				return nil, fmt.Errorf("invalid status code: %s", status[1])
			}
			response.StatusCode = code
			response.StatusReason = strings.TrimSpace(status[2])
		} else if line == "" {
			// no more headers
			body = true
		} else if !body {
			// header
			pos := strings.Index(line, ":")
			if pos < 0 {
				return nil, fmt.Errorf("missing a colon ':' in the header declaration: %s", line)
			}
			header := hatypes.HTTPHeader{
				Name:  strings.TrimSpace(line[:pos]),
				Value: strings.TrimSpace(line[pos+1:]),
			}
			if strings.ToLower(header.Name) == "content-length" {
				// we will overwrite anything the user tried to add
				continue
			}
			if strings.ContainsAny(header.Name, `" `) {
				return nil, fmt.Errorf("invalid chars in the header name: '%s'", header.Name)
			}
			if header.Name == "" || header.Value == "" {
				return nil, fmt.Errorf("header name and value must not be empty: '%s'", line)
			}
			if strings.ContainsAny(header.Value, `"`) {
				return nil, fmt.Errorf("invalid chars in the header value: '%s'", header.Value)
			}
			response.Headers = append(response.Headers, header)
		} else {
			// body
			if strings.Contains(line, "]==]") {
				return nil, fmt.Errorf("the string ']==]' cannot be used in the body")
			}
			response.Body = append(response.Body, line)
			bodysize += len([]byte(line)) + 1 // length of the line as an array of bytes, plus a unix line break
		}
	}
	response.Headers[0].Value = strconv.Itoa(bodysize)
	return response, nil
}
