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
	"strconv"
	"strings"
	"time"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

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
	d.global.Acme.Socket = "/var/run/haproxy/acme.sock"
	d.global.Acme.Enabled = true
	d.global.Acme.Shared = d.mapper.Get(ingtypes.GlobalAcmeShared).Bool()
}

var authProxyRegex = regexp.MustCompile(`^([A-Za-z_-]+):([0-9]{1,5})-([0-9]{1,5})$`)

func (c *updater) buildGlobalAuthProxy(d *globalData) {
	proxystr := d.mapper.Get(ingtypes.GlobalAuthProxy).Value
	proxy := authProxyRegex.FindStringSubmatch(proxystr)
	authproxy := &c.haproxy.Frontend().AuthProxy
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

func (c *updater) buildGlobalBind(d *globalData) {
	d.global.Bind.AcceptProxy = d.mapper.Get(ingtypes.GlobalUseProxyProtocol).Bool()
	d.global.Bind.TCPBindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrTCP).Value
	if bindHTTP := d.mapper.Get(ingtypes.GlobalBindHTTP).Value; bindHTTP != "" {
		d.global.Bind.HTTPBind = bindHTTP
	} else {
		ip := d.mapper.Get(ingtypes.GlobalBindIPAddrHTTP).Value
		port := d.mapper.Get(ingtypes.GlobalHTTPPort).Int()
		d.global.Bind.HTTPBind = fmt.Sprintf("%s:%d", ip, port)
	}
	if bindHTTPS := d.mapper.Get(ingtypes.GlobalBindHTTPS).Value; bindHTTPS != "" {
		d.global.Bind.HTTPSBind = bindHTTPS
	} else {
		ip := d.mapper.Get(ingtypes.GlobalBindIPAddrHTTP).Value
		port := d.mapper.Get(ingtypes.GlobalHTTPSPort).Int()
		d.global.Bind.HTTPSBind = fmt.Sprintf("%s:%d", ip, port)
	}
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

func (c *updater) buildSecurity(d *globalData) {
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
}

func (c *updater) buildGlobalHTTPStoHTTP(d *globalData) {
	bind := d.mapper.Get(ingtypes.GlobalBindFrontingProxy).Value
	if bind == "" {
		port := d.mapper.Get(ingtypes.GlobalFrontingProxyPort).Int()
		if port == 0 {
			port = d.mapper.Get(ingtypes.GlobalHTTPStoHTTPPort).Int()
		}
		if port == 0 {
			return
		}
		bind = fmt.Sprintf("%s:%d", d.mapper.Get(ingtypes.GlobalBindIPAddrHTTP).Value, port)
	}
	// TODO Change all `ToHTTP` naming to `FrontingProxy`
	d.global.Bind.FrontingBind = bind
	d.global.Bind.FrontingUseProto = d.mapper.Get(ingtypes.GlobalUseForwardedProto).Bool()
	// Socket ID should be a high number to avoid colision
	// between the same socket ID from distinct frontends
	// TODO match socket and frontend ID in the backend
	d.global.Bind.FrontingSockID = 10011
}

func (c *updater) buildGlobalModSecurity(d *globalData) {
	d.global.ModSecurity.Endpoints = utils.Split(d.mapper.Get(ingtypes.GlobalModsecurityEndpoints).Value, ",")
	d.global.ModSecurity.Timeout.Connect = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutConnect))
	d.global.ModSecurity.Timeout.Hello = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutHello))
	d.global.ModSecurity.Timeout.Idle = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutIdle))
	d.global.ModSecurity.Timeout.Processing = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutProcessing))
	d.global.ModSecurity.Timeout.Server = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutServer))
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

func (c *updater) buildGlobalForwardFor(d *globalData) {
	if forwardFor := d.mapper.Get(ingtypes.GlobalForwardfor).Value; forwardRegex.MatchString(forwardFor) {
		d.global.ForwardFor = forwardFor
	} else {
		if forwardFor != "" {
			c.logger.Warn("Invalid forwardfor value option on configmap: '%s'. Using 'add' instead", forwardFor)
		}
		d.global.ForwardFor = "add"
	}
}

func (c *updater) buildGlobalCustomConfig(d *globalData) {
	d.global.CustomConfig = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigGlobal).Value)
	d.global.CustomDefaults = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigDefaults).Value)
	d.global.CustomFrontend = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigFrontend).Value)
	d.global.CustomSections = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigSections).Value)
	d.global.CustomTCP = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigTCP).Value)
	proxy := map[string][]string{}
	var curSection string
	for _, line := range utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigProxy).Value) {
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
