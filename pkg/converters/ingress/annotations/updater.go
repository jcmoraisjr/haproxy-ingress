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
	"net"
	"regexp"
	"strings"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// Updater ...
type Updater interface {
	UpdateGlobalConfig(haproxyConfig haproxy.Config, mapper *Mapper)
	UpdatePeers(haproxyConfig haproxy.Config, mapper *Mapper)
	UpdateTCPPortConfig(tcp *hatypes.TCPServicePort, mapper *Mapper)
	UpdateTCPHostConfig(tcpPort *hatypes.TCPServicePort, tcpHost *hatypes.TCPServiceHost, mapper *Mapper)
	UpdateFrontConfig(front *hatypes.Frontend, mapper *Mapper)
	UpdateHostConfig(host *hatypes.Host, mapper *Mapper)
	UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper)
}

// NewUpdater ...
func NewUpdater(haproxy haproxy.Config, options *convtypes.ConverterOptions) Updater {
	return &updater{
		haproxy: haproxy,
		options: options,
		logger:  options.Logger,
		cache:   options.Cache,
		tracker: options.Tracker,
		fakeCA:  options.FakeCAFile,
		vars:    buildGlobalVars(haproxy.Global()),
	}
}

type updater struct {
	haproxy haproxy.Config
	options *convtypes.ConverterOptions
	logger  types.Logger
	cache   convtypes.Cache
	tracker convtypes.Tracker
	fakeCA  convtypes.CrtFile
	srcIPs  map[string][]net.IP
	vars    map[string]string
}

type globalData struct {
	acmeData *hatypes.AcmeData
	global   *hatypes.Global
	mapper   *Mapper
}

type tcpData struct {
	tcpPort *hatypes.TCPServicePort
	tcpHost *hatypes.TCPServiceHost
	mapper  *Mapper
}

type frontData struct {
	front  *hatypes.Frontend
	mapper *Mapper
}

type hostData struct {
	host   *hatypes.Host
	mapper *Mapper
}

type backData struct {
	backend *hatypes.Backend
	mapper  *Mapper
	vars    map[string]string
}

func buildPeersTableName(group, beSuffix string) string {
	// keep in mind that this logic is also implemented on haproxy.tmpl and peers.lua.tmpl.
	return fmt.Sprintf("%s%s_%s", hatypes.PeersTableNamePrefix, group, beSuffix)
}

var regexValidTime = regexp.MustCompile(`^[0-9]+(us|ms|s|m|h|d)$`)

func (c *updater) validateTime(cfg *ConfigValue) string {
	if !regexValidTime.MatchString(cfg.Value) {
		if cfg.Source != nil {
			c.logger.Warn("ignoring invalid time format on %v: %s", cfg.Source, cfg.Value)
		} else if cfg.Value != "" {
			c.logger.Warn("ignoring invalid time format on global/default config: %s", cfg.Value)
		}
		return ""
	}
	return cfg.Value
}

func (c *updater) validateAllowDeny(d *globalData, key string) (allow bool) {
	cfg := d.mapper.Get(key)
	value := strings.ToLower(cfg.Value)
	allow = value == "allow"
	if value != "" && value != "allow" && value != "deny" {
		c.logger.Warn("ignoring invalid value '%s' on global '%s', using 'deny'", cfg.Value, key)
	}
	return allow
}

func (c *updater) splitCIDR(cidrlist *ConfigValue) []string {
	allow, deny := c.splitDualCIDR(cidrlist)
	if len(deny) > 0 {
		c.logger.Warn("ignored deny list of IPs or CIDRs: %v", deny)
	}
	return allow
}

func (c *updater) splitDualCIDR(cidrlist *ConfigValue) (allow, deny []string) {
	for _, cidr := range utils.Split(cidrlist.Value, ",") {
		if cidr == "" {
			continue
		}
		if cidr == "!" {
			c.logger.Warn("skipping deny of an empty IP or CIDR on %v", cidrlist.Source)
			continue
		}
		neg := cidr[0] == '!'
		if neg {
			cidr = cidr[1:]
		}
		var err error
		if net.ParseIP(cidr) == nil {
			_, _, err = net.ParseCIDR(cidr)
		}
		if err != nil {
			c.logger.Warn("skipping invalid IP or cidr on %v: %s", cidrlist.Source, cidr)
		} else if neg {
			deny = append(deny, cidr)
		} else {
			allow = append(allow, cidr)
		}
	}
	return allow, deny
}

func (c *updater) UpdateGlobalConfig(haproxyConfig haproxy.Config, mapper *Mapper) {
	c.UpdatePeers(haproxyConfig, mapper)
	d := &globalData{
		acmeData: haproxyConfig.AcmeData(),
		global:   haproxyConfig.Global(),
		mapper:   mapper,
	}
	d.global.AdminSocket = c.options.AdminSocket
	d.global.TCPBindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrTCP).String()
	d.global.LocalFSPrefix = c.options.LocalFSPrefix
	d.global.MaxConn = mapper.Get(ingtypes.GlobalMaxConnections).Int()
	d.global.DefaultBackendRedir = mapper.Get(ingtypes.GlobalDefaultBackendRedirect).String()
	d.global.DefaultBackendRedirCode = mapper.Get(ingtypes.GlobalDefaultBackendRedirectCode).Int()
	d.global.NoRedirects = utils.Split(mapper.Get(ingtypes.GlobalNoRedirectLocations).String(), ",")
	d.global.DrainSupport.Drain = mapper.Get(ingtypes.GlobalDrainSupport).Bool()
	d.global.DrainSupport.Redispatch = mapper.Get(ingtypes.GlobalDrainSupportRedispatch).Bool()
	d.global.Cookie.Key = mapper.Get(ingtypes.GlobalCookieKey).Value
	d.global.External.HasLua = mapper.Get(ingtypes.GlobalExternalHasLua).Bool()
	d.global.External.IsExternal = c.options.IsExternal
	d.global.LoadServerState = mapper.Get(ingtypes.GlobalLoadServerState).Bool()
	d.global.Master.ExitOnFailure = mapper.Get(ingtypes.GlobalMasterExitOnFailure).Bool()
	d.global.Master.IsMasterWorker = c.options.MasterSocket != ""
	d.global.Master.WorkerMaxReloads = mapper.Get(ingtypes.GlobalWorkerMaxReloads).Int()
	d.global.StrictHost = mapper.Get(ingtypes.GlobalStrictHost).Bool()
	d.global.UseHTX = mapper.Get(ingtypes.GlobalUseHTX).Bool()
	c.buildGlobalAcme(d)
	c.buildGlobalAuthProxy(d)
	c.buildGlobalCloseSessions(d)
	c.buildGlobalCustomConfig(d)
	c.buildGlobalCustomResponses(d)
	c.buildGlobalDNS(d)
	c.buildGlobalDynamic(d)
	c.buildGlobalFastCGI(d)
	c.buildGlobalForwardFor(d)
	c.buildGlobalModSecurity(d)
	c.buildGlobalPathTypeOrder(d)
	c.buildGlobalProc(d)
	c.buildGlobalSecurity(d)
	c.buildGlobalSSL(d)
	c.buildGlobalStats(d)
	c.buildGlobalSyslog(d)
	c.buildGlobalTimeout(d)
}

func (c *updater) UpdatePeers(haproxyConfig haproxy.Config, mapper *Mapper) {
	// NOTE - Peers is updated without cleanup, so all the methods should be idempotent.
	global := haproxyConfig.Global()
	d := &globalData{
		global: global,
		mapper: mapper,
	}
	c.buildGlobalPeers(d)
	// peers is currently a silly dependency to build global vars
	c.vars = buildGlobalVars(global)
}

func (c *updater) UpdateTCPPortConfig(tcp *hatypes.TCPServicePort, mapper *Mapper) {
	// NOTE - TCPPortConfig is updated without cleanup, so all the methods should be idempotent.
	if config := mapper.Get(ingtypes.TCPConfigTCPService).Value; config != "" {
		tcp.CustomConfig = utils.PatternLineToSlice(c.vars, config)
	}
	tcp.LogFormat = mapper.Get(ingtypes.TCPTCPServiceLogFormat).Value
	tcp.ProxyProt = mapper.Get(ingtypes.TCPTCPServiceProxyProto).Bool()
}

func (c *updater) UpdateTCPHostConfig(tcpPort *hatypes.TCPServicePort, tcpHost *hatypes.TCPServiceHost, mapper *Mapper) {
	// NOTE - TCPHostConfig is updated without cleanup, so all the methods should be idempotent.
	d := &tcpData{
		tcpPort: tcpPort,
		tcpHost: tcpHost,
		mapper:  mapper,
	}
	c.buildTCPAuthTLS(d)
}

func (c *updater) UpdateFrontConfig(front *hatypes.Frontend, mapper *Mapper) {
	// NOTE - FrontConfig is updated without cleanup, so all the methods should be idempotent.
	d := &frontData{
		front:  front,
		mapper: mapper,
	}
	front.RedirectFromCode = mapper.Get(ingtypes.FrontRedirectFromCode).Int()
	front.RedirectToCode = mapper.Get(ingtypes.FrontRedirectToCode).Int()
	if front.IsHTTPS {
		c.buildHTTPSFrontBind(d)
	} else {
		c.buildHTTPFrontBind(d)
		c.buildHTTPFrontFrontingProxy(d)
	}
}

func (c *updater) UpdateHostConfig(host *hatypes.Host, mapper *Mapper) {
	d := &hostData{
		host:   host,
		mapper: mapper,
	}
	host.RootRedirect = mapper.Get(ingtypes.HostAppRoot).Value
	host.Alias.AliasName = mapper.Get(ingtypes.HostServerAlias).Value
	host.Alias.AliasRegex = mapper.Get(ingtypes.HostServerAliasRegex).Value
	host.VarNamespace = mapper.Get(ingtypes.HostVarNamespace).Bool()
	c.buildHostAuthExternal(d)
	c.buildHostCertSigner(d)
	c.buildHostRedirect(d)
	c.buildHostCustomResponses(d)
	if host.IsHTTPS() {
		c.buildHostAuthTLS(d)
		c.buildHostTLSConfig(d)
	}
}

func (c *updater) UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper) {
	data := &backData{
		backend: backend,
		mapper:  mapper,
		vars:    buildBackendVars(c.haproxy.Global(), backend, c.vars),
	}
	// TODO check ModeTCP with HTTP annotations
	backend.BalanceAlgorithm = mapper.Get(ingtypes.BackBalanceAlgorithm).Value
	backend.Server.MaxConn = mapper.Get(ingtypes.BackMaxconnServer).Int()
	backend.Server.MaxQueue = mapper.Get(ingtypes.BackMaxQueueServer).Int()
	c.buildBackendAffinity(data)
	c.buildBackendAuthExternal(data)
	c.buildBackendAuthHTTP(data)
	c.buildBackendBlueGreenBalance(data)
	c.buildBackendBlueGreenSelector(data)
	c.buildBackendBodySize(data)
	c.buildBackendCors(data)
	c.buildBackendCustomConfig(data)
	c.buildBackendCustomResponses(data)
	c.buildBackendDNS(data)
	c.buildBackendDynamic(data)
	c.buildBackendAgentCheck(data)
	c.buildBackendHeaders(data)
	c.buildBackendHealthCheck(data)
	c.buildBackendHSTS(data)
	c.buildBackendLimit(data)
	c.buildBackendOAuth(data)
	c.buildBackendPeers(data)
	c.buildBackendProtocol(data)
	c.buildBackendProxyProtocol(data)
	c.buildBackendRewriteURL(data)
	c.buildBackendServerNaming(data)
	c.buildBackendSourceAddressIntf(data)
	c.buildBackendSSL(data)
	c.buildBackendSSLRedirect(data)
	c.buildBackendTimeout(data)
	c.buildBackendWAF(data)
	c.buildBackendWhitelistHTTP(data)
	c.buildBackendWhitelistTCP(data)
}
