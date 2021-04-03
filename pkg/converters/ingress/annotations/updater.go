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
	"net"
	"regexp"

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
	UpdateTCPPortConfig(tcp *hatypes.TCPServicePort, mapper *Mapper)
	UpdateTCPHostConfig(host *hatypes.TCPServiceHost, mapper *Mapper)
	UpdateHostConfig(host *hatypes.Host, mapper *Mapper)
	UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper)
}

// NewUpdater ...
func NewUpdater(haproxy haproxy.Config, options *ingtypes.ConverterOptions) Updater {
	return &updater{
		haproxy: haproxy,
		options: options,
		logger:  options.Logger,
		cache:   options.Cache,
		tracker: options.Tracker,
		fakeCA:  options.FakeCAFile,
	}
}

type updater struct {
	haproxy haproxy.Config
	options *ingtypes.ConverterOptions
	logger  types.Logger
	cache   convtypes.Cache
	tracker convtypes.Tracker
	fakeCA  convtypes.CrtFile
}

type globalData struct {
	acmeData *hatypes.AcmeData
	global   *hatypes.Global
	mapper   *Mapper
}

type hostData struct {
	host   *hatypes.Host
	mapper *Mapper
}

type backData struct {
	backend *hatypes.Backend
	mapper  *Mapper
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
	d := &globalData{
		acmeData: haproxyConfig.AcmeData(),
		global:   haproxyConfig.Global(),
		mapper:   mapper,
	}
	// TODO Move all magic strings to a single place
	d.global.AdminSocket = "/var/run/haproxy/admin.sock"
	d.global.MaxConn = mapper.Get(ingtypes.GlobalMaxConnections).Int()
	d.global.DefaultBackendRedir = mapper.Get(ingtypes.GlobalDefaultBackendRedirect).String()
	d.global.DefaultBackendRedirCode = mapper.Get(ingtypes.GlobalDefaultBackendRedirectCode).Int()
	d.global.DrainSupport.Drain = mapper.Get(ingtypes.GlobalDrainSupport).Bool()
	d.global.DrainSupport.Redispatch = mapper.Get(ingtypes.GlobalDrainSupportRedispatch).Bool()
	d.global.Cookie.Key = mapper.Get(ingtypes.GlobalCookieKey).Value
	d.global.External.HasLua = mapper.Get(ingtypes.GlobalExternalHasLua).Bool()
	d.global.External.MasterSocket = c.options.MasterSocket
	d.global.LoadServerState = mapper.Get(ingtypes.GlobalLoadServerState).Bool()
	d.global.Master.ExitOnFailure = mapper.Get(ingtypes.GlobalMasterExitOnFailure).Bool()
	d.global.Master.WorkerMaxReloads = mapper.Get(ingtypes.GlobalWorkerMaxReloads).Int()
	d.global.StrictHost = mapper.Get(ingtypes.GlobalStrictHost).Bool()
	d.global.UseHTX = mapper.Get(ingtypes.GlobalUseHTX).Bool()
	//
	c.haproxy.Frontend().DefaultServerRedirectCode = mapper.Get(ingtypes.HostServerRedirectCode).Int()
	//
	c.buildGlobalAcme(d)
	c.buildGlobalAuthProxy(d)
	c.buildGlobalBind(d)
	c.buildGlobalCustomConfig(d)
	c.buildGlobalDNS(d)
	c.buildGlobalForwardFor(d)
	c.buildGlobalHTTPStoHTTP(d)
	c.buildGlobalModSecurity(d)
	c.buildGlobalPathTypeOrder(d)
	c.buildGlobalProc(d)
	c.buildSecurity(d)
	c.buildGlobalSSL(d)
	c.buildGlobalStats(d)
	c.buildGlobalSyslog(d)
	c.buildGlobalTimeout(d)
}

func (c *updater) UpdateTCPPortConfig(tcp *hatypes.TCPServicePort, mapper *Mapper) {
	tcp.ProxyProt = mapper.Get(ingtypes.HostTCPServiceProxyProto).Bool()
}

func (c *updater) UpdateTCPHostConfig(host *hatypes.TCPServiceHost, mapper *Mapper) {
}

func (c *updater) UpdateHostConfig(host *hatypes.Host, mapper *Mapper) {
	data := &hostData{
		host:   host,
		mapper: mapper,
	}
	host.RootRedirect = mapper.Get(ingtypes.HostAppRoot).Value
	host.Alias.AliasName = mapper.Get(ingtypes.HostServerAlias).Value
	host.Alias.AliasRegex = mapper.Get(ingtypes.HostServerAliasRegex).Value
	host.VarNamespace = mapper.Get(ingtypes.HostVarNamespace).Bool()
	c.buildHostAuthTLS(data)
	c.buildHostCertSigner(data)
	c.buildHostRedirect(data)
	c.buildHostSSLPassthrough(data)
	c.buildHostTLSConfig(data)
}

func (c *updater) UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper) {
	data := &backData{
		backend: backend,
		mapper:  mapper,
	}
	// TODO check ModeTCP with HTTP annotations
	backend.BalanceAlgorithm = mapper.Get(ingtypes.BackBalanceAlgorithm).Value
	backend.CustomConfig = utils.LineToSlice(mapper.Get(ingtypes.BackConfigBackend).Value)
	backend.Server.MaxConn = mapper.Get(ingtypes.BackMaxconnServer).Int()
	backend.Server.MaxQueue = mapper.Get(ingtypes.BackMaxQueueServer).Int()
	c.buildBackendAffinity(data)
	c.buildBackendAuthExternal(data)
	c.buildBackendAuthHTTP(data)
	c.buildBackendBlueGreenBalance(data)
	c.buildBackendBlueGreenSelector(data)
	c.buildBackendBodySize(data)
	c.buildBackendCors(data)
	c.buildBackendDNS(data)
	c.buildBackendDynamic(data)
	c.buildBackendAgentCheck(data)
	c.buildBackendHeaders(data)
	c.buildBackendHealthCheck(data)
	c.buildBackendHSTS(data)
	c.buildBackendLimit(data)
	c.buildBackendOAuth(data)
	c.buildBackendProtocol(data)
	c.buildBackendProxyProtocol(data)
	c.buildBackendRewriteURL(data)
	c.buildBackendServerNaming(data)
	c.buildBackendSSL(data)
	c.buildBackendSSLRedirect(data)
	c.buildBackendTimeout(data)
	c.buildBackendWAF(data)
	c.buildBackendWhitelistHTTP(data)
	c.buildBackendWhitelistTCP(data)
}
