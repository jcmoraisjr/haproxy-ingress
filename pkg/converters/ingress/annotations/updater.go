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
	UpdateGlobalConfig(global *hatypes.Global, mapper *Mapper)
	UpdateHostConfig(host *hatypes.Host, mapper *Mapper)
	UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper)
}

// NewUpdater ...
func NewUpdater(haproxy haproxy.Config, cache convtypes.Cache, logger types.Logger) Updater {
	return &updater{
		haproxy: haproxy,
		cache:   cache,
		logger:  logger,
	}
}

type updater struct {
	haproxy haproxy.Config
	cache   convtypes.Cache
	logger  types.Logger
}

type globalData struct {
	global *hatypes.Global
	mapper *Mapper
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
	var cidrslice []string
	for _, cidr := range utils.Split(cidrlist.Value, ",") {
		var err error
		if net.ParseIP(cidr) == nil {
			_, _, err = net.ParseCIDR(cidr)
		}
		if err != nil {
			c.logger.Warn("skipping invalid IP or cidr on %v: %s", cidrlist.Source, cidr)
		} else {
			cidrslice = append(cidrslice, cidr)
		}
	}
	return cidrslice
}

func (c *updater) UpdateGlobalConfig(global *hatypes.Global, mapper *Mapper) {
	data := &globalData{
		global: global,
		mapper: mapper,
	}
	global.AdminSocket = "/var/run/haproxy-stats.sock"
	global.MaxConn = mapper.Get(ingtypes.GlobalMaxConnections).Int()
	global.DrainSupport.Drain = mapper.Get(ingtypes.GlobalDrainSupport).Bool()
	global.DrainSupport.Redispatch = mapper.Get(ingtypes.GlobalDrainSupportRedispatch).Bool()
	global.Cookie.Key = mapper.Get(ingtypes.GlobalCookieKey).Value
	global.LoadServerState = mapper.Get(ingtypes.GlobalLoadServerState).Bool()
	global.SSL.ALPN = mapper.Get(ingtypes.GlobalTLSALPN).Value
	global.StrictHost = mapper.Get(ingtypes.GlobalStrictHost).Bool()
	c.buildGlobalBind(data)
	c.buildGlobalCustomConfig(data)
	c.buildGlobalDNS(data)
	c.buildGlobalForwardFor(data)
	c.buildGlobalHealthz(data)
	c.buildGlobalHTTPStoHTTP(data)
	c.buildGlobalModSecurity(data)
	c.buildGlobalProc(data)
	c.buildGlobalSSL(data)
	c.buildGlobalStats(data)
	c.buildGlobalSyslog(data)
	c.buildGlobalTimeout(data)
}

func (c *updater) UpdateHostConfig(host *hatypes.Host, mapper *Mapper) {
	data := &hostData{
		host:   host,
		mapper: mapper,
	}
	host.RootRedirect = mapper.Get(ingtypes.HostAppRoot).Value
	host.Alias.AliasName = mapper.Get(ingtypes.HostServerAlias).Value
	host.Alias.AliasRegex = mapper.Get(ingtypes.HostServerAliasRegex).Value
	c.buildHostAuthTLS(data)
	c.buildHostSSLPassthrough(data)
	c.buildHostTimeout(data)
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
	backend.TLS.AddCertHeader = mapper.Get(ingtypes.BackAuthTLSCertHeader).Bool()
	c.buildBackendAffinity(data)
	c.buildBackendAuthHTTP(data)
	c.buildBackendBlueGreen(data)
	c.buildBackendBodySize(data)
	c.buildBackendCors(data)
	c.buildBackendDNS(data)
	c.buildBackendDynamic(data)
	c.buildBackendAgentCheck(data)
	c.buildBackendHealthCheck(data)
	c.buildBackendHSTS(data)
	c.buildBackendLimit(data)
	c.buildBackendOAuth(data)
	c.buildBackendProxyProtocol(data)
	c.buildBackendRewriteURL(data)
	c.buildBackendSecure(data)
	c.buildBackendSSLRedirect(data)
	c.buildBackendTimeout(data)
	c.buildBackendWAF(data)
	c.buildBackendWhitelistHTTP(data)
	c.buildBackendWhitelistTCP(data)
}
