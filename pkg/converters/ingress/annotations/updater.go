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
	UpdateGlobalConfig(global *hatypes.Global, config *ingtypes.ConfigGlobals)
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
	config *ingtypes.ConfigGlobals
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

func (c *updater) UpdateGlobalConfig(global *hatypes.Global, config *ingtypes.ConfigGlobals) {
	data := &globalData{
		global: global,
		config: config,
	}
	global.Syslog.Endpoint = config.SyslogEndpoint
	global.Syslog.Format = config.SyslogFormat
	global.Syslog.Tag = config.SyslogTag
	global.Syslog.HTTPLogFormat = config.HTTPLogFormat
	global.Syslog.HTTPSLogFormat = config.HTTPSLogFormat
	global.Syslog.TCPLogFormat = config.TCPLogFormat
	global.MaxConn = config.MaxConnections
	global.DrainSupport.Drain = config.DrainSupport
	global.DrainSupport.Redispatch = config.DrainSupportRedispatch
	global.Cookie.Key = config.CookieKey
	global.LoadServerState = config.LoadServerState
	global.StatsSocket = "/var/run/haproxy-stats.sock"
	c.buildGlobalProc(data)
	c.buildGlobalTimeout(data)
	c.buildGlobalSSL(data)
	c.buildGlobalModSecurity(data)
	c.buildGlobalForwardFor(data)
	c.buildGlobalCustomConfig(data)
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
	backend.Server.MaxConn = mapper.Get(ingtypes.BackMaxconnServer).Int()
	backend.Server.MaxQueue = mapper.Get(ingtypes.BackMaxQueueServer).Int()
	backend.TLS.AddCertHeader = mapper.Get(ingtypes.BackAuthTLSCertHeader).Bool()
	c.buildBackendAffinity(data)
	c.buildBackendAuthHTTP(data)
	c.buildBackendBlueGreen(data)
	c.buildBackendBodySize(data)
	c.buildBackendCors(data)
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
