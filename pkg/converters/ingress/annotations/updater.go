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
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// Updater ...
type Updater interface {
	UpdateGlobalConfig(global *hatypes.Global, config *ingtypes.ConfigGlobals)
	UpdateHostConfig(host *hatypes.Host, mapper *Mapper)
	UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper)
}

// NewUpdater ...
func NewUpdater(haproxy haproxy.Config, cache ingtypes.Cache, logger types.Logger) Updater {
	return &updater{
		haproxy: haproxy,
		cache:   cache,
		logger:  logger,
	}
}

type updater struct {
	haproxy haproxy.Config
	cache   ingtypes.Cache
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

func copyHAProxyTime(dst *string, src string) {
	// TODO validate
	*dst = src
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
	host.RootRedirect = mapper.GetStrValue(ingtypes.HostAppRoot)
	host.Alias.AliasName = mapper.GetStrValue(ingtypes.HostServerAlias)
	host.Alias.AliasRegex = mapper.GetStrValue(ingtypes.HostServerAliasRegex)
	host.Timeout.Client = mapper.GetStrValue(ingtypes.HostTimeoutClient)
	host.Timeout.ClientFin = mapper.GetStrValue(ingtypes.HostTimeoutClientFin)
	c.buildHostAuthTLS(data)
	c.buildHostSSLPassthrough(data)
}

func (c *updater) UpdateBackendConfig(backend *hatypes.Backend, mapper *Mapper) {
	data := &backData{
		backend: backend,
		mapper:  mapper,
	}
	// TODO check ModeTCP with HTTP annotations
	backend.BalanceAlgorithm = mapper.GetStrValue(ingtypes.BackBalanceAlgorithm)
	backend.MaxConnServer = mapper.GetIntValue(ingtypes.BackMaxconnServer)
	backend.ProxyBodySize = mapper.GetBackendConfigStr(backend, ingtypes.BackProxyBodySize)
	backend.SSLRedirect = mapper.GetBoolValue(ingtypes.BackSSLRedirect)
	backend.SSL.AddCertHeader = mapper.GetBoolValue(ingtypes.BackAuthTLSCertHeader)
	c.buildBackendAffinity(data)
	c.buildBackendAuthHTTP(data)
	c.buildBackendBlueGreen(data)
	c.buildBackendCors(data)
	c.buildBackendHSTS(data)
	c.buildBackendOAuth(data)
	c.buildBackendRewriteURL(data)
	c.buildBackendWAF(data)
	c.buildBackendWhitelist(data)
}
