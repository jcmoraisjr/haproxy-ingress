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
	UpdateGlobalConfig(global *hatypes.Global, config *ingtypes.Config)
	UpdateFrontendConfig(frontend *hatypes.Frontend, ann *ingtypes.FrontendAnnotations)
	UpdateBackendConfig(backend *hatypes.Backend, ann *ingtypes.BackendAnnotations)
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
	config *ingtypes.Config
}

type frontData struct {
	frontend *hatypes.Frontend
	ann      *ingtypes.FrontendAnnotations
}

type backData struct {
	backend *hatypes.Backend
	ann     *ingtypes.BackendAnnotations
}

func copyHAProxyTime(dst *string, src string) {
	// TODO validate
	*dst = src
}

func (c *updater) UpdateGlobalConfig(global *hatypes.Global, config *ingtypes.Config) {
	data := &globalData{
		global: global,
		config: config,
	}
	global.Syslog.Endpoint = config.SyslogEndpoint
	global.Syslog.Format = config.SyslogFormat
	global.Syslog.Tag = config.SyslogTag
	global.MaxConn = config.MaxConnections
	global.DrainSupport = config.DrainSupport
	global.LoadServerState = config.LoadServerState
	global.StatsSocket = "/var/run/haproxy-stats.sock"
	c.buildGlobalProc(data)
	c.buildGlobalTimeout(data)
	c.buildGlobalSSL(data)
	c.buildGlobalModSecurity(data)
	c.buildGlobalCustomConfig(data)
}

func (c *updater) UpdateFrontendConfig(frontend *hatypes.Frontend, ann *ingtypes.FrontendAnnotations) {
	data := &frontData{
		frontend: frontend,
		ann:      ann,
	}
	frontend.RootRedirect = ann.AppRoot
	frontend.Alias.AliasName = ann.ServerAlias
	frontend.Alias.AliasRegex = ann.ServerAliasRegex
	frontend.Timeout.Client = ann.TimeoutClient
	frontend.Timeout.ClientFin = ann.TimeoutClientFin
	c.buildFrontendAuthTLS(data)
	c.buildFrontendSSLPassthrough(data)
}

func (c *updater) UpdateBackendConfig(backend *hatypes.Backend, ann *ingtypes.BackendAnnotations) {
	data := &backData{
		backend: backend,
		ann:     ann,
	}
	// TODO check ModeTCP with HTTP annotations
	backend.BalanceAlgorithm = ann.BalanceAlgorithm
	backend.MaxconnServer = ann.MaxconnServer
	backend.ProxyBodySize = ann.ProxyBodySize
	backend.SSLRedirect = ann.SSLRedirect
	c.buildBackendAffinity(data)
	c.buildBackendAuthHTTP(data)
	c.buildBackendBlueGreen(data)
}
