/*
Copyright 2025 The HAProxy Ingress Controller Authors.

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
	"strconv"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

type FrontendPorts struct {
	logger types.Logger
	httpPort,
	httpsPort,
	httpPassPort int32
	frontends map[string]httpPorts
}

type FrontendLocalPorts struct {
	HTTP,
	HTTPS,
	HTTPPassthrough int32
	LocalPorts bool
}

type httpPorts struct {
	http  int32
	https int32
}

var frontendSyntaxRegex = regexp.MustCompile(`^([^=]+)=([^/]+)/([^/]+)$`)
var frontendIDRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,19}$`)

func NewFrontendPorts(logger types.Logger, haproxy haproxy.Config, globalMapper *Mapper) *FrontendPorts {
	// global ports
	httpPort := globalMapper.Get(ingtypes.GlobalHTTPPort).Int32()
	httpsPort := globalMapper.Get(ingtypes.GlobalHTTPSPort).Int32()
	httpPassPort := globalMapper.Get(ingtypes.GlobalHTTPPassthroughPort).Int32()
	if httpPassPort == 0 {
		httpPassPort = globalMapper.Get(ingtypes.GlobalFrontingProxyPort).Int32()
	}
	if httpPassPort == 0 {
		httpPassPort = globalMapper.Get(ingtypes.GlobalHTTPStoHTTPPort).Int32()
	}

	// denied ports
	denyPorts := []int32{httpPort, httpsPort}
	if httpPassPort > 0 {
		denyPorts = append(denyPorts, httpPassPort)
	}
	for _, key := range listeningPortGlobalKeys {
		if value := globalMapper.Get(key).Int32(); value > 0 {
			denyPorts = append(denyPorts, value)
		}
	}

	frontends := make(map[string]httpPorts)
	for _, frontend := range utils.LineToSlice(globalMapper.Get(ingtypes.GlobalHTTPFrontends).Value) {
		if frontend == "" {
			continue
		}
		f := frontendSyntaxRegex.FindStringSubmatch(frontend)
		if len(f) != 4 {
			logger.Warn("ignoring local frontend configuration: invalid frontend declaration syntax: '%s'", frontend)
			continue
		}
		frontID := f[1]
		f2, _ := strconv.Atoi(f[2])
		f3, _ := strconv.Atoi(f[3])
		frontHTTP := int32(f2)
		frontHTTPS := int32(f3)
		if !frontendIDRegex.MatchString(frontID) {
			logger.Warn("ignoring local frontend configuration: invalid frontend ID, expected at most 20 letters and numbers, starting with letter: '%s'", frontID)
			continue
		}
		if _, found := frontends[frontID]; found {
			logger.Warn("ignoring local frontend configuration: frontend ID already in use: '%s'", frontID)
			continue
		}
		if frontHTTP <= 0 || frontHTTPS <= 0 {
			logger.Warn("ignoring local frontend configuration: invalid port numbers: '%s/%s'", f[2], f[3])
			continue
		}
		if frontHTTP == frontHTTPS {
			logger.Warn("ignoring local frontend configuration: HTTP and HTTPS ports cannot share the same value: '%d/%d'", frontHTTP, frontHTTPS)
			continue
		}
		if slices.Contains(denyPorts, frontHTTP) || slices.Contains(denyPorts, frontHTTPS) {
			logger.Warn("ignoring local frontend configuration: local frontend ports %d/%d cannot collide with other already declared ports: %v", frontHTTP, frontHTTPS, denyPorts)
			continue
		}
		frontends[frontID] = httpPorts{http: frontHTTP, https: frontHTTPS}
		denyPorts = append(denyPorts, frontHTTP, frontHTTPS)
	}

	return &FrontendPorts{
		logger:       logger,
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		httpPassPort: httpPassPort,
		frontends:    frontends,
	}
}

var listeningPortGlobalKeys = []string{
	// http, https, and http-passthrough already added
	ingtypes.GlobalHealthzPort,
	ingtypes.GlobalPrometheusPort,
}

var listeningBindFrontendKeys = []string{
	ingtypes.FrontBindHTTP,
	ingtypes.FrontBindHTTPS,
	ingtypes.FrontBindHTTPPassthrough,
	ingtypes.FrontBindFrontingProxy,
}

func (fp *FrontendPorts) AcquirePorts(mapper *Mapper) (FrontendLocalPorts, error) {
	defaultPorts := FrontendLocalPorts{
		HTTP:            fp.httpPort,
		HTTPS:           fp.httpsPort,
		HTTPPassthrough: fp.httpPassPort,
		LocalPorts:      false,
	}
	frontendConfig := mapper.Get(ingtypes.FrontHTTPFrontend)
	if frontendConfig.Source == nil {
		// use default if http-frontend is configured globally (!!), or not configured at all
		return defaultPorts, nil
	}
	frontendPorts, found := fp.frontends[frontendConfig.Value]
	if !found {
		return defaultPorts, fmt.Errorf("frontend ID not found on %v: '%s'", frontendConfig.Source, frontendConfig.Value)
	}

	return FrontendLocalPorts{
		HTTP:            frontendPorts.http,
		HTTPS:           frontendPorts.https,
		HTTPPassthrough: fp.httpPassPort,
		LocalPorts:      true,
	}, nil
}

func (fp *FrontendPorts) EnsureEmptyFrontends(frontends *hatypes.Frontends) {
	_ = frontends.AcquireFrontend(fp.httpPort, false)
	_ = frontends.AcquireFrontend(fp.httpsPort, true)
	if fp.httpPassPort > 0 && fp.httpPassPort != fp.httpPort {
		_ = frontends.AcquireFrontend(fp.httpPassPort, false)
	}
	for _, f := range fp.frontends {
		_ = frontends.AcquireFrontend(f.http, false)
		_ = frontends.AcquireFrontend(f.https, true)
	}
}

func (c *frontData) get(key string) *ConfigValue {
	config := c.mapper.Get(key)
	if config.Source != nil && !c.localPorts {
		// malformed configuration: a frontend key was configured via annotation (config.Source not nil)
		// and there is not a valid local port configuration, warn and use default/global instead.
		if c.mapper.Get(ingtypes.FrontHTTPFrontend).Source == nil {
			// logging only in case http-frontend is missing; otherwise the reason why c.localPorts is false is already logged.
			c.logger.Warn("skipping '%s' configuration on %s: missing '%s' key", key, config.Source, ingtypes.FrontHTTPFrontend)
		}
		return c.mapper.GetDefault(key)
	}

	if config.Source != nil && slices.Contains(listeningBindFrontendKeys, key) && !c.mapper.Get(ingtypes.GlobalAllowLocalBind).Bool() {
		// annotation based config for listening bind, but 'allow-local-bind' was not configured
		c.logger.Warn("skipping '%s' configuration on %s: custom bind configuration not allowed", key, config.Source)
		return c.mapper.GetDefault(key)
	}

	return config
}

func (c *updater) buildFrontBindHTTP(d *frontData) {
	d.front.AcceptProxy = d.get(ingtypes.FrontUseProxyProtocol).Bool()
	if bindHTTP := d.get(ingtypes.FrontBindHTTP).Value; bindHTTP != "" {
		d.front.Bind = bindHTTP
	} else {
		ip := d.get(ingtypes.FrontBindIPAddrHTTP).Value
		d.front.Bind = fmt.Sprintf("%s:%d", ip, d.front.Port())
	}
}

func (c *updater) buildFrontBindHTTPS(d *frontData) {
	d.front.AcceptProxy = d.get(ingtypes.FrontUseProxyProtocol).Bool()
	if bindHTTPS := d.get(ingtypes.FrontBindHTTPS).Value; bindHTTPS != "" {
		d.front.Bind = bindHTTPS
	} else {
		ip := d.get(ingtypes.FrontBindIPAddrHTTP).Value
		d.front.Bind = fmt.Sprintf("%s:%d", ip, d.front.Port())
	}
}

func (c *updater) buildFrontHTTPPassthrough(d *frontData) {
	if !d.front.HTTPPassthrough && !d.get(ingtypes.FrontHTTPPassthrough).Bool() {
		return
	}

	httpPort := d.front.Port()
	bind := d.get(ingtypes.FrontBindHTTPPassthrough).Value
	if bind == "" {
		bind = d.get(ingtypes.FrontBindFrontingProxy).Value
	}
	if bind == "" {
		bind = fmt.Sprintf("%s:%d", d.get(ingtypes.FrontBindIPAddrHTTP).Value, httpPort)
	}
	d.front.HTTPPassthrough = true
	d.front.HTTPPassUseProto = d.get(ingtypes.FrontUseForwardedProto).Bool()
	d.front.Bind = bind
}
