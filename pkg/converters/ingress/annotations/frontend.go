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
	"slices"
	"strconv"
	"strings"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type FrontendsPorts struct {
	logger types.Logger
	httpPort,
	httpsPort,
	httpPassPort int32
	denyPorts    []int32
	denyPortsStr string
}

func NewFrontendsPorts(logger types.Logger, haproxy haproxy.Config, globalMapper *Mapper) *FrontendsPorts {
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

	if globalMapper.Get(ingtypes.GlobalCreateDefaultFrontends).Bool() {
		// backward compatible behavior, in case user asks for it
		_ = haproxy.Frontends().AcquireFrontend(httpPort, false)
		_ = haproxy.Frontends().AcquireFrontend(httpsPort, true)
		if httpPassPort > 0 && httpPassPort != httpPort {
			_ = haproxy.Frontends().AcquireFrontend(httpPassPort, false)
		}
	} else {
		// ensures empty frontends are removed on partial parsing
		haproxy.Frontends().RemoveEmptyFrontends()
	}

	// denied ports
	denyPorts := []int32{httpPort, httpsPort}
	denyPortsStr := []string{strconv.Itoa(int(httpPort)), strconv.Itoa(int(httpsPort))}
	if httpPassPort > 0 {
		denyPorts = append(denyPorts, httpPassPort)
		denyPortsStr = append(denyPortsStr, strconv.Itoa(int(httpPassPort)))
	}

	return &FrontendsPorts{
		logger:       logger,
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		httpPassPort: httpPassPort,
		denyPorts:    denyPorts,
		denyPortsStr: strings.Join(denyPortsStr, "/"),
	}
}

func (fp *FrontendsPorts) AcquirePorts(mapper *Mapper) (httpPort, httpsPort, httpPassPort int32, localPorts bool) {
	// reading globals as default values
	httpPort = fp.httpPort
	httpsPort = fp.httpsPort
	httpPassPort = fp.httpPassPort
	localPorts = false

	// defaults already in place, starting local config check
	localPortsConfig := mapper.Get(ingtypes.FrontHTTPPortsLocal)
	if localPortsConfig.Source == nil {
		// use default if local-config is configured globally, or not configured at all
		return
	}
	ports := strings.Split(localPortsConfig.Value, "/")
	var localPortHTTP, localPortHTTPS int32
	if len(ports) == 2 {
		portHTTP, _ := strconv.Atoi(ports[0])
		portHTTPS, _ := strconv.Atoi(ports[1])
		localPortHTTP = int32(portHTTP)
		localPortHTTPS = int32(portHTTPS)
	}
	if localPortHTTP <= 0 || localPortHTTPS <= 0 {
		fp.logger.Warn("ignoring http/https ports configuration on %v: invalid configuration: '%s'", localPortsConfig.Source, localPortsConfig.Value)
		return
	}

	// local port configuration allowed, checking now for invalid or overlapping config
	if slices.Contains(fp.denyPorts, localPortHTTP) || slices.Contains(fp.denyPorts, localPortHTTPS) {
		fp.logger.Warn("ignoring http/https ports configuration on %v: local http(s) ports cannot collide with global '%s' ones", localPortsConfig.Source, fp.denyPortsStr)
		return
	}

	return localPortHTTP, localPortHTTPS, httpPassPort, true
}

func (c *frontData) get(key string) *ConfigValue {
	config := c.mapper.Get(key)
	if config.Source != nil && !c.localPorts {
		// malformed configuration: a frontend key was configured via annotation (config.Source not nil)
		// and there is not a valid local port configuration, warn and use default/global instead.
		if c.mapper.Get(ingtypes.FrontHTTPPortsLocal).Source == nil {
			// logging only in case http-ports-local is missing; otherwise the reason why c.localPorts is false is already logged.
			c.logger.Warn("skipping '%s' configuration on %s: missing '%s' key", key, config.Source, ingtypes.FrontHTTPPortsLocal)
		}
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
