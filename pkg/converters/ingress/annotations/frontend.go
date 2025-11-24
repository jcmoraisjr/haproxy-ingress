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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

func AcquireFrontendPorts(logger types.Logger, mapper *Mapper) (httpPort, httpsPort int32, localPorts bool) {
	httpPort = mapper.Get(ingtypes.GlobalHTTPPort).Int32()
	httpsPort = mapper.Get(ingtypes.GlobalHTTPSPort).Int32()
	localPortsConfig := mapper.Get(ingtypes.FrontHTTPPortsLocal)
	if localPortsConfig.Source != nil {
		ports := strings.Split(localPortsConfig.Value, "/")
		var p0, p1 int32
		if len(ports) == 2 {
			p0i, _ := strconv.Atoi(ports[0])
			p1i, _ := strconv.Atoi(ports[1])
			p0 = int32(p0i)
			p1 = int32(p1i)
		}
		denyPorts := []int32{httpPort, httpsPort}
		switch {
		case p0 == 0 || p1 == 0:
			logger.Warn("ignoring invalid http/https ports configuration '%s' on %v", localPortsConfig.Value, localPortsConfig.Source)
		case slices.Contains(denyPorts, p0) || slices.Contains(denyPorts, p1):
			logger.Warn("ignoring http/https ports configuration on %v: local http(s) ports cannot collide with global '%d/%d' ones", localPortsConfig.Source, httpPort, httpsPort)
		default:
			httpPort = p0
			httpsPort = p1
			localPorts = true
		}
	}
	frontingPort := mapper.Get(ingtypes.FrontFrontingProxyPort).Int32()
	if frontingPort > 0 {
		httpPort = frontingPort
	}
	return httpPort, httpsPort, localPorts
}

func (c *frontData) get(key string) *ConfigValue {
	config := c.mapper.Get(key)
	if config.Source != nil && !c.localPorts {
		// malformed configuration: a frontend key was configured via annotation (config.Source not nil)
		// and there is not a valid local port configuration, warn and use default/global instead.
		c.logger.Warn("skipping '%s' configuration on %s: missing '%s' key", key, config.Source, ingtypes.FrontHTTPPortsLocal)
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

func (c *updater) buildFrontFrontingProxy(d *frontData) {
	bind := d.get(ingtypes.FrontBindFrontingProxy).Value
	if bind == "" {
		port := d.get(ingtypes.FrontFrontingProxyPort).Int()
		if port == 0 {
			port = d.get(ingtypes.FrontHTTPStoHTTPPort).Int()
		}
		if port == 0 {
			return
		}
		bind = fmt.Sprintf("%s:%d", d.get(ingtypes.FrontBindIPAddrHTTP).Value, port)
	}
	d.front.IsFrontingProxy = true
	d.front.IsFrontingUseProto = d.get(ingtypes.FrontUseForwardedProto).Bool()
	d.front.Bind = bind
}
