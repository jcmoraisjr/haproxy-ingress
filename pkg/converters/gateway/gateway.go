/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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

package gateway

import (
	"strconv"
	"strings"

	gatewayv1alpha1 "sigs.k8s.io/gateway-api/apis/v1alpha1"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// Config ...
type Config interface {
	NeedFullSync() bool
	Sync(full bool)
}

// NewGatewayConverter ...
func NewGatewayConverter(options *convtypes.ConverterOptions, haproxy haproxy.Config, changed *convtypes.ChangedObjects) Config {
	return &converter{
		options: options,
		haproxy: haproxy,
		changed: changed,
		logger:  options.Logger,
		cache:   options.Cache,
	}
}

type converter struct {
	options *convtypes.ConverterOptions
	haproxy haproxy.Config
	changed *convtypes.ChangedObjects
	logger  types.Logger
	cache   convtypes.Cache
}

func (c *converter) NeedFullSync() bool {
	// cache.Notify() already reflect the need of
	// full sync from the Gateway API perspective
	return false
}

func (c *converter) Sync(full bool) {
	if !full {
		// there is no change in the Gateway API resources
		return
	}
	// TODO partial parsing
	gateways, err := c.cache.GetGatewayList()
	if err != nil {
		c.logger.Warn("error reading gateway list: %v", err)
		return
	}
	for _, gateway := range gateways {
		c.syncGateway(gateway)
	}
}

func (c *converter) syncGateway(gateway *gatewayv1alpha1.Gateway) {
	var httpRoutes []*gatewayv1alpha1.HTTPRoute
	// TODO implement gateway.Spec.Addresses
	for _, listener := range gateway.Spec.Listeners {
		// TODO validate listener.Routes.Group
		// TODO implement listener.Hostname
		// TODO implement listener.Port
		// TODO implement listener.Protocol
		// TODO implement listener.TLS
		switch strings.ToLower(listener.Routes.Kind) {
		case "httproute":
			// TODO implement listener.Routes.Selector.MatchExpressions
			if routes, err := c.cache.GetHTTPRouteList(listener.Routes.Selector.MatchLabels); err == nil {
				// TODO handle error
				httpRoutes = append(httpRoutes, routes...)
			}
		default:
			// TODO handle error
		}
	}
	for _, route := range httpRoutes {
		// TODO filter by route.Spec.Gateways
		// TODO implement route.Spec.TLS
		for _, rule := range route.Spec.Rules {
			var serviceName string
			var port gatewayv1alpha1.PortNumber
			// TODO implement rule.Filters
			for _, fw := range rule.ForwardTo {
				if fw.ServiceName != nil {
					serviceName = *fw.ServiceName
				}
				if fw.Port != nil {
					port = *fw.Port
				}
				// TODO implement nil fw.Port
				// TODO implement fw.BackendRef
				// TODO implement fw.Weight
				// TODO implement fw.Filters
				break
				// TODO add all ForwardTo
			}
			if serviceName == "" || port == 0 {
				// TODO handle the missing of the serviceName
				continue
			}
			svc, err := c.cache.GetService(gateway.Namespace + "/" + serviceName)
			if err != nil {
				// TODO handle error
				continue
			}
			portStr := strconv.Itoa(int(port))
			svcport := convutils.FindServicePort(svc, portStr)
			if svcport == nil {
				// TODO handle error
				continue
			}
			b := c.haproxy.Backends().AcquireBackend(gateway.Namespace, serviceName, svcport.TargetPort.String())
			hostnames := route.Spec.Hostnames
			if len(hostnames) == 0 {
				hostnames = []gatewayv1alpha1.Hostname{"*"}
			}
			matches := rule.Matches
			if len(matches) == 0 {
				matches = []gatewayv1alpha1.HTTPRouteMatch{
					{
						Path: gatewayv1alpha1.HTTPPathMatch{
							Type:  gatewayv1alpha1.PathMatchPrefix,
							Value: "/",
						},
					},
				}
			}
			for _, match := range matches {
				for _, hostname := range hostnames {
					// TODO implement wildcard hostnames
					hstr := string(hostname)
					if hstr == "" || hstr == "*" {
						hstr = hatypes.DefaultHost
					}
					h := c.haproxy.Hosts().AcquireHost(hstr)
					h.AddPath(b, match.Path.Value, hatypes.MatchPrefix)
				}
				// TODO implement match.Path.Type
				// TODO implement match.Headers
				// TODO implement match.ExtensionRef
			}
			epready, _, err := convutils.CreateEndpoints(c.cache, svc, svcport)
			if err != nil {
				// TODO handle error
				continue
			}
			for _, addr := range epready {
				ep := b.AcquireEndpoint(addr.IP, addr.Port, addr.TargetRef)
				ep.Weight = 1
			}
		}
	}
}
