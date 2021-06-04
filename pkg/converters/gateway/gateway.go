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
	"fmt"
	"strconv"
	"strings"

	api "k8s.io/api/core/v1"
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
func NewGatewayConverter(options *convtypes.ConverterOptions, haproxy haproxy.Config, changed *convtypes.ChangedObjects, annotationReader convtypes.AnnotationReader) Config {
	return &converter{
		options: options,
		haproxy: haproxy,
		changed: changed,
		logger:  options.Logger,
		cache:   options.Cache,
		tracker: options.Tracker,
		ann:     annotationReader,
	}
}

type converter struct {
	options *convtypes.ConverterOptions
	haproxy haproxy.Config
	changed *convtypes.ChangedObjects
	logger  types.Logger
	cache   convtypes.Cache
	tracker convtypes.Tracker
	ann     convtypes.AnnotationReader
}

func (c *converter) NeedFullSync() bool {
	// cache.Notify() already reflect the need of
	// full sync from the Gateway API resource
	// changes. Check if other changed resources
	// impact anyone related with the Gateway API.
	//
	// TODO reused from ingress, move tracking code to a common place.
	secret2names := func(secrets []*api.Secret) []string {
		secretList := make([]string, len(secrets))
		for i, secret := range secrets {
			secretList[i] = secret.Namespace + "/" + secret.Name
		}
		return secretList
	}
	svc2names := func(services []*api.Service) []string {
		serviceList := make([]string, len(services))
		for i, service := range services {
			serviceList[i] = service.Namespace + "/" + service.Name
		}
		return serviceList
	}
	ep2names := func(endpoints []*api.Endpoints) []string {
		epList := make([]string, len(endpoints))
		for i, ep := range endpoints {
			epList[i] = ep.Namespace + "/" + ep.Name
		}
		return epList
	}
	delSecretNames := secret2names(c.changed.SecretsDel)
	updSecretNames := secret2names(c.changed.SecretsUpd)
	addSecretNames := secret2names(c.changed.SecretsAdd)
	oldSecretNames := append(delSecretNames, updSecretNames...)
	delSvcNames := svc2names(c.changed.ServicesDel)
	updSvcNames := svc2names(c.changed.ServicesUpd)
	addSvcNames := svc2names(c.changed.ServicesAdd)
	oldSvcNames := append(delSvcNames, updSvcNames...)
	updEndpointsNames := ep2names(c.changed.EndpointsNew)
	oldSvcNames = append(oldSvcNames, updEndpointsNames...)
	changed := c.tracker.GetGatewayChanged(oldSecretNames, addSecretNames, oldSvcNames, addSvcNames)
	if changed {
		// only remove old links if they will be recreated
		c.tracker.DeleteGateway()
	}
	return changed
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

// Source ...
// TODO reuse ingress' Source
type Source struct {
	kind      string
	namespace string
	name      string
}

func (s *Source) String() string {
	return fmt.Sprintf("%s '%s/%s'", s.kind, s.namespace, s.name)
}

func (c *converter) syncGateway(gateway *gatewayv1alpha1.Gateway) {
	// TODO implement gateway.Spec.Addresses
	group := "networking.x-k8s.io"
	source := &Source{
		kind:      "Gateway",
		namespace: gateway.Namespace,
		name:      gateway.Name,
	}
	var httpListeners []*gatewayv1alpha1.Listener
	for i := range gateway.Spec.Listeners {
		listener := &gateway.Spec.Listeners[i]
		if listener.Routes.Group == "" || listener.Routes.Group == group {
			switch strings.ToLower(listener.Routes.Kind) {
			case "httproute":
				httpListeners = append(httpListeners, listener)
			default:
				c.logger.Warn("ignoring unsupported listener type '%s/%s' on %s", group, listener.Routes.Kind, source)
			}
		}
	}
	// TODO implement TLS listeners
	// TODO implement TCP listeners
	c.createHTTPRoutes(source, httpListeners)
}

func (c *converter) createHTTPRoutes(source *Source, httpListeners []*gatewayv1alpha1.Listener) {
	for _, listener := range httpListeners {
		// TODO implement listener.Port
		// TODO implement listener.Protocol
		// TODO implement listener.Routes.Group
		// TODO implement listener.Routes.Kind
		// TODO implement listener.Routes.Selector.MatchExpressions
		var namespace string
		switch listener.Routes.Namespaces.From {
		case gatewayv1alpha1.RouteSelectAll:
			namespace = ""
		case gatewayv1alpha1.RouteSelectSame:
			namespace = source.namespace
		case gatewayv1alpha1.RouteSelectSelector:
			// TODO implement
			namespace = source.namespace
		default:
			namespace = source.namespace
		}
		routes, err := c.cache.GetHTTPRouteList(namespace, listener.Routes.Selector.MatchLabels)
		if err != nil {
			c.logger.Warn("skipping HTTPRoutes routes from %s: %v", source, err)
			continue
		}
		for _, route := range routes {
			// TODO filter by route.Spec.Gateways
			routeSource := &Source{
				kind:      "HTTPRoute",
				namespace: route.Namespace,
				name:      route.Name,
			}
			for index, rule := range route.Spec.Rules {
				// TODO implement rule.Filters
				backend, services := c.createBackend(routeSource, fmt.Sprintf("_rule%d", index), rule.ForwardTo)
				if backend != nil {
					passthrough := listener.TLS != nil && listener.TLS.Mode == gatewayv1alpha1.TLSModePassthrough
					if passthrough {
						backend.ModeTCP = true
					}
					hostnames := c.filterHostnames(listener.Hostname, route.Spec.Hostnames)
					hosts, pathLinks := c.createHTTPHosts(routeSource, hostnames, rule.Matches, backend)
					c.applyCertRef(source, routeSource, hosts, listener, route)
					if c.ann != nil {
						c.ann.ReadAnnotations(backend, services, pathLinks)
					}
				}
			}
		}
	}
}

func (c *converter) createBackend(source *Source, index string, forwardTo []gatewayv1alpha1.HTTPRouteForwardTo) (*hatypes.Backend, []*api.Service) {
	if habackend := c.haproxy.Backends().FindBackend(source.namespace, source.name, index); habackend != nil {
		return habackend, nil
	}
	type backend struct {
		service string
		port    string
		epready []*convutils.Endpoint
		cl      convutils.WeightCluster
	}
	var backends []backend
	var svclist []*api.Service
	for _, fw := range forwardTo {
		if fw.ServiceName == nil || fw.Port == nil {
			// TODO handle the missing of the serviceName
			// TODO implement nil fw.Port
			continue
		}
		svcName := source.namespace + "/" + *fw.ServiceName
		c.tracker.TrackGateway(convtypes.ServiceType, svcName)
		svc, err := c.cache.GetService(svcName)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", *fw.ServiceName, source, err)
			continue
		}
		svclist = append(svclist, svc)
		portStr := strconv.Itoa(int(*fw.Port))
		svcport := convutils.FindServicePort(svc, portStr)
		if svcport == nil {
			c.logger.Warn("skipping service '%s' on %s: port '%s' not found", *fw.ServiceName, source, portStr)
			continue
		}
		epready, _, err := convutils.CreateEndpoints(c.cache, svc, svcport)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", *fw.ServiceName, source, err)
			continue
		}
		backends = append(backends, backend{
			service: *fw.ServiceName,
			port:    svcport.TargetPort.String(),
			epready: epready,
			cl: convutils.WeightCluster{
				Weight: int(fw.Weight),
				Length: len(epready),
			},
		})
		// TODO implement fw.BackendRef
		// TODO implement fw.Filters
	}
	if len(backends) == 0 {
		return nil, nil
	}
	habackend := c.haproxy.Backends().AcquireBackend(source.namespace, source.name, index)
	cl := make([]*convutils.WeightCluster, len(backends))
	for i := range backends {
		cl[i] = &backends[i].cl
	}
	convutils.RebalanceWeight(cl, 128)
	for i := range backends {
		for _, addr := range backends[i].epready {
			ep := habackend.AcquireEndpoint(addr.IP, addr.Port, addr.TargetRef)
			ep.Weight = cl[i].Weight
		}
	}
	return habackend, svclist
}

func (c *converter) createHTTPHosts(source *Source, hostnames []gatewayv1alpha1.Hostname, matches []gatewayv1alpha1.HTTPRouteMatch, backend *hatypes.Backend) (hosts []*hatypes.Host, pathLinks []hatypes.PathLink) {
	if backend.ModeTCP && len(matches) > 0 {
		if len(matches) > 1 || matches[0].Path.Type != gatewayv1alpha1.PathMatchPrefix || matches[0].Path.Value != "/" {
			// avoid to warn if path == "/" and type == "Prefix"
			// TODO revisit in v0.3.0 Gateway API
			c.logger.Warn("ignoring match from %s: backend is configured as TCP mode", source)
		}
		matches = nil
	}
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
		path := match.Path.Value
		if path == "" {
			path = "/"
		}
		var haMatch hatypes.MatchType
		switch match.Path.Type {
		case gatewayv1alpha1.PathMatchExact:
			haMatch = hatypes.MatchExact
		case gatewayv1alpha1.PathMatchRegularExpression:
			haMatch = hatypes.MatchRegex
		case gatewayv1alpha1.PathMatchImplementationSpecific:
			haMatch = hatypes.MatchBegin
		default:
			haMatch = hatypes.MatchPrefix
		}
		for _, hostname := range hostnames {
			hstr := string(hostname)
			if hstr == "" || hstr == "*" {
				hstr = hatypes.DefaultHost
			}
			h := c.haproxy.Hosts().AcquireHost(hstr)
			h.TLS.UseDefaultCrt = false
			h.AddPath(backend, path, haMatch)
			handlePassthrough(path, h, backend)
			hosts = append(hosts, h)
			pathLinks = append(pathLinks, hatypes.CreatePathLink(hstr, path, haMatch))
		}
		// TODO implement match.Headers
		// TODO implement match.ExtensionRef
	}
	return hosts, pathLinks
}

func handlePassthrough(path string, h *hatypes.Host, b *hatypes.Backend) {
	// Special handling for TLS passthrough due to current haproxy.Host limitation
	// v0.14 will refactor haproxy.Host, allowing to remove this whole func
	if path != "/" || (!b.ModeTCP && !h.SSLPassthrough()) {
		// only matter if root path
		// we also don't care if both present (b.ModeTCP) and past
		// (h.SSLPassthrough()) passthrough isn't/wasn't configured
		return
	}
	for _, hpath := range h.FindPath("/") {
		modeTCP := hpath.Backend.ModeTCP
		if modeTCP != nil && !*modeTCP {
			// current path has a HTTP backend in the root path of a passthrough
			// domain, and the current haproxy.Host implementation uses this as the
			// target HTTPS backend. So we need to:
			//
			// 1. copy the backend ID to b.HTTPPassthroughBackend if not configured
			if h.HTTPPassthroughBackend == "" {
				if b.ModeTCP {
					h.HTTPPassthroughBackend = hpath.Backend.ID
				} else {
					h.HTTPPassthroughBackend = b.ID
				}
			}
			// and
			// 2. remove it from the target HTTPS configuration
			h.RemovePath(hpath)
		}
	}
}

func (c *converter) filterHostnames(listenerHostname *gatewayv1alpha1.Hostname, routeHostnames []gatewayv1alpha1.Hostname) []gatewayv1alpha1.Hostname {
	if listenerHostname == nil || *listenerHostname == "" || *listenerHostname == "*" {
		if len(routeHostnames) == 0 {
			return []gatewayv1alpha1.Hostname{"*"}
		}
		return routeHostnames
	}
	// TODO implement proper filter to wildcard based listenerHostnames -- `*.domain.local`
	return []gatewayv1alpha1.Hostname{*listenerHostname}
}

func (c *converter) applyCertRef(gwSource, routeSource *Source, hosts []*hatypes.Host, listener *gatewayv1alpha1.Listener, route *gatewayv1alpha1.HTTPRoute) {
	var certRef, certFallbackRef *gatewayv1alpha1.LocalObjectReference
	var crtSource *Source
	if listener.TLS != nil {
		if listener.TLS.Mode == gatewayv1alpha1.TLSModePassthrough {
			for _, host := range hosts {
				// backend was already changed to ModeTCP; hosts.match was already
				// changed to root path only and a warning was already logged if needed
				host.SetSSLPassthrough(true)
			}
		} else if route.Spec.TLS != nil && listener.TLS.RouteOverride.Certificate == gatewayv1alpha1.TLSROuteOVerrideAllow {
			certRef = &route.Spec.TLS.CertificateRef
			certFallbackRef = listener.TLS.CertificateRef
			crtSource = routeSource
		} else {
			certRef = listener.TLS.CertificateRef
			crtSource = gwSource
		}
	}
	if certRef != nil {
		crtFile, err := c.readCertRef(crtSource.namespace, certRef)
		if err != nil {
			if certFallbackRef != nil {
				var err2 error
				crtFile, err2 = c.readCertRef(crtSource.namespace, certFallbackRef)
				if err2 != nil {
					c.logger.Warn("skipping listener certificate reference on %s: %v", gwSource, err2)
					c.logger.Warn("skipping route certificate reference on %s: %v", crtSource, err)
					return
				}
				c.logger.Warn("falling back to the listener configured certificate due to an error reading on %s: %v", crtSource, err)
			} else {
				c.logger.Warn("skipping certificate reference on %s: %v", crtSource, err)
				return
			}
		}
		for _, host := range hosts {
			if host.TLS.TLSHash != "" && host.TLS.TLSHash != crtFile.SHA1Hash {
				c.logger.Warn("skipping certificate reference on %s for hostname %s: a TLS certificate was already assigned",
					crtSource, host.Hostname)
				continue
			}
			host.TLS.TLSCommonName = crtFile.CommonName
			host.TLS.TLSFilename = crtFile.Filename
			host.TLS.TLSHash = crtFile.SHA1Hash
		}
	}
}

func (c *converter) readCertRef(namespace string, certRef *gatewayv1alpha1.LocalObjectReference) (crtFile convtypes.CrtFile, err error) {
	if certRef.Group != "" {
		return crtFile, fmt.Errorf("unsupported Group '%s'", certRef.Group)
	}
	if certRef.Kind != "" && strings.ToLower(certRef.Kind) != "secret" {
		return crtFile, fmt.Errorf("unsupported Kind '%s'", certRef.Kind)
	}
	return c.cache.GetTLSSecretPath(namespace, certRef.Name, convtypes.TrackingTarget{Gateway: true})
}
