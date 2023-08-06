/*
Copyright 2023 The HAProxy Ingress Controller Authors.

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

package gatewayv1beta1

import (
	"fmt"
	"sort"
	"strconv"

	api "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

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
	// Gateway API currently does not support partial parsing, so any change
	// on resources tracked by any gateway API resource will return true to
	// NeedFullSync(), which is the only way to Sync() start a reconciliation.
	links := c.tracker.QueryLinks(c.changed.Links, false)
	_, changed := links[convtypes.ResourceGateway]
	return changed
}

func (c *converter) Sync(full bool) {
	if !full {
		return
	}
	// TODO partial parsing
	gateways, err := c.cache.GetGatewayB1Map()
	if err != nil {
		c.logger.Warn("error reading gateway list: %v", err)
		return
	}
	httpRoutes, err := c.cache.GetHTTPRouteB1List()
	if err != nil {
		c.logger.Warn("error reading httpRoute list: %v", err)
		return
	}
	sortHTTPRoutes(httpRoutes)
	for _, httpRoute := range httpRoutes {
		c.syncHTTPRoute(gateways, httpRoute)
	}
}

func sortHTTPRoutes(httpRoutes []*gatewayv1beta1.HTTPRoute) {
	sort.Slice(httpRoutes, func(i, j int) bool {
		h1 := httpRoutes[i]
		h2 := httpRoutes[j]
		if h1.CreationTimestamp != h2.CreationTimestamp {
			return h1.CreationTimestamp.Before(&h2.CreationTimestamp)
		}
		return h1.Namespace+"/"+h1.Name < h2.Namespace+"/"+h2.Name
	})
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

var (
	gatewayGroup  = gatewayv1beta1.Group(gatewayv1beta1.GroupName)
	gatewayKind   = gatewayv1beta1.Kind("Gateway")
	httpRouteKind = gatewayv1beta1.Kind("HTTPRoute")
)

func (c *converter) syncHTTPRoute(gateways map[string]*gatewayv1beta1.Gateway, httpRoute *gatewayv1beta1.HTTPRoute) {
	httpRouteSource := &Source{
		kind:      string(httpRouteKind),
		namespace: httpRoute.Namespace,
		name:      httpRoute.Name,
	}
	for _, parentRef := range httpRoute.Spec.ParentRefs {
		parentGroup := gatewayGroup
		parentKind := gatewayKind
		if parentRef.Group != nil && *parentRef.Group != "" {
			parentGroup = *parentRef.Group
		}
		if parentRef.Kind != nil && *parentRef.Kind != "" {
			parentKind = *parentRef.Kind
		}
		if parentGroup != gatewayGroup || parentKind != gatewayKind {
			c.logger.Warn("ignoring unsupported Group/Kind reference on %s: %s/%s",
				httpRouteSource, parentGroup, parentKind)
			continue
		}
		namespace := httpRoute.Namespace
		if parentRef.Namespace != nil && *parentRef.Namespace != "" {
			namespace = string(*parentRef.Namespace)
		}
		gateway, found := gateways[namespace+"/"+string(parentRef.Name)]
		if !found {
			c.logger.Warn("%s references a gateway that was not found: %s/%s",
				httpRouteSource, namespace, parentRef.Name)
			continue
		}
		gatewaySource := &Source{
			kind:      string(gatewayKind),
			namespace: gateway.Namespace,
			name:      gateway.Name,
		}
		// TODO implement gateway.Spec.Addresses
		err := c.syncHTTPRouteGateway(httpRouteSource, httpRoute, gatewaySource, gateway, parentRef.SectionName)
		if err != nil {
			c.logger.Warn("cannot attach %s to %s: %s", httpRouteSource, gatewaySource, err)
		}
	}
}

func (c *converter) syncHTTPRouteGateway(httpRouteSource *Source, httpRoute *gatewayv1beta1.HTTPRoute, gatewaySource *Source, gateway *gatewayv1beta1.Gateway, sectionName *gatewayv1beta1.SectionName) error {
	for _, listener := range gateway.Spec.Listeners {
		if sectionName != nil && *sectionName != listener.Name {
			continue
		}
		if err := c.checkListenerAllowed(gatewaySource, httpRouteSource, &listener); err != nil {
			c.logger.Warn("skipping attachment of %s to %s listener '%s': %s",
				httpRouteSource, gatewaySource, listener.Name, err)
			continue
		}
		for index, rule := range httpRoute.Spec.Rules {
			// TODO implement rule.Filters
			backend, services := c.createBackend(httpRouteSource, fmt.Sprintf("_rule%d", index), rule.BackendRefs)
			if backend != nil {
				passthrough := listener.TLS != nil && listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1beta1.TLSModePassthrough
				if passthrough {
					backend.ModeTCP = true
				}
				hostnames := c.filterHostnames(listener.Hostname, httpRoute.Spec.Hostnames)
				hosts, pathLinks := c.createHTTPHosts(httpRouteSource, hostnames, rule.Matches, backend)
				c.applyCertRef(gatewaySource, &listener, hosts)
				if c.ann != nil {
					c.ann.ReadAnnotations(backend, services, pathLinks)
				}
			}
		}
	}
	return nil
}

var errRouteNotAllowed = fmt.Errorf("listener does not allow the route")

func (c *converter) checkListenerAllowed(gatewaySource, routeSource *Source, listener *gatewayv1beta1.Listener) error {
	if listener == nil || listener.AllowedRoutes == nil {
		return errRouteNotAllowed
	}
	if err := checkListenerAllowedKind(routeSource, listener.AllowedRoutes.Kinds); err != nil {
		return err
	}
	if err := c.checkListenerAllowedNamespace(gatewaySource, routeSource, listener.AllowedRoutes.Namespaces); err != nil {
		return err
	}
	return nil
}

func checkListenerAllowedKind(routeSource *Source, kinds []gatewayv1beta1.RouteGroupKind) error {
	if len(kinds) == 0 {
		return nil
	}
	for _, kind := range kinds {
		if (kind.Group == nil || *kind.Group == gatewayGroup) && kind.Kind == gatewayv1beta1.Kind(routeSource.kind) {
			return nil
		}
	}
	return fmt.Errorf("listener does not allow route of Kind '%s'", routeSource.kind)
}

func (c *converter) checkListenerAllowedNamespace(gatewaySource, routeSource *Source, namespaces *gatewayv1beta1.RouteNamespaces) error {
	if namespaces == nil || namespaces.From == nil {
		return errRouteNotAllowed
	}
	if *namespaces.From == gatewayv1beta1.NamespacesFromSame && routeSource.namespace == gatewaySource.namespace {
		return nil
	}
	if *namespaces.From == gatewayv1beta1.NamespacesFromAll {
		return nil
	}
	if *namespaces.From == gatewayv1beta1.NamespacesFromSelector {
		if namespaces.Selector == nil {
			return errRouteNotAllowed
		}
		selector, err := v1.LabelSelectorAsSelector(namespaces.Selector)
		if err != nil {
			return err
		}
		ns, err := c.cache.GetNamespace(routeSource.namespace)
		if err != nil {
			return err
		}
		if selector.Matches(labels.Set(ns.Labels)) {
			return nil
		}
	}
	return errRouteNotAllowed
}

func (c *converter) createBackend(source *Source, index string, backendRefs []gatewayv1beta1.HTTPBackendRef) (*hatypes.Backend, []*api.Service) {
	if habackend := c.haproxy.Backends().FindBackend(source.namespace, source.name, index); habackend != nil {
		return habackend, nil
	}
	type backend struct {
		service gatewayv1beta1.ObjectName
		port    string
		epready []*convutils.Endpoint
		cl      convutils.WeightCluster
	}
	var backends []backend
	var svclist []*api.Service
	for _, back := range backendRefs {
		if back.Port == nil {
			// TODO implement nil back.Port
			continue
		}
		// TODO implement back.Group
		// TODO implement back.Kind
		// TODO implement back.Namespace
		svcName := source.namespace + "/" + string(back.Name)
		c.tracker.TrackRefName([]convtypes.TrackingRef{
			{Context: convtypes.ResourceService, UniqueName: svcName},
			{Context: convtypes.ResourceEndpoints, UniqueName: svcName},
		}, convtypes.ResourceGateway, "gw")
		svc, err := c.cache.GetService("", svcName)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", back.Name, source, err)
			continue
		}
		svclist = append(svclist, svc)
		portStr := strconv.Itoa(int(*back.Port))
		svcport := convutils.FindServicePort(svc, portStr)
		if svcport == nil {
			c.logger.Warn("skipping service '%s' on %s: port '%s' not found", back.Name, source, portStr)
			continue
		}
		epready, _, err := convutils.CreateEndpoints(c.cache, svc, svcport, c.options.EnableEPSlices)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", back.Name, source, err)
			continue
		}
		weight := 1
		if back.Weight != nil {
			weight = int(*back.Weight)
		}
		backends = append(backends, backend{
			service: back.Name,
			port:    svcport.TargetPort.String(),
			epready: epready,
			cl: convutils.WeightCluster{
				Weight: weight,
				Length: len(epready),
			},
		})
		// TODO implement back.BackendRef
		// TODO implement back.Filters
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

func (c *converter) createHTTPHosts(source *Source, hostnames []gatewayv1beta1.Hostname, matches []gatewayv1beta1.HTTPRouteMatch, backend *hatypes.Backend) (hosts []*hatypes.Host, pathLinks []*hatypes.PathLink) {
	if backend.ModeTCP && len(matches) > 0 {
		c.logger.Warn("ignoring match from %s: backend is TCP or SSL Passthrough", source)
		matches = nil
	}
	if len(matches) == 0 {
		matches = []gatewayv1beta1.HTTPRouteMatch{{}}
	}
	for _, match := range matches {
		var path string
		var haMatch hatypes.MatchType
		if match.Path != nil {
			if match.Path.Value != nil {
				path = *match.Path.Value
			}
			if match.Path.Type != nil {
				switch *match.Path.Type {
				case gatewayv1beta1.PathMatchExact:
					haMatch = hatypes.MatchExact
				case gatewayv1beta1.PathMatchPathPrefix:
					haMatch = hatypes.MatchPrefix
				case gatewayv1beta1.PathMatchRegularExpression:
					haMatch = hatypes.MatchRegex
				}
			}
		}
		if path == "" {
			path = "/"
		}
		if haMatch == "" {
			haMatch = hatypes.MatchPrefix
		}
		for _, hostname := range hostnames {
			hstr := string(hostname)
			if hstr == "" || hstr == "*" {
				hstr = hatypes.DefaultHost
			}
			h := c.haproxy.Hosts().AcquireHost(hstr)
			pathlink := hatypes.CreateHostPathLink(hstr, path, haMatch)
			var haheaders hatypes.HTTPHeaderMatch
			for _, header := range match.Headers {
				haheaders = append(haheaders, hatypes.HTTPMatch{
					Name:  string(header.Name),
					Value: header.Value,
					Regex: header.Type != nil && *header.Type == gatewayv1beta1.HeaderMatchRegularExpression,
				})
			}
			pathlink.WithHeadersMatch(haheaders)
			if h.FindPathWithLink(pathlink) != nil {
				if backend.ModeTCP && h.SSLPassthrough() {
					c.logger.Warn("skipping redeclared ssl-passthrough root path on %s", source)
					continue
				}
				if !backend.ModeTCP && !h.SSLPassthrough() {
					c.logger.Warn("skipping redeclared path '%s' type '%s' on %s", path, haMatch, source)
					continue
				}
			}
			c.tracker.TrackRefName([]convtypes.TrackingRef{
				{Context: convtypes.ResourceHAHostname, UniqueName: h.Hostname},
			}, convtypes.ResourceGateway, "gw")
			h.TLS.UseDefaultCrt = false
			h.AddLink(backend, pathlink)
			c.handlePassthrough(path, h, backend, source)
			hosts = append(hosts, h)
			pathLinks = append(pathLinks, pathlink)
		}
		// TODO implement match.Headers
		// TODO implement match.ExtensionRef
	}
	return hosts, pathLinks
}

func (c *converter) handlePassthrough(path string, h *hatypes.Host, b *hatypes.Backend, source *Source) {
	// Special handling for TLS passthrough due to current haproxy.Host limitation
	// v0.15 will refactor haproxy.Host, allowing to remove this whole func
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
			} else {
				c.logger.Warn("skipping redeclared http root path on %s", source)
			}
			// and
			// 2. remove it from the target HTTPS configuration
			h.RemovePath(hpath)
		}
	}
}

func (c *converter) filterHostnames(listenerHostname *gatewayv1beta1.Hostname, routeHostnames []gatewayv1beta1.Hostname) []gatewayv1beta1.Hostname {
	if listenerHostname == nil || *listenerHostname == "" || *listenerHostname == "*" {
		if len(routeHostnames) == 0 {
			return []gatewayv1beta1.Hostname{"*"}
		}
		return routeHostnames
	}
	// TODO implement proper filter to wildcard based listenerHostnames -- `*.domain.local`
	return []gatewayv1beta1.Hostname{*listenerHostname}
}

func (c *converter) applyCertRef(source *Source, listener *gatewayv1beta1.Listener, hosts []*hatypes.Host) {
	if listener.TLS == nil {
		return
	}
	if listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1beta1.TLSModePassthrough {
		for _, host := range hosts {
			// backend was already changed to ModeTCP; hosts.match was already
			// changed to root path only and a warning was already logged if needed
			host.SetSSLPassthrough(true)
		}
		return
	}
	certRefs := listener.TLS.CertificateRefs
	if len(certRefs) == 0 {
		c.logger.Warn("skipping certificate reference on %s listener '%s': listener has no certificate reference",
			source, listener.Name)
		return
	}
	// TODO Support more certificates
	if len(certRefs) > 1 {
		err := fmt.Errorf("listener currently supports only the first referenced certificate")
		c.logger.Warn("skipping one or more certificate references on %s listener '%s': %s",
			source, listener.Name, err)
	}
	certRef := &certRefs[0]
	crtFile, err := c.readCertRef(source.namespace, certRef)
	if err != nil {
		c.logger.Warn("skipping certificate reference on %s listener '%s': %s",
			source, listener.Name, err)
		return
	}
	for _, host := range hosts {
		if host.TLS.TLSHash != "" && host.TLS.TLSHash != crtFile.SHA1Hash {
			c.logger.Warn("skipping certificate reference on %s listener '%s' for hostname '%s': a TLS certificate was already assigned",
				source, listener.Name, host.Hostname)
			continue
		}
		host.TLS.TLSCommonName = crtFile.CommonName
		host.TLS.TLSFilename = crtFile.Filename
		host.TLS.TLSHash = crtFile.SHA1Hash
	}
}

func (c *converter) readCertRef(namespace string, certRef *gatewayv1beta1.SecretObjectReference) (crtFile convtypes.CrtFile, err error) {
	if certRef.Group != nil && *certRef.Group != "" && *certRef.Group != "core" {
		return crtFile, fmt.Errorf("unsupported Group '%s', supported groups are 'core' and ''", *certRef.Group)
	}
	if certRef.Kind != nil && *certRef.Kind != "" && *certRef.Kind != "Secret" {
		return crtFile, fmt.Errorf("unsupported Kind '%s', the only supported kind is 'Secret'", *certRef.Kind)
	}
	// TODO implement certRef.Namespace
	return c.cache.GetTLSSecretPath(namespace, string(certRef.Name),
		[]convtypes.TrackingRef{{Context: convtypes.ResourceGateway, UniqueName: "gw"}})
}
