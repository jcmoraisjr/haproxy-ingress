/*
Copyright 2024 The HAProxy Ingress Controller Authors.

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
	"reflect"
	"slices"
	"sort"
	"strconv"

	api "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
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
	Sync(full bool, gwtyp client.Object)
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

func (c *converter) Sync(full bool, gwtyp client.Object) {
	// TODO partial parsing
	if !full {
		return
	}

	// we're not testing TLSRoute hostname declaration collision on HTTPRoute,
	// so a validation should be added in case the order changes and
	// syncTLSRoutes() come first.
	c.syncHTTPRoutes(gwtyp)
	c.syncTLSRoutes(gwtyp)
	c.syncTCPRoutes(gwtyp)
}

func (c *converter) syncHTTPRoutes(gwtyp client.Object) {
	var httpRoutesSource []*httpRouteSource
	var err error
	switch gwtyp.(type) {
	case *gatewayv1alpha2.Gateway:
		httpRoutesSource, err = c.getHTTPRoutesSourceA2()
	case *gatewayv1beta1.Gateway:
		httpRoutesSource, err = c.getHTTPRoutesSourceB1()
	case *gatewayv1.Gateway:
		httpRoutesSource, err = c.getHTTPRoutesSource()
	default:
		panic(fmt.Errorf("unsupported gateway api type: %T", gwtyp))
	}
	if err != nil {
		c.logger.Error(err.Error())
		return
	}

	sortHTTPRoutes(httpRoutesSource)
	for _, httpRoute := range httpRoutesSource {
		c.syncRoute(&httpRoute.source, httpRoute.spec.ParentRefs, gwtyp, func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) {
			c.syncHTTPRouteGateway(httpRoute, gatewaySource, sectionName)
		})
	}
}

func (c *converter) getHTTPRoutesSourceA2() ([]*httpRouteSource, error) {
	httpRoutes, err := c.cache.GetHTTPRouteA2List()
	if err != nil {
		return nil, fmt.Errorf("error reading httpRoute list: %w", err)
	}
	httpRoutesSource := make([]*httpRouteSource, len(httpRoutes))
	for i := range httpRoutes {
		httpRoutesSource[i] = newHTTPRouteSource(httpRoutes[i], &httpRoutes[i].Spec)
	}
	return httpRoutesSource, nil
}

func (c *converter) getHTTPRoutesSourceB1() ([]*httpRouteSource, error) {
	httpRoutes, err := c.cache.GetHTTPRouteB1List()
	if err != nil {
		return nil, fmt.Errorf("error reading httpRoute list: %w", err)
	}
	httpRoutesSource := make([]*httpRouteSource, len(httpRoutes))
	for i := range httpRoutes {
		httpRoutesSource[i] = newHTTPRouteSource(httpRoutes[i], &httpRoutes[i].Spec)
	}
	return httpRoutesSource, nil
}

func (c *converter) getHTTPRoutesSource() ([]*httpRouteSource, error) {
	httpRoutes, err := c.cache.GetHTTPRouteList()
	if err != nil {
		return nil, fmt.Errorf("error reading httpRoute list: %w", err)
	}
	httpRoutesSource := make([]*httpRouteSource, len(httpRoutes))
	for i := range httpRoutes {
		httpRoutesSource[i] = newHTTPRouteSource(httpRoutes[i], &httpRoutes[i].Spec)
	}
	return httpRoutesSource, nil
}

func (c *converter) syncTLSRoutes(gwtyp client.Object) {
	if !c.options.HasTLSRouteA2 {
		return
	}
	tlsRoutes, err := c.cache.GetTLSRouteList()
	if err != nil {
		c.logger.Warn("error reading tlsRoute list: %v", err)
		return
	}
	tlsRoutesSource := make([]*tlsRouteSource, len(tlsRoutes))
	for i := range tlsRoutes {
		tlsRoutesSource[i] = newTLSRouteSource(tlsRoutes[i], &tlsRoutes[i].Spec)
	}
	sortTLSRoutes(tlsRoutesSource)
	for _, tlsRoute := range tlsRoutesSource {
		c.syncRoute(&tlsRoute.source, tlsRoute.spec.ParentRefs, gwtyp, func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) {
			c.syncTLSRouteGateway(tlsRoute, gatewaySource, sectionName)
		})
	}
}

func (c *converter) syncTCPRoutes(gwtyp client.Object) {
	if !c.options.HasTCPRouteA2 {
		return
	}
	tcpRoutes, err := c.cache.GetTCPRouteList()
	if err != nil {
		c.logger.Warn("error reading tcpRoute list: %v", err)
		return
	}
	tcpRoutesSource := make([]*tcpRouteSource, len(tcpRoutes))
	for i := range tcpRoutes {
		tcpRoutesSource[i] = newTCPRouteSource(tcpRoutes[i], &tcpRoutes[i].Spec)
	}
	sortTCPRoutes(tcpRoutesSource)
	for _, tcpRoute := range tcpRoutesSource {
		c.syncRoute(&tcpRoute.source, tcpRoute.spec.ParentRefs, gwtyp, func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) {
			c.syncTCPRouteGateway(tcpRoute, gatewaySource, sectionName)
		})
	}
}

func sortHTTPRoutes(httpRoutesSource []*httpRouteSource) {
	sort.Slice(httpRoutesSource, func(i, j int) bool {
		h1 := httpRoutesSource[i].obj
		h2 := httpRoutesSource[j].obj
		if h1.GetCreationTimestamp() != h2.GetCreationTimestamp() {
			return h1.GetCreationTimestamp().Time.Before(h2.GetCreationTimestamp().Time)
		}
		return h1.GetNamespace()+"/"+h1.GetName() < h2.GetNamespace()+"/"+h2.GetName()
	})
}

func sortTLSRoutes(tlsRoutesSource []*tlsRouteSource) {
	sort.Slice(tlsRoutesSource, func(i, j int) bool {
		r1 := tlsRoutesSource[i].obj
		r2 := tlsRoutesSource[j].obj
		if r1.GetCreationTimestamp() != r2.GetCreationTimestamp() {
			return r1.GetCreationTimestamp().Time.Before(r2.GetCreationTimestamp().Time)
		}
		return r1.GetNamespace()+"/"+r1.GetName() < r2.GetNamespace()+"/"+r2.GetName()
	})
}

func sortTCPRoutes(tcpRoutesSource []*tcpRouteSource) {
	sort.Slice(tcpRoutesSource, func(i, j int) bool {
		r1 := tcpRoutesSource[i].obj
		r2 := tcpRoutesSource[j].obj
		if r1.GetCreationTimestamp() != r2.GetCreationTimestamp() {
			return r1.GetCreationTimestamp().Time.Before(r2.GetCreationTimestamp().Time)
		}
		return r1.GetNamespace()+"/"+r1.GetName() < r2.GetNamespace()+"/"+r2.GetName()
	})
}

type source struct {
	obj client.Object
	//
	kind, namespace, name string
}

type httpRouteSource struct {
	source
	spec *gatewayv1.HTTPRouteSpec
}

type tlsRouteSource struct {
	source
	spec *gatewayv1alpha2.TLSRouteSpec
}

type tcpRouteSource struct {
	source
	spec *gatewayv1alpha2.TCPRouteSpec
}

type gatewaySource struct {
	source
	spec *gatewayv1.GatewaySpec
}

func (s *source) String() string {
	return fmt.Sprintf("%s '%s/%s'", s.kind, s.namespace, s.name)
}

func newSource(obj client.Object) source {
	return source{
		obj:       obj,
		kind:      obj.GetObjectKind().GroupVersionKind().Kind,
		namespace: obj.GetNamespace(),
		name:      obj.GetName(),
	}
}

func newHTTPRouteSource(obj client.Object, spec *gatewayv1.HTTPRouteSpec) *httpRouteSource {
	return &httpRouteSource{
		spec:   spec,
		source: newSource(obj),
	}
}

func newTLSRouteSource(obj client.Object, spec *gatewayv1alpha2.TLSRouteSpec) *tlsRouteSource {
	return &tlsRouteSource{
		spec:   spec,
		source: newSource(obj),
	}
}

func newTCPRouteSource(obj client.Object, spec *gatewayv1alpha2.TCPRouteSpec) *tcpRouteSource {
	return &tcpRouteSource{
		spec:   spec,
		source: newSource(obj),
	}
}

func (c *converter) newGatewaySource(namespace, name string, gwtyp client.Object) *gatewaySource {
	// TODO: we can simplify all these abstract gw/route fetching code after v0.16,
	// when the old controller is going to be dropped and we can redesign the cache interface.
	var gw client.Object
	var err error
	switch gwtyp.(type) {
	case *gatewayv1alpha2.Gateway:
		gw, err = c.cache.GetGatewayA2(namespace, name)
	case *gatewayv1beta1.Gateway:
		gw, err = c.cache.GetGatewayB1(namespace, name)
	case *gatewayv1.Gateway:
		gw, err = c.cache.GetGateway(namespace, name)
	default:
		panic(fmt.Errorf("unsupported Gateway type: %T", gwtyp))
	}
	if err != nil {
		c.logger.Error("error reading gateway: %v", err)
		return nil
	}
	vgw := reflect.ValueOf(gw)
	if vgw.IsNil() {
		// Checking via reflection, since `gw` will always be `!= nil`
		// because all cache methods return a pointer to the underlying struct.
		// https://go.dev/doc/faq#nil_error
		return nil
	}
	return &gatewaySource{
		spec:   vgw.Elem().FieldByName("Spec").Addr().Interface().(*gatewayv1.GatewaySpec),
		source: newSource(gw),
	}
}

var (
	gatewayGroup = gatewayv1.Group(gatewayv1.GroupName)
	gatewayKind  = gatewayv1.Kind("Gateway")
)

func (c *converter) syncRoute(routeSource *source, parentRefs []gatewayv1.ParentReference, gwtyp client.Object, syncGateway func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName)) {
	for _, parentRef := range parentRefs {
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
				routeSource, parentGroup, parentKind)
			continue
		}
		namespace := routeSource.namespace
		if parentRef.Namespace != nil && *parentRef.Namespace != "" {
			namespace = string(*parentRef.Namespace)
		}
		gatewaySource := c.newGatewaySource(namespace, string(parentRef.Name), gwtyp)
		if gatewaySource == nil {
			continue
		}
		// TODO implement gateway.Spec.Addresses
		syncGateway(gatewaySource, parentRef.SectionName)
	}
}

func (c *converter) syncHTTPRouteGateway(httpRouteSource *httpRouteSource, gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) {
	for _, listener := range gatewaySource.spec.Listeners {
		if sectionName != nil && *sectionName != listener.Name {
			continue
		}
		if !c.checkProtocol(gatewaySource, &httpRouteSource.source, listener, gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType) {
			continue
		}
		if err := c.checkListenerAllowed(gatewaySource, &httpRouteSource.source, &listener); err != nil {
			c.logger.Warn("skipping attachment of %s to %s listener '%s': %s",
				httpRouteSource, gatewaySource, listener.Name, err)
			continue
		}
		for index, rule := range httpRouteSource.spec.Rules {
			// TODO implement rule.Filters
			backendRefs := make([]gatewayv1.BackendRef, len(rule.BackendRefs))
			for i := range rule.BackendRefs {
				// TODO implement HTTPBackendRef.Filters
				backendRefs[i] = rule.BackendRefs[i].BackendRef
			}
			backend, services := c.createBackend(&httpRouteSource.source, fmt.Sprintf("_rule%d", index), false, backendRefs)
			if backend != nil {
				hostnames := c.filterHostnames(listener.Hostname, httpRouteSource.spec.Hostnames)
				pathLinks := c.createHTTPHosts(gatewaySource, &httpRouteSource.source, &listener, hostnames, rule.Matches, backend)
				if c.ann != nil {
					c.ann.ReadAnnotations(backend, services, pathLinks)
				}
			}
		}
	}
}

func (c *converter) syncTLSRouteGateway(tlsRouteSource *tlsRouteSource, gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) {
	for _, listener := range gatewaySource.spec.Listeners {
		if sectionName != nil && *sectionName != listener.Name {
			continue
		}
		if !c.checkProtocol(gatewaySource, &tlsRouteSource.source, listener, gatewayv1.TLSProtocolType) {
			continue
		}
		if err := c.checkListenerAllowed(gatewaySource, &tlsRouteSource.source, &listener); err != nil {
			c.logger.Warn("skipping attachment of %s to %s listener '%s': %s",
				tlsRouteSource, gatewaySource, listener.Name, err)
			continue
		}
		for index, rule := range tlsRouteSource.spec.Rules {
			// TODO implement rule.Filters
			backend, services := c.createBackend(&tlsRouteSource.source, fmt.Sprintf("_tlsrule%d", index), true, rule.BackendRefs)
			if backend != nil {
				hostnames := c.filterHostnames(listener.Hostname, tlsRouteSource.spec.Hostnames)
				pathLinks := c.createTLSHosts(gatewaySource, tlsRouteSource, &listener, hostnames, backend)
				if c.ann != nil {
					c.ann.ReadAnnotations(backend, services, pathLinks)
				}
			}
		}
	}
}

func (c *converter) syncTCPRouteGateway(tcpRouteSource *tcpRouteSource, gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) {
	for _, listener := range gatewaySource.spec.Listeners {
		if sectionName != nil && *sectionName != listener.Name {
			continue
		}
		if !c.checkProtocol(gatewaySource, &tcpRouteSource.source, listener, gatewayv1.TCPProtocolType) {
			continue
		}
		if err := c.checkListenerAllowed(gatewaySource, &tcpRouteSource.source, &listener); err != nil {
			c.logger.Warn("skipping attachment of %s to %s listener '%s': %s",
				tcpRouteSource, gatewaySource, listener.Name, err)
			continue
		}
		for index, rule := range tcpRouteSource.spec.Rules {
			// TODO implement rule.Filters
			backend, services := c.createBackend(&tcpRouteSource.source, fmt.Sprintf("_tcprule%d", index), true, rule.BackendRefs)
			if backend != nil {
				pathLinks := c.createTCPService(gatewaySource, &listener, nil, backend)
				if c.ann != nil {
					c.ann.ReadAnnotations(backend, services, pathLinks)
				}
			}
		}
	}
}

func (c *converter) checkProtocol(gatewaySource *gatewaySource, source *source, listener gatewayv1.Listener, proto ...gatewayv1.ProtocolType) bool {
	if listener.Protocol == "" {
		c.logger.Warn("missing protocol on %v listener '%s' for %v", gatewaySource, listener.Name, source)
		return false
	}
	if !slices.Contains(proto, listener.Protocol) {
		c.logger.Warn("invalid protocol on %v listener '%s' for %v: '%s'", gatewaySource, listener.Name, source, listener.Protocol)
		return false
	}
	switch listener.Protocol {
	case gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
		if listener.TLS == nil {
			c.logger.Warn("protocol '%s' on %v listener '%s' is missing TLS configuration", listener.Protocol, gatewaySource, listener.Name)
			return false
		}
	}
	return true
}

var errRouteNotAllowed = fmt.Errorf("listener does not allow the route")

func (c *converter) checkListenerAllowed(gatewaySource *gatewaySource, routeSource *source, listener *gatewayv1.Listener) error {
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

func checkListenerAllowedKind(routeSource *source, kinds []gatewayv1.RouteGroupKind) error {
	if len(kinds) == 0 {
		return nil
	}
	for _, kind := range kinds {
		if (kind.Group == nil || *kind.Group == gatewayGroup) && kind.Kind == gatewayv1.Kind(routeSource.kind) {
			return nil
		}
	}
	return fmt.Errorf("listener does not allow route of Kind '%s'", routeSource.kind)
}

func (c *converter) checkListenerAllowedNamespace(gatewaySource *gatewaySource, routeSource *source, namespaces *gatewayv1.RouteNamespaces) error {
	if namespaces == nil || namespaces.From == nil {
		return errRouteNotAllowed
	}
	if *namespaces.From == gatewayv1.NamespacesFromSame && routeSource.namespace == gatewaySource.namespace {
		return nil
	}
	if *namespaces.From == gatewayv1.NamespacesFromAll {
		return nil
	}
	if *namespaces.From == gatewayv1.NamespacesFromSelector {
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

func (c *converter) filterHostnames(listenerHostname *gatewayv1.Hostname, routeHostnames []gatewayv1.Hostname) []gatewayv1.Hostname {
	if listenerHostname == nil || *listenerHostname == "" || *listenerHostname == "*" {
		if len(routeHostnames) == 0 {
			return []gatewayv1.Hostname{"*"}
		}
		return routeHostnames
	}
	// TODO implement proper filter to wildcard based listenerHostnames -- `*.domain.local`
	return []gatewayv1.Hostname{*listenerHostname}
}

func (c *converter) createBackend(routeSource *source, index string, modeTCP bool, backendRefs []gatewayv1.BackendRef) (*hatypes.Backend, []*api.Service) {
	if habackend := c.haproxy.Backends().FindBackend(routeSource.namespace, routeSource.name, index); habackend != nil {
		habackend.ModeTCP = modeTCP
		return habackend, nil
	}
	type backend struct {
		service gatewayv1.ObjectName
		port    string
		epReady []*convutils.Endpoint
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
		svcName := routeSource.namespace + "/" + string(back.Name)
		c.tracker.TrackRefName([]convtypes.TrackingRef{
			{Context: convtypes.ResourceService, UniqueName: svcName},
			{Context: convtypes.ResourceEndpoints, UniqueName: svcName},
		}, convtypes.ResourceGateway, "gw")
		svc, err := c.cache.GetService("", svcName)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", back.Name, routeSource, err)
			continue
		}
		svclist = append(svclist, svc)
		portStr := strconv.Itoa(int(*back.Port))
		svcport := convutils.FindServicePort(svc, portStr)
		if svcport == nil {
			c.logger.Warn("skipping service '%s' on %s: port '%s' not found", back.Name, routeSource, portStr)
			continue
		}
		epReady, _, err := convutils.CreateEndpoints(c.cache, svc, svcport)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", back.Name, routeSource, err)
			continue
		}
		weight := 1
		if back.Weight != nil {
			weight = int(*back.Weight)
		}
		backends = append(backends, backend{
			service: back.Name,
			port:    svcport.TargetPort.String(),
			epReady: epReady,
			cl: convutils.WeightCluster{
				Weight: weight,
				Length: len(epReady),
			},
		})
		// TODO implement back.BackendRef
		// TODO implement back.Filters (HTTPBackendRef only)
	}
	if len(backends) == 0 {
		return nil, nil
	}
	habackend := c.haproxy.Backends().AcquireBackend(routeSource.namespace, routeSource.name, index)
	habackend.ModeTCP = modeTCP
	cl := make([]*convutils.WeightCluster, len(backends))
	for i := range backends {
		cl[i] = &backends[i].cl
	}
	convutils.RebalanceWeight(cl, 128)
	for i := range backends {
		for _, addr := range backends[i].epReady {
			ep := habackend.AddEndpoint(addr.IP, addr.Port, addr.TargetRef)
			ep.Weight = cl[i].Weight
		}
	}
	return habackend, svclist
}

func (c *converter) createHTTPHosts(gatewaySource *gatewaySource, routeSource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, matches []gatewayv1.HTTPRouteMatch, backend *hatypes.Backend) (pathLinks []*hatypes.PathLink) {
	if len(matches) == 0 {
		matches = []gatewayv1.HTTPRouteMatch{{}}
	}
	var hostsTLS map[string]*hatypes.TLSConfig
	if listener.TLS != nil {
		hostsTLS = make(map[string]*hatypes.TLSConfig)
	}
	frontend := c.haproxy.Frontends().AcquireFrontend(int32(listener.Port), listener.Protocol == gatewayv1.HTTPSProtocolType)
	for _, match := range matches {
		var path string
		var haMatch hatypes.MatchType
		if match.Path != nil {
			if match.Path.Value != nil {
				path = *match.Path.Value
			}
			if match.Path.Type != nil {
				switch *match.Path.Type {
				case gatewayv1.PathMatchExact:
					haMatch = hatypes.MatchExact
				case gatewayv1.PathMatchPathPrefix:
					haMatch = hatypes.MatchPrefix
				case gatewayv1.PathMatchRegularExpression:
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
			h := frontend.AcquireHost(hstr)
			pathlink := hatypes.CreatePathLink(path, haMatch).WithHTTPHost(h)
			var haheaders hatypes.HTTPHeaderMatch
			for _, header := range match.Headers {
				haheaders = append(haheaders, hatypes.HTTPMatch{
					Name:  string(header.Name),
					Value: header.Value,
					Regex: header.Type != nil && *header.Type == gatewayv1.HeaderMatchRegularExpression,
				})
			}
			pathlink.WithHeadersMatch(haheaders)
			if h.FindPathWithLink(pathlink) != nil {
				c.logger.Warn("skipping redeclared path '%s' type '%s' on %s", path, haMatch, routeSource)
				continue
			}
			c.tracker.TrackRefName([]convtypes.TrackingRef{
				{Context: convtypes.ResourceHAHostname, UniqueName: h.Hostname},
			}, convtypes.ResourceGateway, "gw")
			h.AddLink(backend, pathlink)
			pathLinks = append(pathLinks, pathlink)
			if hostsTLS != nil {
				hostsTLS[h.Hostname] = &h.TLS.TLSConfig
			}
		}
		// TODO implement match.ExtensionRef
	}
	if hostsTLS != nil {
		err := c.readCertRefs(gatewaySource, listener, hostsTLS)
		if err != nil {
			// avoid partial (i.e. broken) configuration by reverting all the added paths in the case of an error
			frontend.RemoveAllLinks(pathLinks...)
			c.logger.Warn("skipping certificate reference on %s listener '%s': %v", gatewaySource, listener.Name, err)
			return nil
		}
	}
	return pathLinks
}

func (c *converter) createTLSHosts(gatewaySource *gatewaySource, routeSource *tlsRouteSource, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, backend *hatypes.Backend) []*hatypes.PathLink {
	if mode := listener.TLS.Mode; mode == nil || *mode == gatewayv1.TLSModeTerminate {
		// ssl-offload on haproxy, backend is a plain TCP service
		return c.createTCPService(gatewaySource, listener, hostnames, backend)
	}
	// ssl-passthrough, backend is TLS, just SNI inspection on haproxy without ssl-offload
	f := c.haproxy.Frontends().AcquireFrontend(int32(listener.Port), true)
	for _, hostname := range hostnames {
		h := f.FindHost(string(hostname))
		if h != nil && !h.SSLPassthrough {
			c.logger.Warn("skipping hostname '%s' on %s: hostname already declared as HTTP", hostname, routeSource)
			continue
		}
		if h == nil {
			h = f.AcquireHost(string(hostname))
			h.SSLPassthrough = true
		}
		link := hatypes.CreatePathLink("/", hatypes.MatchPrefix).WithHTTPHost(h)
		if h.FindPathWithLink(link) != nil {
			c.logger.Warn("skipping redeclared ssl-passthrough hostname '%s' on %s", hostname, routeSource)
			continue
		}
		c.tracker.TrackNames(convtypes.ResourceHAHostname, string(hostname), convtypes.ResourceGateway, "gw")
		h.AddLink(backend, link) // TODO missing a better abstraction for ssl-passthrough handling
	}
	return nil
}

func (c *converter) createTCPService(gatewaySource *gatewaySource, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, backend *hatypes.Backend) []*hatypes.PathLink {
	tcpport := c.haproxy.TCPServices().AcquireTCPPort(int(listener.Port))
	if len(hostnames) == 0 || listener.TLS == nil {
		// defaults to wildcard (len==0); overwrite hostnames if non TLS (TLS==nil)
		hostnames = []gatewayv1.Hostname{"*"}
	}
	var hostsTLS map[string]*hatypes.TLSConfig
	if listener.TLS != nil {
		hostsTLS = make(map[string]*hatypes.TLSConfig)
	}
	var pathlinks []*hatypes.PathLink
	for _, hostname := range hostnames {
		if hostname == "" || hostname == "*" {
			hostname = hatypes.DefaultHost
		}
		tcphost := tcpport.AcquireTLSHost(string(hostname))
		if !tcphost.Backend.IsEmpty() {
			c.logger.Warn("skipping redeclared TCPService '%s'", hostname)
			continue
		}
		c.tracker.TrackNames(convtypes.ResourceHAHostname, string(hostname), convtypes.ResourceGateway, "gw")
		tcphost.Backend = backend.BackendID()
		pathlinks = append(pathlinks, hatypes.CreatePathLink("/", hatypes.MatchExact).WithTCPHost(tcphost))
		if hostsTLS != nil {
			tls := &hatypes.TCPServiceTLSConfig{}
			tcpport.TLS[string(hostname)] = tls
			hostsTLS[string(hostname)] = &tls.TLSConfig
		}
	}
	if hostsTLS != nil {
		err := c.readCertRefs(gatewaySource, listener, hostsTLS)
		if err != nil {
			// avoid partial (i.e. broken) configuration by reverting all the added services in the case of an error
			c.haproxy.TCPServices().RemoveAllLinks(pathlinks...)
			c.logger.Warn("skipping certificate reference on %s listener '%s': %v", gatewaySource, listener.Name, err)
			return nil
		}
	}
	return pathlinks
}

// readCertRefs updates all the TLSConfig references on the hostsTLS hashmap with certificates provided via
// listener.TLS.CertificateRefs. No further action is needed, provided that the hashmap is populated with the
// reference to the real TLSConfig.
//
// Special handling of the added hosts or services should be done in the case of an error: the caller should
// revert all the changes; otherwise, haproxy would lead to an incomplete/invalid configuration due to the
// missing of some TLS certificates.
func (c *converter) readCertRefs(source *gatewaySource, listener *gatewayv1.Listener, hostsTLS map[string]*hatypes.TLSConfig) error {
	certRefs := listener.TLS.CertificateRefs
	if len(certRefs) == 0 {
		return fmt.Errorf("listener has no certificate reference")
	}
	var defaultCrtFile *convtypes.CrtFile
	for i := range certRefs {
		certRef := certRefs[i]
		crtFile, err := c.readCertRef(source.namespace, &certRef)
		if err != nil {
			return err
		}
		if defaultCrtFile == nil {
			// first certificate, use later on hosts with missing ones
			defaultCrtFile = &crtFile
		}
		for hostname, hostTLS := range hostsTLS {
			if crtFile.Certificate.VerifyHostname(hostname) == nil {
				if hostTLS.TLSHash != "" && hostTLS.TLSHash != crtFile.SHA1Hash {
					c.logger.Warn("skipping certificate reference on %s listener '%s' for hostname '%s': a TLS certificate was already assigned",
						source, listener.Name, hostname)
					continue
				}
				hostTLS.TLSCommonName = crtFile.Certificate.Subject.CommonName
				hostTLS.TLSFilename = crtFile.Filename
				hostTLS.TLSHash = crtFile.SHA1Hash
			}
		}
	}
	for _, hostTLS := range hostsTLS {
		if hostTLS.TLSHash == "" {
			hostTLS.TLSCommonName = defaultCrtFile.Certificate.Subject.CommonName
			hostTLS.TLSFilename = defaultCrtFile.Filename
			hostTLS.TLSHash = defaultCrtFile.SHA1Hash
		}
	}
	return nil
}

func (c *converter) readCertRef(namespace string, certRef *gatewayv1.SecretObjectReference) (crtFile convtypes.CrtFile, err error) {
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
