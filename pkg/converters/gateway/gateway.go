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

	c.syncHTTPRoutes(gwtyp)
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
		c.syncRoute(&httpRoute.source, httpRoute.spec.ParentRefs, gwtyp, func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) error {
			return c.syncHTTPRouteGateway(httpRoute, gatewaySource, sectionName)
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
		c.syncRoute(&tcpRoute.source, tcpRoute.spec.ParentRefs, gwtyp, func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) error {
			return c.syncTCPRouteGateway(tcpRoute, gatewaySource, sectionName)
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

func (c *converter) syncRoute(routeSource *source, parentRefs []gatewayv1.ParentReference, gwtyp client.Object, syncGateway func(gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) error) {
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
		err := syncGateway(gatewaySource, parentRef.SectionName)
		if err != nil {
			c.logger.Warn("cannot attach %s to %s: %s", routeSource, gatewaySource, err)
		}
	}
}

func (c *converter) syncHTTPRouteGateway(httpRouteSource *httpRouteSource, gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) error {
	for _, listener := range gatewaySource.spec.Listeners {
		if sectionName != nil && *sectionName != listener.Name {
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
				backendRefs[i] = rule.BackendRefs[i].BackendRef
			}
			backend, services := c.createBackend(&httpRouteSource.source, fmt.Sprintf("_rule%d", index), backendRefs)
			if backend != nil {
				passthrough := listener.TLS != nil && listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1.TLSModePassthrough
				if passthrough {
					backend.ModeTCP = true
				}
				hostnames := c.filterHostnames(listener.Hostname, httpRouteSource.spec.Hostnames)
				hosts, pathLinks := c.createHTTPHosts(&httpRouteSource.source, hostnames, rule.Matches, backend)
				c.applyCertRef(gatewaySource, &listener, hosts)
				if c.ann != nil {
					c.ann.ReadAnnotations(backend, services, pathLinks)
				}
			}
		}
	}
	return nil
}

func (c *converter) syncTCPRouteGateway(tcpRouteSource *tcpRouteSource, gatewaySource *gatewaySource, sectionName *gatewayv1.SectionName) error {
	for _, listener := range gatewaySource.spec.Listeners {
		if sectionName != nil && *sectionName != listener.Name {
			continue
		}
		if err := c.checkListenerAllowed(gatewaySource, &tcpRouteSource.source, &listener); err != nil {
			c.logger.Warn("skipping attachment of %s to %s listener '%s': %s",
				tcpRouteSource, gatewaySource, listener.Name, err)
			continue
		}
		for index, rule := range tcpRouteSource.spec.Rules {
			// TODO implement rule.Filters
			backend, services := c.createBackend(&tcpRouteSource.source, fmt.Sprintf("_tcprule%d", index), rule.BackendRefs)
			if backend != nil {
				pathLinks := c.createTCPService(listener.Port, backend)
				if c.ann != nil {
					c.ann.ReadAnnotations(backend, services, pathLinks)
				}
			}
		}
	}
	return nil
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

func (c *converter) createBackend(routeSource *source, index string, backendRefs []gatewayv1.BackendRef) (*hatypes.Backend, []*api.Service) {
	if habackend := c.haproxy.Backends().FindBackend(routeSource.namespace, routeSource.name, index); habackend != nil {
		return habackend, nil
	}
	type backend struct {
		service gatewayv1.ObjectName
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
		epready, _, err := convutils.CreateEndpoints(c.cache, svc, svcport, c.options.EnableEPSlices)
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
			epready: epready,
			cl: convutils.WeightCluster{
				Weight: weight,
				Length: len(epready),
			},
		})
		// TODO implement back.BackendRef
		// TODO implement back.Filters (HTTPBackendRef only)
	}
	if len(backends) == 0 {
		return nil, nil
	}
	habackend := c.haproxy.Backends().AcquireBackend(routeSource.namespace, routeSource.name, index)
	cl := make([]*convutils.WeightCluster, len(backends))
	for i := range backends {
		cl[i] = &backends[i].cl
	}
	convutils.RebalanceWeight(cl, 128)
	for i := range backends {
		for _, addr := range backends[i].epready {
			ep := habackend.AddEndpoint(addr.IP, addr.Port, addr.TargetRef)
			ep.Weight = cl[i].Weight
		}
	}
	return habackend, svclist
}

func (c *converter) createHTTPHosts(routeSource *source, hostnames []gatewayv1.Hostname, matches []gatewayv1.HTTPRouteMatch, backend *hatypes.Backend) (hosts []*hatypes.Host, pathLinks []*hatypes.PathLink) {
	if backend.ModeTCP && len(matches) > 0 {
		c.logger.Warn("ignoring match from %s: backend is TCP or SSL Passthrough", routeSource)
		matches = nil
	}
	if len(matches) == 0 {
		matches = []gatewayv1.HTTPRouteMatch{{}}
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
			h := c.haproxy.Hosts().AcquireHost(hstr)
			pathlink := hatypes.CreateHostPathLink(hstr, path, haMatch)
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
				if backend.ModeTCP && h.SSLPassthrough() {
					c.logger.Warn("skipping redeclared ssl-passthrough root path on %s", routeSource)
					continue
				}
				if !backend.ModeTCP && !h.SSLPassthrough() {
					c.logger.Warn("skipping redeclared path '%s' type '%s' on %s", path, haMatch, routeSource)
					continue
				}
			}
			c.tracker.TrackRefName([]convtypes.TrackingRef{
				{Context: convtypes.ResourceHAHostname, UniqueName: h.Hostname},
			}, convtypes.ResourceGateway, "gw")
			h.TLS.UseDefaultCrt = false
			h.AddLink(backend, pathlink)
			c.handlePassthrough(path, h, backend, routeSource)
			hosts = append(hosts, h)
			pathLinks = append(pathLinks, pathlink)
		}
		// TODO implement match.ExtensionRef
	}
	return hosts, pathLinks
}

func (c *converter) createTCPService(port gatewayv1.PortNumber, backend *hatypes.Backend) []*hatypes.PathLink {
	// TODO: this mimics the format currently expected by TCPService,
	// implemented by ingress as well; need a refactor, there's already
	// a few TODOs in ingress converter and TCPService implementations.
	hostname := fmt.Sprintf("%s:%d", hatypes.DefaultHost, port)
	backend.ModeTCP = true
	_, tcphost := c.haproxy.TCPServices().AcquireTCPService(hostname)
	if !tcphost.Backend.IsEmpty() {
		c.logger.Warn("skipping redeclared TCPService '%s'", hostname)
		return nil
	}
	c.tracker.TrackNames(convtypes.ResourceHAHostname, hostname, convtypes.ResourceGateway, "gw")
	tcphost.Backend = backend.BackendID()
	pathLink := hatypes.CreateHostPathLink(hostname, "/", hatypes.MatchExact)
	return []*hatypes.PathLink{pathLink}
}

func (c *converter) handlePassthrough(path string, h *hatypes.Host, b *hatypes.Backend, routeSource *source) {
	// Special handling for TLS passthrough due to current haproxy.Host limitation
	// TODO: haproxy.Host refactor, allowing to remove this whole func
	if path != "/" || (!b.ModeTCP && !h.SSLPassthrough()) {
		// only matter if root path
		// we also don't care if both present (b.ModeTCP) and past
		// (h.SSLPassthrough()) passthrough isn't/wasn't configured
		return
	}
	for _, hpath := range h.FindPath("/") {
		backend := c.haproxy.Backends().FindBackend(hpath.Backend.Namespace, hpath.Backend.Name, hpath.Backend.Port)
		if backend != nil && !backend.ModeTCP {
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
				c.logger.Warn("skipping redeclared http root path on %s", routeSource)
			}
			// and
			// 2. remove it from the target HTTPS configuration
			h.RemovePath(hpath)
		}
	}
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

func (c *converter) applyCertRef(source *gatewaySource, listener *gatewayv1.Listener, hosts []*hatypes.Host) {
	if listener.TLS == nil {
		return
	}
	if listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1.TLSModePassthrough {
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
