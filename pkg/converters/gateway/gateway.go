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
	"slices"
	"sort"
	"strconv"

	api "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// Config ...
type Config interface {
	NeedFullSync() bool
	SyncFull()
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

func (c *converter) SyncFull() {
	// we're not testing TLSRoute hostname declaration collision on HTTPRoute,
	// so a validation should be added in case the order changes and
	// syncTLSRoutes() come first.
	c.syncHTTPRoutes()
	c.syncTLSRoutes()
	c.syncTCPRoutes()
}

type source struct {
	kind, namespace, name string
}

func (s *source) String() string {
	return fmt.Sprintf("%s '%s/%s'", s.kind, s.namespace, s.name)
}

func newSource(obj client.Object) source {
	return source{
		kind:      obj.GetObjectKind().GroupVersionKind().Kind,
		namespace: obj.GetNamespace(),
		name:      obj.GetName(),
	}
}

func (c *converter) syncHTTPRoutes() {
	routes, err := c.cache.GetHTTPRouteList()
	if err != nil {
		c.logger.Warn("error reading httpRoute list: %v", err)
		return
	}
	sort.Slice(routes, func(i, j int) bool {
		r1 := routes[i]
		r2 := routes[j]
		if r1.CreationTimestamp != r2.CreationTimestamp {
			return r1.CreationTimestamp.Time.Before(r2.CreationTimestamp.Time)
		}
		return r1.Namespace+"/"+r1.Name < r2.Namespace+"/"+r2.Name
	})
	for _, route := range routes {
		routeSource := newSource(route)
		c.syncRoute(&routeSource, route.Spec.ParentRefs, []gatewayv1.ProtocolType{gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType}, func(gatewaySource *source, listener *gatewayv1.Listener) {
			for index, rule := range route.Spec.Rules {
				// TODO implement rule.Filters
				backendRefs := make([]gatewayv1.BackendRef, len(rule.BackendRefs))
				for i := range rule.BackendRefs {
					// TODO implement HTTPBackendRef.Filters
					backendRefs[i] = rule.BackendRefs[i].BackendRef
				}
				backend, services := c.createBackend(&routeSource, fmt.Sprintf("_rule%d", index), false, backendRefs)
				if backend != nil {
					hostnames := c.filterHostnames(listener.Hostname, route.Spec.Hostnames)
					pathLinks := c.createHTTPHosts(gatewaySource, &routeSource, listener, hostnames, rule.Matches, backend)
					if c.ann != nil {
						c.ann.ReadAnnotations(backend, services, pathLinks)
					}
				}
			}
		})
	}
}

func (c *converter) syncTLSRoutes() {
	routes, err := c.cache.GetTLSRouteList()
	if err != nil {
		c.logger.Warn("error reading tlsRoute list: %v", err)
		return
	}
	sort.Slice(routes, func(i, j int) bool {
		r1 := routes[i]
		r2 := routes[j]
		if r1.CreationTimestamp != r2.CreationTimestamp {
			return r1.CreationTimestamp.Time.Before(r2.CreationTimestamp.Time)
		}
		return r1.Namespace+"/"+r1.Name < r2.Namespace+"/"+r2.Name
	})
	for _, route := range routes {
		routeSource := newSource(route)
		c.syncRoute(&routeSource, route.Spec.ParentRefs, []gatewayv1.ProtocolType{gatewayv1.TLSProtocolType}, func(gatewaySource *source, listener *gatewayv1.Listener) {
			for index, rule := range route.Spec.Rules {
				// TODO implement rule.Filters
				backend, services := c.createBackend(&routeSource, fmt.Sprintf("_tlsrule%d", index), true, rule.BackendRefs)
				if backend != nil {
					hostnames := c.filterHostnames(listener.Hostname, route.Spec.Hostnames)
					pathLinks := c.createTLSHosts(gatewaySource, &routeSource, listener, hostnames, backend)
					if c.ann != nil {
						c.ann.ReadAnnotations(backend, services, pathLinks)
					}
				}
			}
		})
	}
}

func (c *converter) syncTCPRoutes() {
	routes, err := c.cache.GetTCPRouteList()
	if err != nil {
		c.logger.Warn("error reading tcpRoute list: %v", err)
		return
	}
	sort.Slice(routes, func(i, j int) bool {
		r1 := routes[i]
		r2 := routes[j]
		if r1.CreationTimestamp != r2.CreationTimestamp {
			return r1.CreationTimestamp.Time.Before(r2.CreationTimestamp.Time)
		}
		return r1.Namespace+"/"+r1.Name < r2.Namespace+"/"+r2.Name
	})
	for _, route := range routes {
		routeSource := newSource(route)
		c.syncRoute(&routeSource, route.Spec.ParentRefs, []gatewayv1.ProtocolType{gatewayv1.TCPProtocolType}, func(gatewaySource *source, listener *gatewayv1.Listener) {
			for index, rule := range route.Spec.Rules {
				// TODO implement rule.Filters
				backend, services := c.createBackend(&routeSource, fmt.Sprintf("_tcprule%d", index), true, rule.BackendRefs)
				if backend != nil {
					pathLinks := c.createTCPService(gatewaySource, listener, nil, backend)
					if c.ann != nil {
						c.ann.ReadAnnotations(backend, services, pathLinks)
					}
				}
			}
		})
	}
}

var (
	gatewayGroup = gatewayv1.Group(gatewayv1.GroupName)
	gatewayKind  = gatewayv1.Kind("Gateway")
)

func (c *converter) syncRoute(routeSource *source, parentRefs []gatewayv1.ParentReference, protos []gatewayv1.ProtocolType, syncRouteListener func(gatewaySource *source, listener *gatewayv1.Listener)) {
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
		gateway, err := c.cache.GetGateway(namespace, string(parentRef.Name))
		if err != nil {
			c.logger.Error("error reading gateway: %v", err)
			continue
		}
		if gateway == nil {
			continue
		}
		gatewaySource := newSource(gateway)
		sectionName := parentRef.SectionName
		for i := range gateway.Spec.Listeners {
			listener := &gateway.Spec.Listeners[i]
			if sectionName != nil && *sectionName != listener.Name {
				continue
			}
			if listener.Protocol == "" {
				c.logger.Warn("missing protocol on %s listener '%s' for %s", gatewaySource.String(), listener.Name, routeSource.String())
				continue
			}
			if !slices.Contains(protos, listener.Protocol) {
				c.logger.Warn("invalid protocol on %s listener '%s' for %s: '%s'", gatewaySource.String(), listener.Name, routeSource.String(), listener.Protocol)
				continue
			}
			switch listener.Protocol {
			case gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
				if listener.TLS == nil {
					c.logger.Warn("protocol '%s' on %s listener '%s' is missing TLS configuration", listener.Protocol, gatewaySource.String(), listener.Name)
					continue
				}
			}
			if err := c.checkListenerAllowed(&gatewaySource, routeSource, listener); err != nil {
				c.logger.Warn("skipping attachment of %s to %s listener '%s': %s", routeSource.String(), gatewaySource.String(), listener.Name, err)
				continue
			}
			// TODO implement gateway.Spec.Addresses
			syncRouteListener(&gatewaySource, listener)
		}
	}
}

var errRouteNotAllowed = fmt.Errorf("listener does not allow the route")

func (c *converter) checkListenerAllowed(gatewaySource, routeSource *source, listener *gatewayv1.Listener) error {
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

func (c *converter) checkListenerAllowedNamespace(gatewaySource, routeSource *source, namespaces *gatewayv1.RouteNamespaces) error {
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

func (c *converter) createHTTPHosts(gatewaySource, routeSource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, matches []gatewayv1.HTTPRouteMatch, backend *hatypes.Backend) (pathLinks []*hatypes.PathLink) {
	if len(matches) == 0 {
		matches = []gatewayv1.HTTPRouteMatch{{}}
	}
	var hostsTLS map[string]*hatypes.TLSConfig
	if listener.TLS != nil {
		hostsTLS = make(map[string]*hatypes.TLSConfig)
	}
	frontend := c.haproxy.Frontends().AcquireFrontend(listener.Port, listener.Protocol == gatewayv1.HTTPSProtocolType)
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
			c.logger.Warn("skipping certificate reference on %s listener '%s': %v", gatewaySource.String(), listener.Name, err)
			return nil
		}
	}
	return pathLinks
}

func (c *converter) createTLSHosts(gatewaySource, routeSource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, backend *hatypes.Backend) []*hatypes.PathLink {
	if mode := listener.TLS.Mode; mode == nil || *mode == gatewayv1.TLSModeTerminate {
		// ssl-offload on haproxy, backend is a plain TCP service
		return c.createTCPService(gatewaySource, listener, hostnames, backend)
	}
	// ssl-passthrough, backend is TLS, just SNI inspection on haproxy without ssl-offload
	f := c.haproxy.Frontends().AcquireFrontend(listener.Port, true)
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

func (c *converter) createTCPService(gatewaySource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, backend *hatypes.Backend) []*hatypes.PathLink {
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
			c.logger.Warn("skipping certificate reference on %s listener '%s': %v", gatewaySource.String(), listener.Name, err)
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
func (c *converter) readCertRefs(gatewaySource *source, listener *gatewayv1.Listener, hostsTLS map[string]*hatypes.TLSConfig) error {
	certRefs := listener.TLS.CertificateRefs
	if len(certRefs) == 0 {
		return fmt.Errorf("listener has no certificate reference")
	}
	var defaultCrtFile *convtypes.CrtFile
	for i := range certRefs {
		certRef := certRefs[i]
		crtFile, err := c.readCertRef(gatewaySource.namespace, &certRef)
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
						gatewaySource.String(), listener.Name, hostname)
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
