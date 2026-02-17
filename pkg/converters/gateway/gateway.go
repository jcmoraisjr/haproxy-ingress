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
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	pkgtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// Config ...
type Config interface {
	NeedFullSync() bool
	SyncFull() error
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
		events: events{
			classes: nil, // initialized in the very beginning, via syncGatewayClass()
			gateway: make(map[types.NamespacedName]*gatewayEvent),
			route:   make(map[types.NamespacedName]*routeEvent),
			grant:   make(map[gatewayv1beta1.ReferenceGrantFrom][]referenceGrantTo),
		},
	}
}

type converter struct {
	options *convtypes.ConverterOptions
	haproxy haproxy.Config
	changed *convtypes.ChangedObjects
	logger  pkgtypes.Logger
	cache   convtypes.Cache
	tracker convtypes.Tracker
	ann     convtypes.AnnotationReader
	events  events
}

type events struct {
	classes map[gatewayv1.ObjectName]*gatewayv1.GatewayClass
	gateway map[types.NamespacedName]*gatewayEvent
	route   map[types.NamespacedName]*routeEvent
	grant   map[gatewayv1beta1.ReferenceGrantFrom][]referenceGrantTo
}

type referenceGrantTo struct {
	gatewayv1beta1.ReferenceGrantTo
	Namespace gatewayv1.Namespace
}

type gatewayEvent struct {
	gateway    *gatewayv1.Gateway
	source     *source
	controller gatewayv1.GatewayController
	listeners  map[gatewayv1.SectionName]*listenerEvent
}

type listenerEvent struct {
	certRefs         *certificateRefs
	supportedKinds   []routeGroupKind
	unsupportedKinds []routeGroupKind
	unsupportedProto string
	attachedRoutes   int32
}

type routeGroupKind struct {
	group gatewayv1.Group
	kind  gatewayv1.Kind
}

type certificateRefs struct {
	passthrough          bool
	certFiles            []convtypes.CrtFile
	certRefErrors        []error
	certRefNoGrant       []string
	conflictingHostnames []string
}

type routeEvent struct {
	route  *source
	parent []*routeParentRefEvent
}

type routeParentRefEvent struct {
	ref               parentReference
	gateway           *gatewayEvent
	listener          string
	match             bool
	notAllowed        string
	nohostname        bool
	backendRef        string
	backendRefNoGrant []string
	invalidKind       string
	unsupportedValue  string
}

type parentReference struct {
	namespace gatewayv1.Namespace
	name      gatewayv1.ObjectName
	section   gatewayv1.SectionName
	port      gatewayv1.PortNumber
}

type source struct {
	types.NamespacedName
	schema.GroupVersionKind
	generation int64
}

func (k *routeGroupKind) String() string {
	return string(k.group) + "/" + string(k.kind)
}

func (s *source) String() string {
	if s.Namespace != "" {
		return fmt.Sprintf("%s '%s/%s'", s.Kind, s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s '%s'", s.Kind, s.Name)
}

func newSource(obj client.Object) *source {
	return &source{
		NamespacedName: types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		},
		GroupVersionKind: obj.GetObjectKind().GroupVersionKind(),
		generation:       obj.GetGeneration(),
	}
}

func buildEventGroupKind(gk gatewayv1.RouteGroupKind) routeGroupKind {
	return routeGroupKind{
		group: ptr.Deref(gk.Group, gatewayGroup),
		kind:  gk.Kind,
	}
}

func buildStatusGroupKinds(egks []routeGroupKind) []gatewayv1.RouteGroupKind {
	gks := make([]gatewayv1.RouteGroupKind, 0, len(egks))
	for _, egk := range egks {
		var gk gatewayv1.RouteGroupKind
		if egk.group != "" && egk.group != gatewayGroup {
			gk.Group = &egk.group
		}
		gk.Kind = egk.kind
		gks = append(gks, gk)
	}
	return gks
}

func buildEventParentRef(parentRef gatewayv1.ParentReference) parentReference {
	return parentReference{
		namespace: ptr.Deref(parentRef.Namespace, ""),
		name:      parentRef.Name,
		section:   ptr.Deref(parentRef.SectionName, ""),
		port:      ptr.Deref(parentRef.Port, 0),
	}
}

func buildStatusParentRef(parentRef parentReference) gatewayv1.ParentReference {
	ref := gatewayv1.ParentReference{
		Name: parentRef.name,
	}
	if parentRef.namespace != "" {
		ref.Namespace = &parentRef.namespace
	}
	if parentRef.section != "" {
		ref.SectionName = &parentRef.section
	}
	if parentRef.port > 0 {
		ref.Port = &parentRef.port
	}
	return ref
}

func (c *converter) NeedFullSync() bool {
	// Gateway API currently does not support partial parsing, so any change
	// on resources tracked by any gateway API resource will return true to
	// NeedFullSync(), which is the only way to Sync() start a reconciliation.
	links := c.tracker.QueryLinks(c.changed.Links, false)

	// Tracking Gateway only, as a way to identify changes on other resources
	// (e.g. Secret) impacting Gateway API ones. Changes made direcly on
	// Gateway API resources already flags fullsync as true, see `hdlr.full`
	// on watchers.go
	_, changed := links[convtypes.ResourceGateway]
	return changed
}

func (c *converter) SyncFull() error {
	if err := c.syncReferenceGrant(); err != nil {
		return err
	}
	if err := c.syncGatewayClass(); err != nil {
		return err
	}
	if err := c.syncGateway(); err != nil {
		return err
	}

	// we're not testing TLSRoute hostname declaration collision on HTTPRoute,
	// so a validation should be added in case the order changes and
	// syncTLSRoutes() comes first.
	c.syncHTTPRoutes()
	c.syncTLSRoutes()
	c.syncTCPRoutes()

	if err := c.syncGatewayClassStatus(); err != nil {
		return err
	}
	if err := c.syncGatewayStatus(); err != nil {
		return err
	}
	if err := c.syncRouteStatus(&gatewayv1.HTTPRoute{}); err != nil {
		return err
	}
	if err := c.syncRouteStatus(&gatewayv1alpha2.TCPRoute{}); err != nil {
		return err
	}
	if err := c.syncRouteStatus(&gatewayv1alpha2.TLSRoute{}); err != nil {
		return err
	}

	return nil
}

func (c *converter) syncGatewayClass() error {
	gatewayClasses, err := c.cache.GetGatewayClassMap()
	if err != nil {
		return fmt.Errorf("error reading gatewayClass list: %w", err)
	}
	c.events.classes = gatewayClasses
	return nil
}

func (c *converter) syncGateway() error {
	gateways, err := c.cache.GetGatewayList()
	if err != nil {
		return fmt.Errorf("error reading gateway list: %w", err)
	}
	sort.Slice(gateways, func(i, j int) bool {
		r1 := gateways[i]
		r2 := gateways[j]
		if r1.CreationTimestamp != r2.CreationTimestamp {
			return r1.CreationTimestamp.Time.Before(r2.CreationTimestamp.Time)
		}
		return r1.Namespace+"/"+r1.Name < r2.Namespace+"/"+r2.Name
	})
	for _, gateway := range gateways {
		gatewayClass, found := c.events.classes[gateway.Spec.GatewayClassName]
		if !found {
			// sanity check, cache should have already filtered this
			continue
		}
		gatewayEvent := c.registerGatewayEvent(gateway, gatewayClass.Spec.ControllerName)
		for i := range gateway.Spec.Listeners {
			listener := &gateway.Spec.Listeners[i]
			_ = c.acquireListenerEvent(gatewayEvent.source, listener)
			if listener.TLS != nil {
				_ = c.acquireCertificateRefs(gatewayEvent.source, listener)
			}
		}
	}
	return nil
}

func (c *converter) syncReferenceGrant() error {
	grants, err := c.cache.GetReferenceGrantList()
	if err != nil {
		return fmt.Errorf("error reading ReferenceGrant list: %w", err)
	}
	for _, refs := range grants {
		for _, from := range refs.Spec.From {
			for _, to := range refs.Spec.To {
				if from.Group == "core" {
					from.Group = ""
				}
				if to.Group == "core" {
					to.Group = ""
				}
				c.events.grant[from] = append(c.events.grant[from], referenceGrantTo{
					ReferenceGrantTo: to,
					Namespace:        gatewayv1.Namespace(refs.Namespace),
				})
			}
		}
	}
	return nil
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
		c.syncRoute(routeSource, route.Spec.Hostnames, route.Spec.ParentRefs, func(gatewaySource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, refEvent *routeParentRefEvent) {
			for index, rule := range route.Spec.Rules {
				// TODO implement httpRoute.Spec.Rules[].BackendRefs[].Filters[]
				backendRefs := make([]gatewayv1.BackendRef, len(rule.BackendRefs))
				for i := range rule.BackendRefs {
					backendRefs[i] = rule.BackendRefs[i].BackendRef
				}
				backendSuffix := fmt.Sprintf("_rule%d", index)
				backend, services := c.createBackend(routeSource, refEvent, backendSuffix, false, backendRefs)
				var haCORS *hatypes.Cors
				for _, filter := range rule.Filters {
					switch filter.Type {
					case gatewayv1.HTTPRouteFilterRequestRedirect:
						if backend == nil {
							backend = c.haproxy.Backends().AcquireBackend(route.Namespace, route.Name, backendSuffix)
						}
						c.syncHTTPRoutesFilterRequestRedirect(backend, filter.RequestRedirect)
					case gatewayv1.HTTPRouteFilterCORS:
						if backend != nil {
							haCORS = ptr.To(c.syncHTTPRoutesFilterCORS(filter.CORS))
						}
					case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
						if backend != nil {
							c.syncHTTPRoutesFilterHeaderModifier(filter.RequestHeaderModifier, &backend.RequestHeadersAdd, &backend.RequestHeadersSet, &backend.RequestHeadersDel)
						}
					case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
						if backend != nil {
							c.syncHTTPRoutesFilterHeaderModifier(filter.ResponseHeaderModifier, &backend.ResponseHeadersAdd, &backend.ResponseHeadersSet, &backend.ResponseHeadersDel)
						}
					default:
						refEvent.unsupportedValue = "Unsupported filter type: " + string(filter.Type)
					}
				}
				if backend != nil {
					paths, pathLinks := c.createHTTPHosts(gatewaySource, routeSource, listener, hostnames, rule.Matches, backend)
					if c.ann != nil {
						c.ann.ReadAnnotations(backend, services, pathLinks)
					}
					if haCORS != nil {
						for _, path := range paths {
							path.Cors = *haCORS
						}
					}
				}
			}
		})
	}
}

func (c *converter) syncHTTPRoutesFilterRequestRedirect(backend *hatypes.Backend, redirect *gatewayv1.HTTPRequestRedirectFilter) {
	backend.Redirect.Scheme = ptr.Deref(redirect.Scheme, "")
	backend.Redirect.Hostname = string(ptr.Deref(redirect.Hostname, ""))
	// backend.Redirect.Path = redirect.Path.ReplaceFullPath
	backend.Redirect.Port = int(ptr.Deref(redirect.Port, 0))
	backend.Redirect.Code = ptr.Deref(redirect.StatusCode, 302)
}

func (c *converter) syncHTTPRoutesFilterCORS(cors *gatewayv1.HTTPCORSFilter) (haCORS hatypes.Cors) {
	haCORS.Enabled = true
	haCORS.AllowOrigin = make([]string, len(cors.AllowOrigins))
	for i, origin := range cors.AllowOrigins {
		haCORS.AllowOrigin[i] = string(origin)
	}
	haCORS.AllowCredentials = ptr.Deref(cors.AllowCredentials, false)
	methods := make([]string, len(cors.AllowMethods))
	for i, method := range cors.AllowMethods {
		methods[i] = string(method)
	}
	haCORS.AllowMethods = strings.Join(methods, ",")
	headers := make([]string, len(cors.AllowHeaders))
	for i, header := range cors.AllowHeaders {
		headers[i] = string(header)
	}
	haCORS.AllowHeaders = strings.Join(headers, ",")
	expHeaders := make([]string, len(cors.ExposeHeaders))
	for i, header := range cors.ExposeHeaders {
		expHeaders[i] = string(header)
	}
	haCORS.ExposeHeaders = strings.Join(expHeaders, ",")
	haCORS.MaxAge = int(cors.MaxAge)
	if haCORS.MaxAge == 0 {
		haCORS.MaxAge = 5
	}
	return haCORS
}

func (c *converter) syncHTTPRoutesFilterHeaderModifier(headerModifier *gatewayv1.HTTPHeaderFilter, addList, setList *[]hatypes.HTTPHeader, delList *[]string) {
	for _, hdrAdd := range headerModifier.Add {
		*addList = append(*addList, hatypes.HTTPHeader{
			Name:  string(hdrAdd.Name),
			Value: hdrAdd.Value,
		})
	}
	for _, hdrSet := range headerModifier.Set {
		*setList = append(*setList, hatypes.HTTPHeader{
			Name:  string(hdrSet.Name),
			Value: hdrSet.Value,
		})
	}
	*delList = append(*delList, headerModifier.Remove...)
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
		c.syncRoute(routeSource, route.Spec.Hostnames, route.Spec.ParentRefs, func(gatewaySource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, refEvent *routeParentRefEvent) {
			for index, rule := range route.Spec.Rules {
				backend, services := c.createBackend(routeSource, refEvent, fmt.Sprintf("_tlsrule%d", index), true, rule.BackendRefs)
				if backend != nil {
					pathLinks := c.createTLSHosts(gatewaySource, routeSource, listener, hostnames, backend)
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
		c.syncRoute(routeSource, nil, route.Spec.ParentRefs, func(gatewaySource *source, listener *gatewayv1.Listener, _ []gatewayv1.Hostname, refEvent *routeParentRefEvent) {
			for index, rule := range route.Spec.Rules {
				backend, services := c.createBackend(routeSource, refEvent, fmt.Sprintf("_tcprule%d", index), true, rule.BackendRefs)
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

const (
	gatewayGroup  = gatewayv1.Group(gatewayv1.GroupName)
	gatewayKind   = gatewayv1.Kind("Gateway")
	httpRouteKind = gatewayv1.Kind("HTTPRoute")
	tlsRouteKind  = gatewayv1.Kind("TLSRoute")
	tcpRouteKind  = gatewayv1.Kind("TCPRoute")
)

func (c *converter) syncRoute(routeSource *source, routeHostnames []gatewayv1.Hostname, parentRefs []gatewayv1.ParentReference, syncRouteListener func(gatewaySource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, refEvent *routeParentRefEvent)) {
	for i := range parentRefs {
		parentRef := &parentRefs[i]
		parentGroup := gatewayGroup
		parentKind := gatewayKind
		if parentRef.Group != nil && *parentRef.Group != "" {
			parentGroup = *parentRef.Group
		}
		if parentRef.Kind != nil && *parentRef.Kind != "" {
			parentKind = *parentRef.Kind
		}
		if parentGroup != gatewayGroup || parentKind != gatewayKind {
			// Silently ignore, this is some other parent resource kind.
			// that cannot (or should not) be pointing to a HAProxy Ingress class.
			continue
		}
		gwref := types.NamespacedName{
			Namespace: routeSource.Namespace,
			Name:      string(parentRef.Name),
		}
		if parentRef.Namespace != nil && *parentRef.Namespace != "" {
			gwref.Namespace = string(*parentRef.Namespace)
		}
		gatewayEvent, found := c.events.gateway[gwref]
		if !found {
			// Gateway either does not exist, or it was filtered out in the cache
			// in the case it does not point to a HAProxy Ingress class.
			// So just silently ignore as well.
			continue
		}
		gateway := gatewayEvent.gateway
		gatewaySource := gatewayEvent.source
		routeEvent := c.acquireRouteEvent(routeSource)
		sectionName := ptr.Deref(parentRef.SectionName, "")
		portNumber := ptr.Deref(parentRef.Port, 0)
		if sectionName != "" || portNumber > 0 {
			// ensures that there is either a matching listener (refEvent.match=true) or otherwise a failing status
			_ = routeEvent.acquireParentRefEvent(gatewayEvent, sectionName, portNumber)
		}
		for i := range gateway.Spec.Listeners {
			listener := &gateway.Spec.Listeners[i]
			if sectionName != "" && sectionName != listener.Name {
				continue
			}
			if portNumber > 0 && portNumber != listener.Port {
				continue
			}
			refEvent := routeEvent.acquireParentRefEvent(gatewayEvent, listener.Name, portNumber)
			refEvent.match = true
			if err := c.checkListenerAllowed(gatewaySource, routeSource, listener); err != nil {
				refEvent.notAllowed = err.Error()
				refEvent.listener = string(listener.Name)
				continue
			}
			matchingHostname, hostnames := c.checkMatchingHostnames(listener, routeHostnames)
			if !matchingHostname {
				refEvent.nohostname = true
				continue
			}
			lstEvent := c.acquireListenerEvent(gatewaySource, listener)
			lstEvent.attachedRoutes += 1
			// TODO implement gateway.Spec.Addresses[]
			syncRouteListener(gatewaySource, listener, hostnames, refEvent)
		}
		routeEvent.shrinkNoHostnames(gatewayEvent)
	}
}

func (c *converter) checkMatchingHostnames(listener *gatewayv1.Listener, routeHostnames []gatewayv1.Hostname) (match bool, matchingHostnames []gatewayv1.Hostname) {
	if listener.Protocol == gatewayv1.TCPProtocolType {
		// TCP does not use hostname at all
		return true, nil
	}
	if listener.Hostname == nil || *listener.Hostname == "" || *listener.Hostname == "*" {
		// always allowed by the listener side, return the route configuration
		if len(routeHostnames) == 0 {
			// we create the frontend entries by iterating over the hostnames list, so need at least one item
			routeHostnames = []gatewayv1.Hostname{"*"}
		}
		return true, routeHostnames
	}
	if len(routeHostnames) == 0 {
		// route accepts any hostname, returns the listener configuration
		return true, []gatewayv1.Hostname{*listener.Hostname}
	}

	// both sides have configuration, lets merge them
	addIfMatch := func(matchRule, matchingPattern gatewayv1.Hostname) (matches bool) {
		matches = matchRule == matchingPattern || (strings.HasPrefix(string(matchRule), "*.") && strings.HasSuffix(string(matchingPattern), string(matchRule[1:])))
		if matches && !slices.Contains(matchingHostnames, matchingPattern) {
			matchingHostnames = append(matchingHostnames, matchingPattern)
		}
		return matches
	}
	for _, routeHostname := range routeHostnames {
		// check equality or the wildcard in the listener side ...
		_ = addIfMatch(*listener.Hostname, routeHostname) ||
			// ... and if does not match, check the wildcard in the route side
			addIfMatch(routeHostname, *listener.Hostname)
	}
	return len(matchingHostnames) > 0, matchingHostnames
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

func (c *converter) registerGatewayEvent(gateway *gatewayv1.Gateway, controller gatewayv1.GatewayController) *gatewayEvent {
	gatewaySource := newSource(gateway)
	gwEvent, found := c.events.gateway[gatewaySource.NamespacedName]
	if !found {
		gwEvent = &gatewayEvent{
			gateway:    gateway,
			source:     gatewaySource,
			controller: controller,
			listeners:  make(map[gatewayv1.SectionName]*listenerEvent),
		}
		c.events.gateway[gatewaySource.NamespacedName] = gwEvent
	}
	return gwEvent
}

func (c *converter) referenceIsPermitted(groupFrom gatewayv1.Group, kindFrom gatewayv1.Kind, namespaceFrom gatewayv1.Namespace, groupTo gatewayv1.Group, kindTo gatewayv1.Kind, namespaceTo gatewayv1.Namespace, nameTo gatewayv1.ObjectName) bool {
	if namespaceFrom == namespaceTo {
		return true
	}
	if groupFrom == "core" {
		groupFrom = ""
	}
	if groupTo == "core" {
		groupTo = ""
	}
	dest, found := c.events.grant[gatewayv1beta1.ReferenceGrantFrom{Group: groupFrom, Kind: kindFrom, Namespace: namespaceFrom}]
	if !found {
		return false
	}
	return slices.ContainsFunc(dest, func(to referenceGrantTo) bool {
		if to.Group == groupTo && to.Kind == kindTo && to.Namespace == namespaceTo {
			return to.Name == nil || *to.Name == "" || *to.Name == nameTo
		}
		return false
	})
}

func (c *converter) acquireRouteEvent(routeSource *source) *routeEvent {
	event, found := c.events.route[routeSource.NamespacedName]
	if !found {
		event = &routeEvent{
			route: routeSource,
		}
		c.events.route[routeSource.NamespacedName] = event
	}
	return event
}

func (c *converter) acquireListenerEvent(gatewaySource *source, listener *gatewayv1.Listener) *listenerEvent {
	gwEvent := c.events.gateway[gatewaySource.NamespacedName]
	lstEvent, found := gwEvent.listeners[listener.Name]
	if !found {
		lstEvent = &listenerEvent{}
		gwEvent.listeners[listener.Name] = lstEvent
		var tlsMode gatewayv1.TLSModeType
		if listener.TLS != nil && listener.TLS.Mode != nil {
			tlsMode = *listener.TLS.Mode
		}
		var protoSupportedKinds []gatewayv1.Kind
		switch listener.Protocol {
		case gatewayv1.HTTPProtocolType:
			switch tlsMode {
			case "": // Non TLS mode
				protoSupportedKinds = []gatewayv1.Kind{httpRouteKind}
			default:
				lstEvent.unsupportedProto = "HTTP proto does not support TLS mode"
			}
		case gatewayv1.HTTPSProtocolType:
			switch tlsMode {
			case gatewayv1.TLSModeTerminate:
				protoSupportedKinds = []gatewayv1.Kind{httpRouteKind}
			case gatewayv1.TLSModePassthrough:
				lstEvent.unsupportedProto = "Passthrough mode is only supported by TLSRoute"
			default: // Non TLS mode
				lstEvent.unsupportedProto = "HTTPS proto needs listener.tls configured"
			}
		case gatewayv1.TLSProtocolType:
			switch tlsMode {
			case gatewayv1.TLSModeTerminate:
				protoSupportedKinds = []gatewayv1.Kind{tcpRouteKind}
			case gatewayv1.TLSModePassthrough:
				protoSupportedKinds = []gatewayv1.Kind{tlsRouteKind}
			default: // Non TLS mode
				lstEvent.unsupportedProto = "TLS proto needs listener.tls configured"
			}
		case gatewayv1.TCPProtocolType:
			switch tlsMode {
			case gatewayv1.TLSModeTerminate:
				protoSupportedKinds = []gatewayv1.Kind{tcpRouteKind}
			case gatewayv1.TLSModePassthrough:
				lstEvent.unsupportedProto = "Passthrough mode is only supported by TLSRoute"
			default: // Non TLS mode
				protoSupportedKinds = []gatewayv1.Kind{tcpRouteKind}
			}
		default: // includes UDPProtocolType
			lstEvent.unsupportedProto = fmt.Sprintf("Protocol unsupported by HAProxy Ingress: %q", listener.Protocol)
		}
		if listener.AllowedRoutes != nil {
			for _, gk := range listener.AllowedRoutes.Kinds {
				egk := buildEventGroupKind(gk)
				if slices.Contains(protoSupportedKinds, gk.Kind) {
					lstEvent.supportedKinds = append(lstEvent.supportedKinds, egk)
				} else if !slices.Contains(lstEvent.unsupportedKinds, egk) {
					lstEvent.unsupportedKinds = append(lstEvent.unsupportedKinds, egk)
				}
			}
		}
		if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
			for _, kind := range protoSupportedKinds {
				lstEvent.supportedKinds = append(lstEvent.supportedKinds, routeGroupKind{kind: kind})
			}
		}
	}
	return lstEvent
}

func (c *converter) acquireCertificateRefs(gatewaySource *source, listener *gatewayv1.Listener) *certificateRefs {
	lstEvent := c.acquireListenerEvent(gatewaySource, listener)
	if lstEvent.certRefs != nil {
		return lstEvent.certRefs
	}
	lstEvent.certRefs = &certificateRefs{}
	certRefs := listener.TLS.CertificateRefs
	eventRefs := lstEvent.certRefs
	eventRefs.passthrough = listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1.TLSModePassthrough
	if len(certRefs) == 0 {
		return eventRefs
	}
	for i := range certRefs {
		certRef := &certRefs[i]
		namespace := gatewaySource.Namespace
		if certRef.Namespace != nil && *certRef.Namespace != "" {
			namespace = string(*certRef.Namespace)
		}
		if !c.referenceIsPermitted(gatewayGroup, gatewayKind, gatewayv1.Namespace(gatewaySource.Namespace), "", "Secret", gatewayv1.Namespace(namespace), certRef.Name) {
			certName := string(certRef.Name)
			if certRef.Namespace != nil {
				certName = fmt.Sprintf("%s/%s", *certRef.Namespace, certRef.Name)
			}
			eventRefs.certRefNoGrant = append(eventRefs.certRefNoGrant, certName)
			continue
		}
		if certRef.Group != nil && *certRef.Group != "" && *certRef.Group != "core" {
			eventRefs.certRefErrors = append(eventRefs.certRefErrors, fmt.Errorf("unsupported Group '%s', supported groups are 'core' and ''", *certRef.Group))
			continue
		}
		if certRef.Kind != nil && *certRef.Kind != "" && *certRef.Kind != "Secret" {
			eventRefs.certRefErrors = append(eventRefs.certRefErrors, fmt.Errorf("unsupported Kind '%s', the only supported kind is 'Secret'", *certRef.Kind))
			continue
		}
		crtFile, err := c.cache.GetTLSSecretPath(namespace, string(certRef.Name), []convtypes.TrackingRef{{Context: convtypes.ResourceGateway, UniqueName: "gw"}})
		if err != nil {
			eventRefs.certRefErrors = append(eventRefs.certRefErrors, err)
			continue
		}
		eventRefs.certFiles = append(eventRefs.certFiles, crtFile)
	}
	if listener.Protocol == gatewayv1.HTTPSProtocolType && !eventRefs.passthrough && len(eventRefs.certFiles) > 0 {
		// configures the listener hostname in the HTTPS frontend, so its certificate is
		// served during TLS handshake even if there is no published path and backend.
		f := c.haproxy.Frontends().AcquireFrontend(listener.Port, true)
		var hostname string
		if listener.Hostname != nil {
			hostname = string(*listener.Hostname)
		}
		if hostname == "" || hostname == "*" {
			hostname = hatypes.DefaultHost
		}
		h := f.AcquireHost(hostname)
		h.ExtendedWildcard = true
		h.DefaultBackend = c.haproxy.Backends().AcquireNotFoundBackend()
		configCertRef(&h.TLS.TLSConfig, eventRefs.certFiles[0])
	}
	return eventRefs
}

func (e *routeEvent) acquireParentRefEvent(gatewayEvent *gatewayEvent, section gatewayv1.SectionName, port gatewayv1.PortNumber) *routeParentRefEvent {
	parentRef := parentReference{
		namespace: gatewayv1.Namespace(gatewayEvent.gateway.Namespace),
		name:      gatewayv1.ObjectName(gatewayEvent.gateway.Name),
		section:   section,
		port:      port,
	}
	parentIdx := slices.IndexFunc(e.parent, func(e *routeParentRefEvent) bool {
		return e.ref == parentRef
	})
	if parentIdx < 0 {
		parentIdx = len(e.parent)
		e.parent = append(e.parent, &routeParentRefEvent{
			ref:     parentRef,
			gateway: gatewayEvent,
		})
	}
	return e.parent[parentIdx]
}

func (e *routeEvent) shrinkNoHostnames(gatewayEvent *gatewayEvent) {
	// The "no hostname matching" errors from parentRefs should be removed from the resulting status.
	// If all the failures are due to "no hostname matching", they should be simplified to a single
	// one, despite the number of parentRefs.
	e.parent = slices.DeleteFunc(e.parent, func(p *routeParentRefEvent) bool {
		return p.nohostname
	})
	if len(e.parent) == 0 {
		e.parent = nil
		refEvent := e.acquireParentRefEvent(gatewayEvent, "", 0)
		refEvent.nohostname = true
	}
}

func checkListenerAllowedKind(routeSource *source, kinds []gatewayv1.RouteGroupKind) error {
	if len(kinds) == 0 {
		return nil
	}
	for _, kind := range kinds {
		if (kind.Group == nil || *kind.Group == gatewayGroup) && kind.Kind == gatewayv1.Kind(routeSource.Kind) {
			return nil
		}
	}
	return fmt.Errorf("listener does not allow route of Kind '%s'", routeSource.Kind)
}

func (c *converter) checkListenerAllowedNamespace(gatewaySource, routeSource *source, namespaces *gatewayv1.RouteNamespaces) error {
	if namespaces == nil || namespaces.From == nil {
		return errRouteNotAllowed
	}
	if *namespaces.From == gatewayv1.NamespacesFromSame && routeSource.Namespace == gatewaySource.Namespace {
		return nil
	}
	if *namespaces.From == gatewayv1.NamespacesFromAll {
		return nil
	}
	if *namespaces.From == gatewayv1.NamespacesFromSelector {
		if namespaces.Selector == nil {
			return errRouteNotAllowed
		}
		selector, err := metav1.LabelSelectorAsSelector(namespaces.Selector)
		if err != nil {
			return err
		}
		ns, err := c.cache.GetNamespace(routeSource.Namespace)
		if err != nil {
			return err
		}
		if selector.Matches(labels.Set(ns.Labels)) {
			return nil
		}
	}
	return errRouteNotAllowed
}

func (c *converter) createBackend(routeSource *source, refEvent *routeParentRefEvent, index string, modeTCP bool, backendRefs []gatewayv1.BackendRef) (*hatypes.Backend, []*corev1.Service) {
	if habackend := c.haproxy.Backends().FindBackend(routeSource.Namespace, routeSource.Name, index); habackend != nil {
		habackend.ModeTCP = modeTCP
		return habackend, nil
	}
	type backend struct {
		service gatewayv1.ObjectName
		port    string
		epReady []*convutils.Endpoint
		cl      convutils.WeightCluster
	}
	http500 := func() *hatypes.Backend {
		return c.haproxy.Backends().AcquireStatusCodeBackend(http.StatusInternalServerError)
	}
	var backends []backend
	var svclist []*corev1.Service
	for _, back := range backendRefs {
		if back.Port == nil {
			refEvent.backendRef = "BackendRef is missing port number"
			return http500(), nil
		}
		namespace := routeSource.Namespace
		if back.Namespace != nil {
			namespace = string(*back.Namespace)
		}
		if !c.referenceIsPermitted(gatewayv1.Group(routeSource.Group), gatewayv1.Kind(routeSource.Kind), gatewayv1.Namespace(routeSource.Namespace), "", "Service", gatewayv1.Namespace(namespace), back.Name) {
			backName := string(back.Name)
			if back.Namespace != nil {
				backName = fmt.Sprintf("%s/%s", *back.Namespace, back.Name)
			}
			refEvent.backendRefNoGrant = append(refEvent.backendRefNoGrant, backName)
			return http500(), nil
		}
		var invalidKind []string
		if back.Group != nil && *back.Group != "" && *back.Group != "core" {
			invalidKind = append(invalidKind, "Invalid backendRef group: "+string(*back.Group))
		}
		if back.Kind != nil && *back.Kind != "Service" {
			invalidKind = append(invalidKind, "Invalid backendRef kind: "+string(*back.Kind))
		}
		if len(invalidKind) > 0 {
			refEvent.invalidKind = strings.Join(invalidKind, "; ")
			return http500(), nil
		}
		svcName := namespace + "/" + string(back.Name)
		c.tracker.TrackRefName([]convtypes.TrackingRef{
			{Context: convtypes.ResourceService, UniqueName: svcName},
			{Context: convtypes.ResourceEndpoints, UniqueName: svcName},
		}, convtypes.ResourceGateway, "gw")
		svc, err := c.cache.GetService("", svcName)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", back.Name, routeSource, err)
			refEvent.backendRef = err.Error()
			return http500(), nil
		}
		svclist = append(svclist, svc)
		portStr := strconv.Itoa(int(*back.Port))
		svcport := convutils.FindServicePort(svc, portStr)
		if svcport == nil {
			c.logger.Warn("skipping service '%s' on %s: port '%s' not found", back.Name, routeSource, portStr)
			refEvent.backendRef = fmt.Sprintf("Port %s not found", portStr)
			return http500(), nil
		}
		epReady, _, err := convutils.CreateEndpoints(c.cache, svc, svcport)
		if err != nil {
			c.logger.Warn("skipping service '%s' on %s: %v", back.Name, routeSource, err)
			refEvent.backendRef = err.Error()
			return http500(), nil
		}
		backends = append(backends, backend{
			service: back.Name,
			port:    svcport.TargetPort.String(),
			epReady: epReady,
			cl: convutils.WeightCluster{
				Weight: int(ptr.Deref(back.Weight, 1)),
				Length: len(epReady),
			},
		})
	}
	if len(backends) == 0 && len(backendRefs) == 0 {
		return nil, nil
	}
	habackend := c.haproxy.Backends().AcquireBackend(routeSource.Namespace, routeSource.Name, index)
	habackend.ModeTCP = modeTCP
	if len(backends) == 0 {
		return http500(), nil
	}
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

func (c *converter) createHTTPHosts(gatewaySource, routeSource *source, listener *gatewayv1.Listener, hostnames []gatewayv1.Hostname, matches []gatewayv1.HTTPRouteMatch, backend *hatypes.Backend) (paths []*hatypes.Path, pathLinks []*hatypes.PathLink) {
	if len(matches) == 0 {
		matches = []gatewayv1.HTTPRouteMatch{{}}
	}
	var certRefs *certificateRefs
	var hostsTLS map[string]*hatypes.TLSConfig
	if listener.TLS != nil {
		if certRefs = c.acquireCertificateRefs(gatewaySource, listener); len(certRefs.certFiles) == 0 {
			return nil, nil
		}
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
			h.ExtendedWildcard = true
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
			path := h.AddLink(backend, pathlink)
			paths = append(paths, path)
			pathLinks = append(pathLinks, pathlink)
			if hostsTLS != nil {
				hostsTLS[h.Hostname] = &h.TLS.TLSConfig
			}
		}
	}
	if listener.TLS != nil {
		c.readCertRefs(certRefs, hostsTLS)
	}
	return paths, pathLinks
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
			h.ExtendedWildcard = true
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
	var certRefs *certificateRefs
	var hostsTLS map[string]*hatypes.TLSConfig
	if listener.TLS != nil {
		if certRefs = c.acquireCertificateRefs(gatewaySource, listener); len(certRefs.certFiles) == 0 {
			return nil
		}
		hostsTLS = make(map[string]*hatypes.TLSConfig)
	}
	if len(hostnames) == 0 || listener.TLS == nil {
		// defaults to wildcard (len==0); overwrite hostnames if non TLS (TLS==nil)
		hostnames = []gatewayv1.Hostname{"*"}
	}
	tcpport := c.haproxy.TCPServices().AcquireTCPPort(int(listener.Port))
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
	if listener.TLS != nil {
		c.readCertRefs(certRefs, hostsTLS)
	}
	return pathlinks
}

// readCertRefs updates all the TLSConfig references on the hostsTLS hashmap with certificates provided via
// listener.TLS.CertificateRefs. No further action is needed, provided that the hashmap is populated with the
// reference to the real TLSConfig.
//
// Special handling of the added hosts or services should be done in the case of not succeeding: the caller
// should revert all the changes; otherwise, haproxy would lead to an incomplete/invalid configuration due
// to the missing of some TLS certificates.
func (c *converter) readCertRefs(certRefs *certificateRefs, hostsTLS map[string]*hatypes.TLSConfig) {
	for i := range certRefs.certFiles {
		crtFile := certRefs.certFiles[i]
		for hostname, hostTLS := range hostsTLS {
			if crtFile.Certificate.VerifyHostname(hostname) == nil {
				if hostTLS.TLSHash != "" && hostTLS.TLSHash != crtFile.SHA1Hash {
					certRefs.conflictingHostnames = append(certRefs.conflictingHostnames, hostname)
					continue
				}
				configCertRef(hostTLS, crtFile)
			}
		}
	}
	defaultCrtFile := certRefs.certFiles[0]
	for _, hostTLS := range hostsTLS {
		if hostTLS.TLSHash == "" {
			configCertRef(hostTLS, defaultCrtFile)
		}
	}
}

func configCertRef(hostTLS *hatypes.TLSConfig, crtFile convtypes.CrtFile) {
	hostTLS.TLSCommonName = crtFile.Certificate.Subject.CommonName
	hostTLS.TLSFilename = crtFile.Filename
	hostTLS.TLSHash = crtFile.SHA1Hash
}

func (c *converter) syncGatewayClassStatus() error {
	for name := range c.events.classes {
		gwcls := &gatewayv1.GatewayClass{}
		gwcls.Name = string(name)
		err := c.cache.UpdateStatus(gwcls, func() bool {
			return meta.SetStatusCondition(&gwcls.Status.Conditions, metav1.Condition{
				Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
				Status:             metav1.ConditionTrue,
				Reason:             string(gatewayv1.GatewayClassReasonAccepted),
				Message:            "Class accepted by HAProxy Ingress",
				ObservedGeneration: gwcls.Generation,
			})
		})
		if err != nil {
			return fmt.Errorf("error updating GatewayClass status: %w", err)
		}
	}
	return nil
}

func (c *converter) syncGatewayStatus() error {
	for gwref, gwEvent := range c.events.gateway {
		gw := &gatewayv1.Gateway{}
		gw.Namespace = gwref.Namespace
		gw.Name = gwref.Name
		gwGeneration := gwEvent.source.generation
		err := c.cache.UpdateStatus(gw, func() bool {
			var changed bool
			changed = meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
				Type:               string(gatewayv1.GatewayConditionAccepted),
				Status:             metav1.ConditionTrue,
				Reason:             string(gatewayv1.GatewayReasonAccepted),
				Message:            "Gateway accepted by HAProxy Ingress",
				ObservedGeneration: gwGeneration,
			}) || changed
			changed = meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
				Type:               string(gatewayv1.GatewayConditionProgrammed),
				Status:             metav1.ConditionTrue,
				Reason:             string(gatewayv1.GatewayReasonProgrammed),
				ObservedGeneration: gwGeneration,
			}) || changed
			gw.Status.Listeners = slices.DeleteFunc(gw.Status.Listeners, func(listenerStatus gatewayv1.ListenerStatus) bool {
				found := slices.ContainsFunc(gw.Spec.Listeners, func(listener gatewayv1.Listener) bool {
					return listenerStatus.Name == listener.Name
				})
				if !found {
					changed = true
				}
				return !found
			})
			for i := range gw.Spec.Listeners {
				listener := &gw.Spec.Listeners[i]
				listenerStatus := acquireListenerStatus(gw, listener.Name)
				listenerEvent := c.acquireListenerEvent(gwEvent.source, listener)

				// condition ListenerConditionResolvedRefs
				conditionResolvedRefs := metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					ObservedGeneration: gwGeneration,
				}
				if listenerEvent.unsupportedProto != "" {
					message := listenerEvent.unsupportedProto
					conditionResolvedRefs.Status = metav1.ConditionFalse
					conditionResolvedRefs.Reason = string(gatewayv1.ListenerReasonInvalidRouteKinds)
					conditionResolvedRefs.Message = message
					c.logger.Warn("%s on %s listener '%s'", message, gwEvent.source.String(), listener.Name)
				} else if len(listenerEvent.supportedKinds) == 0 {
					kinds := make([]string, len(listenerEvent.unsupportedKinds))
					for i, k := range listenerEvent.unsupportedKinds {
						kinds[i] = k.String()
					}
					message := "None of the configured route kinds are supported"
					conditionResolvedRefs.Status = metav1.ConditionFalse
					conditionResolvedRefs.Reason = string(gatewayv1.ListenerReasonInvalidRouteKinds)
					conditionResolvedRefs.Message = message
					c.logger.Warn("%s on %s listener '%s': %s", message, gwEvent.source.String(), listener.Name, strings.Join(kinds, ", "))
				} else if len(listenerEvent.unsupportedKinds) > 0 {
					kinds := make([]string, len(listenerEvent.unsupportedKinds))
					for i, k := range listenerEvent.unsupportedKinds {
						kinds[i] = k.String()
					}
					message := fmt.Sprintf("Route kinds (%s) not supported", strings.Join(kinds, ", "))
					conditionResolvedRefs.Status = metav1.ConditionFalse
					conditionResolvedRefs.Reason = string(gatewayv1.ListenerReasonInvalidRouteKinds)
					conditionResolvedRefs.Message = message
					c.logger.Warn("%s on %s listener '%s'", message, gwEvent.source.String(), listener.Name)
				} else if certRefs := listenerEvent.certRefs; certRefs != nil {
					if len(certRefs.certRefErrors) > 0 {
						errorList := errors.Join(certRefs.certRefErrors...).Error()
						conditionResolvedRefs.Status = metav1.ConditionFalse
						conditionResolvedRefs.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
						conditionResolvedRefs.Message = errorList
						c.logger.Warn("skipping certificate reference on %s listener '%s': %s", gwEvent.source.String(), listener.Name, errorList)
					} else if len(certRefs.certRefNoGrant) > 0 {
						refs := strings.Join(certRefs.certRefNoGrant, ", ")
						conditionResolvedRefs.Status = metav1.ConditionFalse
						conditionResolvedRefs.Reason = string(gatewayv1.ListenerReasonRefNotPermitted)
						conditionResolvedRefs.Message = "Certificate reference not permitted from: " + refs
						c.logger.Warn("skipping certificate reference on %s listener '%s': certificate reference not permitted from %s", gwEvent.source.String(), listener.Name, refs)
					} else if len(certRefs.certFiles) == 0 && !certRefs.passthrough {
						conditionResolvedRefs.Status = metav1.ConditionFalse
						conditionResolvedRefs.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
						conditionResolvedRefs.Message = "Listener has no valid certificate reference"
						c.logger.Warn("skipping certificate reference on %s listener '%s': listener has no certificate reference", gwEvent.source.String(), listener.Name)
					}
				}
				changed = meta.SetStatusCondition(&listenerStatus.Conditions, conditionResolvedRefs) || changed

				// condition ListenerConditionProgrammed
				conditionProgrammed := metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonProgrammed),
					ObservedGeneration: gwGeneration,
				}
				if conditionResolvedRefs.Status != metav1.ConditionTrue {
					conditionProgrammed.Status = metav1.ConditionFalse
					conditionProgrammed.Reason = string(gatewayv1.ListenerReasonPending)
					conditionProgrammed.Message = string(gatewayv1.ListenerConditionResolvedRefs) + " condition has a failure status"
				}
				changed = meta.SetStatusCondition(&listenerStatus.Conditions, conditionProgrammed) || changed

				if conditionResolvedRefs.Status == metav1.ConditionTrue {
					// condition ListenerConditionAccepted
					conditionAccepted := metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionAccepted),
						Status:             metav1.ConditionTrue,
						Reason:             string(gatewayv1.ListenerReasonAccepted),
						ObservedGeneration: gwGeneration,
					}
					changed = meta.SetStatusCondition(&listenerStatus.Conditions, conditionAccepted) || changed

					// condition ListenerConditionConflicted
					conditionConflicted := metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionConflicted),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonNoConflicts),
						ObservedGeneration: gwGeneration,
					}
					changed = meta.SetStatusCondition(&listenerStatus.Conditions, conditionConflicted) || changed
				} else {
					changed = meta.RemoveStatusCondition(&listenerStatus.Conditions, string(gatewayv1.ListenerConditionAccepted)) || changed
					changed = meta.RemoveStatusCondition(&listenerStatus.Conditions, string(gatewayv1.ListenerConditionConflicted)) || changed
				}

				// condition ListenerConditionOverlappingTLSConfig
				if listenerEvent.certRefs != nil && len(listenerEvent.certRefs.conflictingHostnames) > 0 {
					hostnames := strings.Join(listenerEvent.certRefs.conflictingHostnames, "; ")
					changed = meta.SetStatusCondition(&listenerStatus.Conditions, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionOverlappingTLSConfig),
						Status:             metav1.ConditionTrue,
						Reason:             string(gatewayv1.ListenerReasonOverlappingHostnames),
						Message:            "Overlapping hostname(s): " + hostnames,
						ObservedGeneration: gwGeneration,
					}) || changed
					c.logger.Warn("skipping certificate reference on %s listener '%s' for hostname(s) '%s': a TLS certificate was already assigned", gwEvent.source.String(), listener.Name, hostnames)
				} else {
					changed = meta.RemoveStatusCondition(
						&listenerStatus.Conditions,
						string(gatewayv1.ListenerConditionOverlappingTLSConfig),
					) || changed
				}

				// other status updates
				if listenerStatus.AttachedRoutes != listenerEvent.attachedRoutes {
					listenerStatus.AttachedRoutes = listenerEvent.attachedRoutes
					changed = true
				}
				listenerStatus.SupportedKinds = buildStatusGroupKinds(listenerEvent.supportedKinds)
			}
			return changed
		})
		if err != nil {
			return fmt.Errorf("error updating Gateway status: %w", err)
		}
	}
	return nil
}

func acquireListenerStatus(gw *gatewayv1.Gateway, listenerName gatewayv1.SectionName) *gatewayv1.ListenerStatus {
	find := func() *gatewayv1.ListenerStatus {
		i, found := slices.BinarySearchFunc(gw.Status.Listeners, listenerName, func(status gatewayv1.ListenerStatus, name gatewayv1.SectionName) int {
			return cmp.Compare(status.Name, name)
		})
		if found {
			return &gw.Status.Listeners[i]
		}
		return nil
	}
	if listener := find(); listener != nil {
		return listener
	}
	gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
		Name: listenerName,
	})
	slices.SortFunc(gw.Status.Listeners, func(a, b gatewayv1.ListenerStatus) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return find()
}

func (c *converter) syncRouteStatus(route client.Object) error {
	for routeRef, routeEvent := range c.events.route {
		route.SetNamespace(routeRef.Namespace)
		route.SetName(routeRef.Name)
		routeGeneration := routeEvent.route.generation
		err := c.cache.UpdateStatus(route, func() bool {
			// Choosing the beauty of type safety instead of this one-liner:
			// routeStatus := reflect.ValueOf(route).Elem().FieldByName("Status").FieldByName("RouteStatus").Addr().Interface().(*gatewayv1.RouteStatus)
			var routeStatus *gatewayv1.RouteStatus
			switch r := route.(type) {
			case *gatewayv1.HTTPRoute:
				routeStatus = &r.Status.RouteStatus
			case *gatewayv1alpha2.TLSRoute:
				routeStatus = &r.Status.RouteStatus
			case *gatewayv1alpha2.TCPRoute:
				routeStatus = &r.Status.RouteStatus
			default:
				panic(fmt.Errorf("unsupported route type: %T", route))
			}
			var changed bool
			routeStatus.Parents = slices.DeleteFunc(routeStatus.Parents, func(statusParent gatewayv1.RouteParentStatus) bool {
				found := slices.ContainsFunc(routeEvent.parent, func(eventParent *routeParentRefEvent) bool {
					return eventParent.ref == buildEventParentRef(statusParent.ParentRef)
				})
				if !found {
					// a route.status.parents[] not found during route processing,
					// probably removed from spec, lets remove from the status as well.
					changed = true
					return true
				}
				return false
			})
			for _, eventParent := range routeEvent.parent {
				i := slices.IndexFunc(routeStatus.Parents, func(statusParent gatewayv1.RouteParentStatus) bool {
					return eventParent.ref == buildEventParentRef(statusParent.ParentRef)
				})
				if i < 0 {
					i = len(routeStatus.Parents)
					routeStatus.Parents = append(routeStatus.Parents, gatewayv1.RouteParentStatus{ParentRef: buildStatusParentRef(eventParent.ref)})
				}
				statusParent := &routeStatus.Parents[i]
				statusParent.ControllerName = eventParent.gateway.controller

				// condition RouteConditionResolvedRefs
				conditionResolvedRefs := metav1.Condition{
					Type:               string(gatewayv1.RouteConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.RouteReasonResolvedRefs),
					ObservedGeneration: routeGeneration,
				}
				if eventParent.backendRef != "" {
					conditionResolvedRefs.Status = metav1.ConditionFalse
					conditionResolvedRefs.Reason = string(gatewayv1.RouteReasonBackendNotFound)
					conditionResolvedRefs.Message = eventParent.backendRef
				} else if len(eventParent.backendRefNoGrant) > 0 {
					nogrants := strings.Join(eventParent.backendRefNoGrant, ", ")
					conditionResolvedRefs.Status = metav1.ConditionFalse
					conditionResolvedRefs.Reason = string(gatewayv1.RouteReasonRefNotPermitted)
					conditionResolvedRefs.Message = "Route has not permitted backendRefs: " + nogrants
				} else if eventParent.invalidKind != "" {
					conditionResolvedRefs.Status = metav1.ConditionFalse
					conditionResolvedRefs.Reason = string(gatewayv1.RouteReasonInvalidKind)
					conditionResolvedRefs.Message = eventParent.invalidKind
				}
				changed = meta.SetStatusCondition(&statusParent.Conditions, conditionResolvedRefs) || changed

				// condition RouteConditionAccepted
				conditionAccepted := metav1.Condition{
					Type:               string(gatewayv1.RouteConditionAccepted),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.RouteReasonAccepted),
					ObservedGeneration: routeGeneration,
				}
				if eventParent.nohostname {
					conditionAccepted.Status = metav1.ConditionFalse
					conditionAccepted.Reason = string(gatewayv1.RouteReasonNoMatchingListenerHostname)
					conditionAccepted.Message = "No matching listener hostname"
				} else if eventParent.notAllowed != "" {
					conditionAccepted.Status = metav1.ConditionFalse
					conditionAccepted.Reason = string(gatewayv1.RouteReasonNotAllowedByListeners)
					conditionAccepted.Message = eventParent.notAllowed
					c.logger.Warn("skipping attachment of %s to %s listener '%s': %s", routeEvent.route.String(), eventParent.gateway.source.String(), eventParent.listener, eventParent.notAllowed)
				} else if !eventParent.match {
					conditionAccepted.Status = metav1.ConditionFalse
					conditionAccepted.Reason = string(gatewayv1.RouteReasonNoMatchingParent)
					conditionAccepted.Message = "No matching parent"
				} else if eventParent.unsupportedValue != "" {
					conditionAccepted.Status = metav1.ConditionFalse
					conditionAccepted.Reason = string(gatewayv1.RouteReasonUnsupportedValue)
					conditionAccepted.Message = eventParent.unsupportedValue
				}
				changed = meta.SetStatusCondition(&statusParent.Conditions, conditionAccepted) || changed

				// condition RouteConditionPartiallyInvalid
				changed = meta.RemoveStatusCondition(&statusParent.Conditions, string(gatewayv1.RouteConditionPartiallyInvalid)) || changed
			}
			return changed
		})
		if err != nil {
			return fmt.Errorf("error updating %T status: %w", route, err)
		}
	}
	return nil
}
