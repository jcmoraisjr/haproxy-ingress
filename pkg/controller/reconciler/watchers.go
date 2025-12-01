/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package reconciler

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"

	"github.com/go-logr/logr"
	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/services"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

func createWatchers(ctx context.Context, cfg *config.Config, val services.IsValidResource) *watchers {
	w := &watchers{
		log: logr.FromContextOrDiscard(ctx).WithName("watchers"),
		cfg: cfg,
		val: val,
	}
	w.initCh()
	return w
}

type watchers struct {
	mu  sync.Mutex
	ch  *types.ChangedObjects
	log logr.Logger
	cfg *config.Config
	val services.IsValidResource
	run bool
}

func (w *watchers) getHandlers() []*hdlr {
	handlers := w.handlersCore()
	handlers = append(handlers, w.handlersIngress()...)
	if w.cfg.HasGatewayB1 {
		handlers = append(handlers, w.handlersGatewayv1beta1()...)
	}
	if w.cfg.HasGatewayV1 {
		handlers = append(handlers, w.handlersGatewayv1()...)
	}
	if w.cfg.HasTCPRouteA2 {
		handlers = append(handlers, w.handlersTCPRoutev1alpha2()...)
	}
	if w.cfg.HasTLSRouteA2 {
		handlers = append(handlers, w.handlersTLSRoutev1alpha2()...)
	}
	for _, h := range handlers {
		h.w = w
	}
	return handlers
}

func (w *watchers) getChangedObjects() *types.ChangedObjects {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch := *w.ch
	w.initCh()
	w.run = true
	return &ch
}

func (w *watchers) initCh() {
	newch := new(types.ChangedObjects)
	if w.ch != nil {
		if w.ch.GlobalConfigMapDataNew != nil {
			newch.GlobalConfigMapDataCur = w.ch.GlobalConfigMapDataNew
		} else {
			newch.GlobalConfigMapDataCur = w.ch.GlobalConfigMapDataCur
		}
		if w.ch.TCPConfigMapDataNew != nil {
			newch.TCPConfigMapDataCur = w.ch.TCPConfigMapDataNew
		} else {
			newch.TCPConfigMapDataCur = w.ch.TCPConfigMapDataCur
		}
	}
	w.ch = newch
	w.ch.Links = types.TrackingLinks{}
}

func (w *watchers) running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.run
}

func (w *watchers) handlersCore() []*hdlr {
	cmChange := func(o client.Object) {
		cm := o.(*api.ConfigMap)
		key := cm.Namespace + "/" + cm.Name
		switch key {
		case w.cfg.ConfigMapName:
			w.ch.GlobalConfigMapDataNew = cm.Data
		case w.cfg.TCPConfigMapName:
			w.ch.TCPConfigMapDataNew = cm.Data
		}
	}
	return []*hdlr{
		{
			typ: &api.ConfigMap{},
			res: types.ResourceConfigMap,
			add: cmChange,
			upd: func(old, new client.Object) {
				cmChange(new)
			},
			pr: []predicate.Predicate{
				predicate.NewPredicateFuncs(func(o client.Object) bool {
					cm := o.(*api.ConfigMap)
					key := cm.Namespace + "/" + cm.Name
					return key == w.cfg.ConfigMapName || key == w.cfg.TCPConfigMapName
				}),
			},
		},
		{
			typ: &api.Service{},
			res: types.ResourceService,
			pr: []predicate.Predicate{
				predicate.Or(
					predicate.AnnotationChangedPredicate{},
					predicate.GenerationChangedPredicate{},
					predicate.NewPredicateFuncs(func(object client.Object) bool {
						if w.cfg.PublishService == "" {
							return false
						}
						svc := object.(*api.Service)
						return svc.Namespace+"/"+svc.Name == w.cfg.PublishService
					}),
				),
			},
		},
		{
			typ: &discoveryv1.EndpointSlice{},
			res: types.ResourceEndpoints,
			pr: []predicate.Predicate{
				predicate.Funcs{
					UpdateFunc: func(ue event.UpdateEvent) bool {
						old := ue.ObjectOld.(*discoveryv1.EndpointSlice)
						new := ue.ObjectNew.(*discoveryv1.EndpointSlice)
						return !reflect.DeepEqual(old.Endpoints, new.Endpoints)
					},
				},
			},
			trkn: func(obj client.Object) string {
				if labels := obj.GetLabels(); labels != nil {
					if name := labels["kubernetes.io/service-name"]; name != "" {
						return name
					}
				}
				return obj.GetName()
			},
		},
		{
			typ: &api.Secret{},
			res: types.ResourceSecret,
		},
		{
			typ: &api.Pod{},
			res: types.ResourcePod,
			pr: []predicate.Predicate{
				predicate.Funcs{
					CreateFunc: func(e event.CreateEvent) bool {
						// peers
						return e.Object.GetNamespace() == w.cfg.ControllerPod.Namespace
					},
					UpdateFunc: func(e event.UpdateEvent) bool {
						if e.ObjectNew.GetNamespace() == w.cfg.ControllerPod.Namespace {
							// peers
							objOld := e.ObjectOld.(*api.Pod)
							objNew := e.ObjectNew.(*api.Pod)
							return objOld.Status.PodIP != objNew.Status.PodIP
						}
						return e.ObjectOld.GetDeletionTimestamp() != e.ObjectNew.GetDeletionTimestamp()
					},
				},
			},
		},
	}
}

func (w *watchers) handlersIngress() []*hdlr {
	h := []*hdlr{
		{
			typ: &networking.Ingress{},
			res: types.ResourceIngress,
			add: func(o client.Object) {
				w.ch.IngressesAdd = append(w.ch.IngressesAdd, o.(*networking.Ingress))
			},
			upd: func(old, new client.Object) {
				oldIng := old.(*networking.Ingress)
				newIng := new.(*networking.Ingress)
				oldValid := w.val.IsValidIngress(oldIng)
				newValid := w.val.IsValidIngress(newIng)
				if oldValid && newValid {
					w.ch.IngressesUpd = append(w.ch.IngressesUpd, newIng)
				} else if !oldValid && newValid {
					w.ch.IngressesAdd = append(w.ch.IngressesAdd, newIng)
				} else if oldValid && !newValid {
					w.ch.IngressesDel = append(w.ch.IngressesDel, oldIng)
				}
			},
			del: func(o client.Object) {
				w.ch.IngressesDel = append(w.ch.IngressesDel, o.(*networking.Ingress))
			},
			pr: []predicate.Predicate{
				predicate.Or(
					predicate.AnnotationChangedPredicate{},
					predicate.GenerationChangedPredicate{},
				),
				predicate.Funcs{
					CreateFunc: func(ce event.CreateEvent) bool {
						return w.val.IsValidIngress(ce.Object.(*networking.Ingress))
					},
					DeleteFunc: func(de event.DeleteEvent) bool {
						return w.val.IsValidIngress(de.Object.(*networking.Ingress))
					},
					UpdateFunc: func(ue event.UpdateEvent) bool {
						return w.val.IsValidIngress(ue.ObjectOld.(*networking.Ingress)) ||
							w.val.IsValidIngress(ue.ObjectNew.(*networking.Ingress))
					},
				},
			},
		},
	}
	if !w.cfg.DisableIngressClassAPI {
		h = append(h, &hdlr{
			typ: &networking.IngressClass{},
			res: types.ResourceIngressClass,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
				predicate.Funcs{
					CreateFunc: func(ce event.CreateEvent) bool {
						return w.val.IsValidIngressClass(ce.Object.(*networking.IngressClass))
					},
					DeleteFunc: func(de event.DeleteEvent) bool {
						return w.val.IsValidIngressClass(de.Object.(*networking.IngressClass))
					},
					UpdateFunc: func(ue event.UpdateEvent) bool {
						return w.val.IsValidIngressClass(ue.ObjectOld.(*networking.IngressClass)) ||
							w.val.IsValidIngressClass(ue.ObjectNew.(*networking.IngressClass))
					},
				},
			},
		})
	}
	return h
}

func (w *watchers) handlersGatewayv1beta1() []*hdlr {
	return []*hdlr{
		{
			typ:  &gatewayv1beta1.Gateway{},
			res:  types.ResourceGateway,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
		{
			typ:  &gatewayv1beta1.GatewayClass{},
			res:  types.ResourceGatewayClass,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
				predicate.Funcs{
					CreateFunc: func(ce event.CreateEvent) bool {
						return w.val.IsValidGatewayClassB1(ce.Object.(*gatewayv1beta1.GatewayClass))
					},
					DeleteFunc: func(de event.DeleteEvent) bool {
						return w.val.IsValidGatewayClassB1(de.Object.(*gatewayv1beta1.GatewayClass))
					},
					UpdateFunc: func(ue event.UpdateEvent) bool {
						return w.val.IsValidGatewayClassB1(ue.ObjectOld.(*gatewayv1beta1.GatewayClass)) ||
							w.val.IsValidGatewayClassB1(ue.ObjectNew.(*gatewayv1beta1.GatewayClass))
					},
				},
			},
		},
		{
			typ:  &gatewayv1beta1.HTTPRoute{},
			res:  types.ResourceHTTPRoute,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
	}
}

func (w *watchers) handlersGatewayv1() []*hdlr {
	return []*hdlr{
		{
			typ:  &gatewayv1.Gateway{},
			res:  types.ResourceGateway,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
		{
			typ:  &gatewayv1.GatewayClass{},
			res:  types.ResourceGatewayClass,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
				predicate.Funcs{
					CreateFunc: func(ce event.CreateEvent) bool {
						return w.val.IsValidGatewayClass(ce.Object.(*gatewayv1.GatewayClass))
					},
					DeleteFunc: func(de event.DeleteEvent) bool {
						return w.val.IsValidGatewayClass(de.Object.(*gatewayv1.GatewayClass))
					},
					UpdateFunc: func(ue event.UpdateEvent) bool {
						return w.val.IsValidGatewayClass(ue.ObjectOld.(*gatewayv1.GatewayClass)) ||
							w.val.IsValidGatewayClass(ue.ObjectNew.(*gatewayv1.GatewayClass))
					},
				},
			},
		},
		{
			typ:  &gatewayv1.HTTPRoute{},
			res:  types.ResourceHTTPRoute,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
	}
}

func (w *watchers) handlersTCPRoutev1alpha2() []*hdlr {
	return []*hdlr{
		{
			typ:  &gatewayv1alpha2.TCPRoute{},
			res:  types.ResourceTCPRoute,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
	}
}

func (w *watchers) handlersTLSRoutev1alpha2() []*hdlr {
	return []*hdlr{
		{
			typ:  &gatewayv1alpha2.TLSRoute{},
			res:  types.ResourceTLSRoute,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
	}
}

type hdlr struct {
	w   *watchers
	typ client.Object
	res types.ResourceType
	pr  []predicate.Predicate
	add,
	del func(o client.Object)
	upd  func(old, new client.Object)
	trkn func(obj client.Object) string
	full bool
}

func (h *hdlr) getSource(c cache.Cache) source.TypedSource[rparam] {
	return source.TypedKind(c, h.typ, h, h.pr...)
}

func (h *hdlr) Create(ctx context.Context, e event.TypedCreateEvent[client.Object], q workqueue.TypedRateLimitingInterface[rparam]) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if h.add != nil {
		h.add(e.Object)
	}
	h.compose("add", e.Object)
	h.notify("create", e.Object, q)
}

func (h *hdlr) Update(ctx context.Context, e event.TypedUpdateEvent[client.Object], q workqueue.TypedRateLimitingInterface[rparam]) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if h.upd != nil {
		h.upd(e.ObjectOld, e.ObjectNew)
	}
	h.compose("update", e.ObjectNew)
	h.notify("update", e.ObjectNew, q)
}

func (h *hdlr) Delete(ctx context.Context, e event.TypedDeleteEvent[client.Object], q workqueue.TypedRateLimitingInterface[rparam]) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if h.del != nil {
		h.del(e.Object)
	}
	h.compose("del", e.Object)
	h.notify("delete", e.Object, q)
}

func (h *hdlr) Generic(ctx context.Context, e event.TypedGenericEvent[client.Object], q workqueue.TypedRateLimitingInterface[rparam]) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	h.w.ch.NeedFullSync = true
	h.notify("generic", e.Object, q)
}

func (h *hdlr) compose(ev string, obj client.Object) {
	resourcename := obj.GetName()
	trackingname := resourcename
	if h.trkn != nil {
		trackingname = h.trkn(obj)
	}
	if ns := obj.GetNamespace(); ns != "" {
		resourcename = ns + "/" + resourcename
		trackingname = ns + "/" + trackingname
	}
	ch := h.w.ch
	tracker.TrackChanges(ch.Links, h.res, trackingname)
	if objname := fmt.Sprintf("%s/%s:%s", ev, h.res, resourcename); !slices.Contains(ch.Objects, objname) {
		ch.Objects = append(ch.Objects, objname)
	}
}

func (h *hdlr) notify(event string, o client.Object, q workqueue.TypedRateLimitingInterface[rparam]) {
	if h.full {
		h.w.ch.NeedFullSync = true
	}
	q.AddRateLimited(rparam{fullsync: h.full})
	if h.w.run {
		h.w.log.Info("notify", "event", event, "kind", reflect.TypeOf(o), "namespace", o.GetNamespace(), "name", o.GetName())
	}
}
