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
	"sync"

	"github.com/go-logr/logr"
	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/services"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

func createWatchers(ctx context.Context, cfg *config.Config, val services.IsValidResource) *watchers {
	w := &watchers{
		mu:  sync.Mutex{},
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
	if w.cfg.HasGatewayA2 {
		handlers = append(handlers, w.handlersGatewayv1alpha2()...)
	}
	if w.cfg.HasGatewayB1 {
		handlers = append(handlers, w.handlersGatewayv1beta1()...)
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
				),
			},
		},
		{
			typ: &api.Endpoints{},
			res: types.ResourceEndpoints,
			pr: []predicate.Predicate{
				predicate.NewPredicateFuncs(func(object client.Object) bool { return !w.cfg.EnableEndpointSliceAPI }),
				predicate.Funcs{
					UpdateFunc: func(ue event.UpdateEvent) bool {
						old := ue.ObjectOld.(*api.Endpoints)
						new := ue.ObjectNew.(*api.Endpoints)
						return !reflect.DeepEqual(old.Subsets, new.Subsets)
					},
				},
			},
		},
		{
			typ: &discoveryv1.EndpointSlice{},
			res: types.ResourceEndpoints,
			pr: []predicate.Predicate{
				predicate.NewPredicateFuncs(func(object client.Object) bool { return w.cfg.EnableEndpointSliceAPI }),
				predicate.Funcs{
					UpdateFunc: func(ue event.UpdateEvent) bool {
						old := ue.ObjectOld.(*discoveryv1.EndpointSlice)
						new := ue.ObjectNew.(*discoveryv1.EndpointSlice)
						return !reflect.DeepEqual(old.Endpoints, new.Endpoints)
					},
				},
			},
			name: func(obj client.Object) string {
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
					CreateFunc: func(e event.CreateEvent) bool { return false },
					UpdateFunc: func(e event.UpdateEvent) bool {
						return e.ObjectOld.GetDeletionTimestamp() != e.ObjectNew.GetDeletionTimestamp()
					},
				},
			},
		},
	}
}

func (w *watchers) handlersIngress() []*hdlr {
	return []*hdlr{
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
		{
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
		},
	}
}

func (w *watchers) handlersGatewayv1alpha2() []*hdlr {
	return []*hdlr{
		{
			typ:  &gatewayv1alpha2.Gateway{},
			res:  types.ResourceGateway,
			full: true,
			add: func(o client.Object) {
				w.ch.GatewaysA2Add = append(w.ch.GatewaysA2Add, o.(*gatewayv1alpha2.Gateway))
			},
			upd: func(old, new client.Object) {
				oldgw := old.(*gatewayv1alpha2.Gateway)
				newgw := new.(*gatewayv1alpha2.Gateway)
				oldValid := w.val.IsValidGatewayA2(oldgw)
				newValid := w.val.IsValidGatewayA2(newgw)
				if oldValid && newValid {
					w.ch.GatewaysA2Upd = append(w.ch.GatewaysA2Upd, newgw)
				} else if !oldValid && newValid {
					w.ch.GatewaysA2Add = append(w.ch.GatewaysA2Add, newgw)
				} else if oldValid && !newValid {
					w.ch.GatewaysA2Del = append(w.ch.GatewaysA2Del, oldgw)
				}
			},
			del: func(o client.Object) {
				w.ch.GatewaysA2Del = append(w.ch.GatewaysA2Del, o.(*gatewayv1alpha2.Gateway))
			},
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
		{
			typ: &gatewayv1alpha2.GatewayClass{},
			res: types.ResourceGatewayClass,
			add: func(o client.Object) {
				w.ch.GatewayClassesA2Add = append(w.ch.GatewayClassesA2Add, o.(*gatewayv1alpha2.GatewayClass))
			},
			upd: func(old, new client.Object) {
				oldgwcls := old.(*gatewayv1alpha2.GatewayClass)
				newgwcls := new.(*gatewayv1alpha2.GatewayClass)
				oldValid := w.val.IsValidGatewayClassA2(oldgwcls)
				newValid := w.val.IsValidGatewayClassA2(newgwcls)
				if oldValid && newValid {
					w.ch.GatewayClassesA2Upd = append(w.ch.GatewayClassesA2Upd, newgwcls)
				} else if !oldValid && newValid {
					w.ch.GatewayClassesA2Add = append(w.ch.GatewayClassesA2Add, newgwcls)
				} else if oldValid && !newValid {
					w.ch.GatewayClassesA2Del = append(w.ch.GatewayClassesA2Del, oldgwcls)
				}
			},
			del: func(o client.Object) {
				w.ch.GatewayClassesA2Del = append(w.ch.GatewayClassesA2Del, o.(*gatewayv1alpha2.GatewayClass))
			},
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
				predicate.Funcs{
					CreateFunc: func(ce event.CreateEvent) bool {
						return w.val.IsValidGatewayClassA2(ce.Object.(*gatewayv1alpha2.GatewayClass))
					},
					DeleteFunc: func(de event.DeleteEvent) bool {
						return w.val.IsValidGatewayClassA2(de.Object.(*gatewayv1alpha2.GatewayClass))
					},
					UpdateFunc: func(ue event.UpdateEvent) bool {
						return w.val.IsValidGatewayClassA2(ue.ObjectOld.(*gatewayv1alpha2.GatewayClass)) ||
							w.val.IsValidGatewayClassA2(ue.ObjectNew.(*gatewayv1alpha2.GatewayClass))
					},
				},
			},
		},
		{
			typ:  &gatewayv1alpha2.HTTPRoute{},
			res:  types.ResourceHTTPRoute,
			full: true,
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
	}
}

func (w *watchers) handlersGatewayv1beta1() []*hdlr {
	return []*hdlr{
		{
			typ:  &gatewayv1beta1.Gateway{},
			res:  types.ResourceGateway,
			full: true,
			add: func(o client.Object) {
				w.ch.GatewaysB1Add = append(w.ch.GatewaysB1Add, o.(*gatewayv1beta1.Gateway))
			},
			upd: func(old, new client.Object) {
				oldgw := old.(*gatewayv1beta1.Gateway)
				newgw := new.(*gatewayv1beta1.Gateway)
				oldValid := w.val.IsValidGatewayB1(oldgw)
				newValid := w.val.IsValidGatewayB1(newgw)
				if oldValid && newValid {
					w.ch.GatewaysB1Upd = append(w.ch.GatewaysB1Upd, newgw)
				} else if !oldValid && newValid {
					w.ch.GatewaysB1Add = append(w.ch.GatewaysB1Add, newgw)
				} else if oldValid && !newValid {
					w.ch.GatewaysB1Del = append(w.ch.GatewaysB1Del, oldgw)
				}
			},
			del: func(o client.Object) {
				w.ch.GatewaysB1Del = append(w.ch.GatewaysB1Del, o.(*gatewayv1beta1.Gateway))
			},
			pr: []predicate.Predicate{
				predicate.GenerationChangedPredicate{},
			},
		},
		{
			typ: &gatewayv1beta1.GatewayClass{},
			res: types.ResourceGatewayClass,
			add: func(o client.Object) {
				w.ch.GatewayClassesB1Add = append(w.ch.GatewayClassesB1Add, o.(*gatewayv1beta1.GatewayClass))
			},
			upd: func(old, new client.Object) {
				oldgwcls := old.(*gatewayv1beta1.GatewayClass)
				newgwcls := new.(*gatewayv1beta1.GatewayClass)
				oldValid := w.val.IsValidGatewayClassB1(oldgwcls)
				newValid := w.val.IsValidGatewayClassB1(newgwcls)
				if oldValid && newValid {
					w.ch.GatewayClassesB1Upd = append(w.ch.GatewayClassesB1Upd, newgwcls)
				} else if !oldValid && newValid {
					w.ch.GatewayClassesB1Add = append(w.ch.GatewayClassesB1Add, newgwcls)
				} else if oldValid && !newValid {
					w.ch.GatewayClassesB1Del = append(w.ch.GatewayClassesB1Del, oldgwcls)
				}
			},
			del: func(o client.Object) {
				w.ch.GatewayClassesB1Del = append(w.ch.GatewayClassesB1Del, o.(*gatewayv1beta1.GatewayClass))
			},
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

type hdlr struct {
	w   *watchers
	typ client.Object
	res types.ResourceType
	pr  []predicate.Predicate
	add,
	del func(o client.Object)
	upd  func(old, new client.Object)
	name func(obj client.Object) string
	full bool
}

func (h *hdlr) getSource() source.Source {
	return &source.Kind{Type: h.typ}
}

func (h *hdlr) getEventHandler() handler.EventHandler {
	return h
}

func (h *hdlr) getPredicates() []predicate.Predicate {
	return h.pr
}

func (h *hdlr) Create(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if h.add != nil {
		h.add(e.Object)
	}
	h.compose("add", e.Object)
	h.notify("create", e.Object, q)
}

func (h *hdlr) Update(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if h.upd != nil {
		h.upd(e.ObjectOld, e.ObjectNew)
	}
	h.compose("update", e.ObjectNew)
	h.notify("update", e.ObjectNew, q)
}

func (h *hdlr) Delete(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if h.del != nil {
		h.del(e.Object)
	}
	h.compose("del", e.Object)
	h.notify("delete", e.Object, q)
}

func (h *hdlr) Generic(e event.GenericEvent, q workqueue.RateLimitingInterface) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	h.w.ch.NeedFullSync = true
	h.notify("generic", e.Object, q)
}

func (h *hdlr) compose(ev string, obj client.Object) {
	var fullname string
	if h.name != nil {
		fullname = h.name(obj)
	} else {
		fullname = obj.GetName()
	}
	ns := obj.GetNamespace()
	if ns != "" {
		fullname = ns + "/" + fullname
	}
	ch := h.w.ch
	ch.Links[h.res] = appenddedup(ch.Links[h.res], fullname)
	ch.Objects = appenddedup(ch.Objects, fmt.Sprintf("%s/%s:%s", ev, h.res, fullname))
}

func (h *hdlr) notify(event string, o client.Object, q workqueue.RateLimitingInterface) {
	if h.full {
		h.w.ch.NeedFullSync = true
	}
	q.AddRateLimited(reconcile.Request{})
	if h.w.run {
		h.w.log.Info("notify", "event", event, "kind", reflect.TypeOf(o), "namespace", o.GetNamespace(), "name", o.GetName())
	}
}

func appenddedup(slice []string, s string) []string {
	for _, item := range slice {
		if item == s {
			return slice
		}
	}
	return append(slice, s)
}
