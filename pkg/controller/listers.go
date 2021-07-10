/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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

package controller

import (
	"fmt"
	"reflect"
	"time"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	informerscore "k8s.io/client-go/informers/core/v1"
	informersnetworking "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes/fake"
	listerscore "k8s.io/client-go/listers/core/v1"
	listersnetworking "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	gateway "sigs.k8s.io/gateway-api/apis/v1alpha1"
	informersgateway "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	informersgatewayv1alpha1 "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1alpha1"
	listersgateway "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1alpha1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// ListerEvents ...
type ListerEvents interface {
	IsValidIngress(ing *networking.Ingress) bool
	IsValidIngressClass(ingClass *networking.IngressClass) bool
	IsValidGateway(gw *gateway.Gateway) bool
	IsValidGatewayClass(gwClass *gateway.GatewayClass) bool
	IsValidConfigMap(cm *api.ConfigMap) bool
	Notify(old, cur interface{})
}

type listers struct {
	events   ListerEvents
	logger   types.Logger
	recorder record.EventRecorder
	running  bool
	//
	hasPodLister bool
	//
	ingressLister       listersnetworking.IngressLister
	ingressClassLister  listersnetworking.IngressClassLister
	gatewayLister       listersgateway.GatewayLister
	gatewayClassLister  listersgateway.GatewayClassLister
	httpRouteLister     listersgateway.HTTPRouteLister
	tlsRouteLister      listersgateway.TLSRouteLister
	tcpRouteLister      listersgateway.TCPRouteLister
	udpRouteLister      listersgateway.UDPRouteLister
	backendPolicyLister listersgateway.BackendPolicyLister
	endpointLister      listerscore.EndpointsLister
	serviceLister       listerscore.ServiceLister
	secretLister        listerscore.SecretLister
	configMapLister     listerscore.ConfigMapLister
	podLister           listerscore.PodLister
	//
	ingressInformer       cache.SharedInformer
	ingressClassInformer  cache.SharedInformer
	gatewayInformer       cache.SharedInformer
	gatewayClassInformer  cache.SharedInformer
	httpRouteInformer     cache.SharedInformer
	tlsRouteInformer      cache.SharedInformer
	tcpRouteInformer      cache.SharedInformer
	udpRouteInformer      cache.SharedInformer
	backendPolicyInformer cache.SharedInformer
	endpointInformer      cache.SharedInformer
	serviceInformer       cache.SharedInformer
	secretInformer        cache.SharedInformer
	configMapInformer     cache.SharedInformer
	podInformer           cache.SharedInformer
}

func createListers(
	events ListerEvents,
	logger types.Logger,
	recorder record.EventRecorder,
	client types.Client,
	watchGateway bool,
	watchNamespace string,
	isolateNamespace bool,
	podWatch bool,
	resync time.Duration,
) *listers {
	clusterWatch := watchNamespace == api.NamespaceAll
	clusterOption := informers.WithTweakListOptions(nil)
	namespaceOption := informers.WithNamespace(watchNamespace)
	var ingressInformer, resourceInformer, localInformer informers.SharedInformerFactory
	if clusterWatch {
		ingressInformer = informers.NewSharedInformerFactoryWithOptions(client, resync, clusterOption)
		resourceInformer = ingressInformer
	} else if isolateNamespace {
		ingressInformer = informers.NewSharedInformerFactoryWithOptions(client, resync, namespaceOption)
		resourceInformer = ingressInformer
	} else {
		ingressInformer = informers.NewSharedInformerFactoryWithOptions(client, resync, namespaceOption)
		resourceInformer = informers.NewSharedInformerFactoryWithOptions(client, resync, clusterOption)
	}
	if !podWatch || !clusterWatch {
		localInformer = informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
	}
	l := &listers{
		events:   events,
		recorder: recorder,
		logger:   logger,
	}
	l.createIngressLister(ingressInformer.Networking().V1().Ingresses())
	l.createIngressClassLister(ingressInformer.Networking().V1().IngressClasses())
	l.createEndpointLister(resourceInformer.Core().V1().Endpoints())
	l.createServiceLister(resourceInformer.Core().V1().Services())
	l.createSecretLister(resourceInformer.Core().V1().Secrets())
	l.createConfigMapLister(resourceInformer.Core().V1().ConfigMaps())
	if podWatch {
		l.createPodLister(ingressInformer.Core().V1().Pods())
		l.hasPodLister = true
	} else {
		l.createPodLister(localInformer.Core().V1().Pods())
	}

	if watchGateway {
		var option informersgateway.SharedInformerOption
		if clusterWatch {
			option = informersgateway.WithTweakListOptions(nil)
		} else {
			option = informersgateway.WithNamespace(watchNamespace)
		}
		informer := informersgateway.NewSharedInformerFactoryWithOptions(client, resync, option)
		l.createGatewayLister(informer.Networking().V1alpha1().Gateways())
		l.createGatewayClassLister(informer.Networking().V1alpha1().GatewayClasses())
		l.createHTTPRouteLister(informer.Networking().V1alpha1().HTTPRoutes())
		l.createTLSRouteLister(informer.Networking().V1alpha1().TLSRoutes())
		l.createTCPRouteLister(informer.Networking().V1alpha1().TCPRoutes())
		l.createUDPRouteLister(informer.Networking().V1alpha1().UDPRoutes())
		l.createBackendPolicyLister(informer.Networking().V1alpha1().BackendPolicies())
	}

	return l
}

func (l *listers) RunAsync(stopCh <-chan struct{}) {
	syncFailed := func() {
		runtime.HandleError(fmt.Errorf("initial cache sync has timed out or shutdown has requested"))
	}
	l.logger.Info("loading object cache...")

	if l.gatewayClassInformer != nil {
		go l.gatewayClassInformer.Run(stopCh)
		if !cache.WaitForCacheSync(stopCh,
			l.gatewayClassInformer.HasSynced,
		) {
			syncFailed()
			return
		}

		go l.gatewayInformer.Run(stopCh)
		go l.httpRouteInformer.Run(stopCh)
		go l.tlsRouteInformer.Run(stopCh)
		go l.tcpRouteInformer.Run(stopCh)
		go l.udpRouteInformer.Run(stopCh)
		go l.backendPolicyInformer.Run(stopCh)
		if !cache.WaitForCacheSync(stopCh,
			l.gatewayInformer.HasSynced,
			l.httpRouteInformer.HasSynced,
			l.tlsRouteInformer.HasSynced,
			l.tcpRouteInformer.HasSynced,
			l.udpRouteInformer.HasSynced,
			l.backendPolicyInformer.HasSynced,
		) {
			syncFailed()
			return
		}
	}

	// wait IngressClass lister initialize, ingress informers initialization depends on it
	go l.ingressClassInformer.Run(stopCh)
	ingClassSynced := cache.WaitForCacheSync(stopCh,
		l.ingressClassInformer.HasSynced,
	)
	if !ingClassSynced {
		syncFailed()
		return
	}

	// initialize listers and informers
	go l.ingressInformer.Run(stopCh)
	go l.endpointInformer.Run(stopCh)
	go l.serviceInformer.Run(stopCh)
	go l.secretInformer.Run(stopCh)
	go l.configMapInformer.Run(stopCh)
	go l.podInformer.Run(stopCh)
	synced := cache.WaitForCacheSync(stopCh,
		l.ingressInformer.HasSynced,
		l.endpointInformer.HasSynced,
		l.serviceInformer.HasSynced,
		l.secretInformer.HasSynced,
		l.configMapInformer.HasSynced,
		l.podInformer.HasSynced,
	)
	if synced {
		l.logger.Info("cache successfully synced")
		l.running = true
	} else {
		syncFailed()
	}
}

func (l *listers) createIngressLister(informer informersnetworking.IngressInformer) {
	l.ingressLister = informer.Lister()
	l.ingressInformer = informer.Informer()
	l.ingressInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ing := obj.(*networking.Ingress)
			if l.events.IsValidIngress(ing) {
				l.events.Notify(nil, ing)
				if l.running {
					l.recorder.Eventf(ing, api.EventTypeNormal, "CREATE", "Ingress %s/%s", ing.Namespace, ing.Name)
				}
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if reflect.DeepEqual(old, cur) {
				return
			}
			oldIng := old.(*networking.Ingress)
			curIng := cur.(*networking.Ingress)
			oldValid := l.events.IsValidIngress(oldIng)
			curValid := l.events.IsValidIngress(curIng)
			if !oldValid && !curValid {
				return
			}
			if !oldValid && curValid {
				l.events.Notify(nil, curIng)
				l.recorder.Eventf(curIng, api.EventTypeNormal, "CREATE", "Ingress %s/%s", curIng.Namespace, curIng.Name)
			} else if oldValid && !curValid {
				l.events.Notify(oldIng, nil)
				l.recorder.Eventf(curIng, api.EventTypeNormal, "DELETE", "Ingress %s/%s", curIng.Namespace, curIng.Name)
			} else {
				l.events.Notify(oldIng, curIng)
				l.recorder.Eventf(curIng, api.EventTypeNormal, "UPDATE", "Ingress %s/%s", curIng.Namespace, curIng.Name)
			}
		},
		DeleteFunc: func(obj interface{}) {
			ing, ok := obj.(*networking.Ingress)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					l.logger.Error("couldn't get object from tombstone %#v", obj)
					l.events.Notify(nil, nil)
					return
				}
				if ing, ok = tombstone.Obj.(*networking.Ingress); !ok {
					l.logger.Error("Tombstone contained object that is not an Ingress: %#v", obj)
					l.events.Notify(nil, nil)
					return
				}
			}
			if !l.events.IsValidIngress(ing) {
				return
			}
			l.recorder.Eventf(ing, api.EventTypeNormal, "DELETE", "Ingress %s/%s", ing.Namespace, ing.Name)
			l.events.Notify(ing, nil)
		},
	})
}

func (l *listers) createIngressClassLister(informer informersnetworking.IngressClassInformer) {
	l.ingressClassLister = informer.Lister()
	l.ingressClassInformer = informer.Informer()
	l.ingressClassInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cls := obj.(*networking.IngressClass)
			if l.events.IsValidIngressClass(cls) {
				l.events.Notify(nil, cls)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if reflect.DeepEqual(old, cur) {
				return
			}
			oldClass := old.(*networking.IngressClass)
			curClass := cur.(*networking.IngressClass)
			oldValid := l.events.IsValidIngressClass(oldClass)
			curValid := l.events.IsValidIngressClass(curClass)
			if !oldValid && !curValid {
				return
			}
			if !oldValid && curValid {
				l.events.Notify(nil, curClass)
			} else if oldValid && !curValid {
				l.events.Notify(oldClass, nil)
			} else {
				l.events.Notify(oldClass, curClass)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createGatewayLister(informer informersgatewayv1alpha1.GatewayInformer) {
	l.gatewayLister = informer.Lister()
	l.gatewayInformer = informer.Informer()
	l.gatewayInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			gw := obj.(*gateway.Gateway)
			if l.events.IsValidGateway(gw) {
				l.events.Notify(nil, gw)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if reflect.DeepEqual(old, cur) {
				return
			}
			oldGw := old.(*gateway.Gateway)
			curGw := cur.(*gateway.Gateway)
			oldValid := l.events.IsValidGateway(oldGw)
			curValid := l.events.IsValidGateway(curGw)
			if !oldValid && !curValid {
				return
			}
			if !oldValid && curValid {
				l.events.Notify(nil, curGw)
			} else if oldValid && !curValid {
				l.events.Notify(oldGw, nil)
			} else {
				l.events.Notify(oldGw, curGw)
			}
		},
		DeleteFunc: func(obj interface{}) {
			gw, ok := obj.(*gateway.Gateway)
			if !ok {
				l.events.Notify(nil, nil)
				return
			}
			if l.events.IsValidGateway(gw) {
				l.events.Notify(gw, nil)
			}
		},
	})
}

func (l *listers) createGatewayClassLister(informer informersgatewayv1alpha1.GatewayClassInformer) {
	l.gatewayClassLister = informer.Lister()
	l.gatewayClassInformer = informer.Informer()
	l.gatewayClassInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cls := obj.(*gateway.GatewayClass)
			if l.events.IsValidGatewayClass(cls) {
				l.events.Notify(nil, cls)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if reflect.DeepEqual(old, cur) {
				return
			}
			oldClass := old.(*gateway.GatewayClass)
			curClass := cur.(*gateway.GatewayClass)
			oldValid := l.events.IsValidGatewayClass(oldClass)
			curValid := l.events.IsValidGatewayClass(curClass)
			if !oldValid && !curValid {
				return
			}
			if !oldValid && curValid {
				l.events.Notify(nil, curClass)
			} else if oldValid && !curValid {
				l.events.Notify(oldClass, nil)
			} else {
				l.events.Notify(oldClass, curClass)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createHTTPRouteLister(informer informersgatewayv1alpha1.HTTPRouteInformer) {
	l.httpRouteLister = informer.Lister()
	l.httpRouteInformer = informer.Informer()
	l.httpRouteInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createTLSRouteLister(informer informersgatewayv1alpha1.TLSRouteInformer) {
	l.tlsRouteLister = informer.Lister()
	l.tlsRouteInformer = informer.Informer()
	l.tlsRouteInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createTCPRouteLister(informer informersgatewayv1alpha1.TCPRouteInformer) {
	l.tcpRouteLister = informer.Lister()
	l.tcpRouteInformer = informer.Informer()
	l.tcpRouteInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createUDPRouteLister(informer informersgatewayv1alpha1.UDPRouteInformer) {
	l.udpRouteLister = informer.Lister()
	l.udpRouteInformer = informer.Informer()
	l.udpRouteInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createBackendPolicyLister(informer informersgatewayv1alpha1.BackendPolicyInformer) {
	l.backendPolicyLister = informer.Lister()
	l.backendPolicyInformer = informer.Informer()
	l.backendPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createEndpointLister(informer informerscore.EndpointsInformer) {
	l.endpointLister = informer.Lister()
	l.endpointInformer = informer.Informer()
	l.endpointInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			oldEP := old.(*api.Endpoints)
			curEP := cur.(*api.Endpoints)
			if !reflect.DeepEqual(oldEP.Subsets, curEP.Subsets) {
				l.events.Notify(oldEP, curEP)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}

func (l *listers) createServiceLister(informer informerscore.ServiceInformer) {
	l.serviceLister = informer.Lister()
	l.serviceInformer = informer.Informer()
	l.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			svc, ok := obj.(*api.Service)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					l.logger.Error("couldn't get object from tombstone %#v", obj)
					return
				}
				if svc, ok = tombstone.Obj.(*api.Service); !ok {
					l.logger.Error("Tombstone contained object that is not a Service: %#v", obj)
					return
				}
			}
			l.events.Notify(svc, nil)
		},
	})
}

func (l *listers) createSecretLister(informer informerscore.SecretInformer) {
	l.secretLister = informer.Lister()
	l.secretInformer = informer.Informer()
	l.secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			l.events.Notify(nil, obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			sec, ok := obj.(*api.Secret)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					l.logger.Error("couldn't get object from tombstone %#v", obj)
					return
				}
				if sec, ok = tombstone.Obj.(*api.Secret); !ok {
					l.logger.Error("Tombstone contained object that is not a Secret: %#v", obj)
					return
				}
			}
			l.events.Notify(sec, nil)
		},
	})
}

func (l *listers) createConfigMapLister(informer informerscore.ConfigMapInformer) {
	l.configMapLister = informer.Lister()
	l.configMapInformer = informer.Informer()
	l.configMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if l.events.IsValidConfigMap(obj.(*api.ConfigMap)) {
				l.events.Notify(nil, obj)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			curCM := cur.(*api.ConfigMap)
			if l.events.IsValidConfigMap(curCM) {
				oldCM := old.(*api.ConfigMap)
				if !reflect.DeepEqual(oldCM.Data, curCM.Data) {
					l.events.Notify(old, cur)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if l.events.IsValidConfigMap(obj.(*api.ConfigMap)) {
				l.events.Notify(obj, nil)
			}
		},
	})
}

func (l *listers) createPodLister(informer informerscore.PodInformer) {
	l.podLister = informer.Lister()
	l.podInformer = informer.Informer()
	l.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, cur interface{}) {
			oldPod := old.(*api.Pod)
			curPod := cur.(*api.Pod)
			if oldPod.DeletionTimestamp != curPod.DeletionTimestamp {
				l.events.Notify(old, cur)
			}
		},
		DeleteFunc: func(obj interface{}) {
			l.events.Notify(obj, nil)
		},
	})
}
