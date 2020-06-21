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
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	informersv1 "k8s.io/client-go/informers/core/v1"
	informersv1beta1 "k8s.io/client-go/informers/extensions/v1beta1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	listersv1 "k8s.io/client-go/listers/core/v1"
	listersv1beta1 "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// ListerEvents ...
type ListerEvents interface {
	IsValidIngress(ing *extensions.Ingress) bool
	IsValidConfigMap(cm *api.ConfigMap) bool
	Notify(old, cur interface{})
}

type listers struct {
	events   ListerEvents
	logger   types.Logger
	recorder record.EventRecorder
	running  bool
	//
	ingressLister   listersv1beta1.IngressLister
	endpointLister  listersv1.EndpointsLister
	serviceLister   listersv1.ServiceLister
	secretLister    listersv1.SecretLister
	configMapLister listersv1.ConfigMapLister
	podLister       listersv1.PodLister
	nodeLister      listersv1.NodeLister
	//
	ingressInformer   cache.SharedInformer
	endpointInformer  cache.SharedInformer
	serviceInformer   cache.SharedInformer
	secretInformer    cache.SharedInformer
	configMapInformer cache.SharedInformer
	podInformer       cache.SharedInformer
	nodeInformer      cache.SharedInformer
}

func createListers(
	events ListerEvents,
	logger types.Logger,
	recorder record.EventRecorder,
	client k8s.Interface,
	watchNamespace string,
	isolateNamespace bool,
	resync time.Duration,
) *listers {
	clusterWatch := watchNamespace == api.NamespaceAll
	clusterOption := informers.WithTweakListOptions(nil)
	namespaceOption := informers.WithNamespace(watchNamespace)
	var ingressInformer, resourceInformer informers.SharedInformerFactory
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
	l := &listers{
		events:   events,
		recorder: recorder,
		logger:   logger,
	}
	l.createIngressLister(ingressInformer.Extensions().V1beta1().Ingresses())
	l.createEndpointLister(resourceInformer.Core().V1().Endpoints())
	l.createServiceLister(resourceInformer.Core().V1().Services())
	l.createSecretLister(resourceInformer.Core().V1().Secrets())
	l.createConfigMapLister(resourceInformer.Core().V1().ConfigMaps())
	l.createPodLister(ingressInformer.Core().V1().Pods())
	if clusterWatch {
		// ignoring --disable-node-list
		l.createNodeLister(resourceInformer.Core().V1().Nodes())
	} else {
		localInformer := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
		l.createNodeLister(localInformer.Core().V1().Nodes())
	}
	return l
}

func (l *listers) RunAsync(stopCh <-chan struct{}) {
	go l.ingressInformer.Run(stopCh)
	go l.endpointInformer.Run(stopCh)
	go l.serviceInformer.Run(stopCh)
	go l.secretInformer.Run(stopCh)
	go l.configMapInformer.Run(stopCh)
	go l.podInformer.Run(stopCh)
	go l.nodeInformer.Run(stopCh)
	l.logger.Info("loading object cache...")
	synced := cache.WaitForCacheSync(stopCh,
		l.ingressInformer.HasSynced,
		l.endpointInformer.HasSynced,
		l.serviceInformer.HasSynced,
		l.secretInformer.HasSynced,
		l.configMapInformer.HasSynced,
		l.podInformer.HasSynced,
		l.nodeInformer.HasSynced,
	)
	if synced {
		l.logger.Info("cache successfully synced")
		l.running = true
	} else {
		runtime.HandleError(fmt.Errorf("initial cache sync has timed out or shutdown has requested"))
	}
}

func (l *listers) createIngressLister(informer informersv1beta1.IngressInformer) {
	l.ingressLister = informer.Lister()
	l.ingressInformer = informer.Informer()
	l.ingressInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ing := obj.(*extensions.Ingress)
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
			oldIng := old.(*extensions.Ingress)
			curIng := cur.(*extensions.Ingress)
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
			ing, ok := obj.(*extensions.Ingress)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					l.logger.Error("couldn't get object from tombstone %#v", obj)
					l.events.Notify(nil, nil)
					return
				}
				if ing, ok = tombstone.Obj.(*extensions.Ingress); !ok {
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

func (l *listers) createEndpointLister(informer informersv1.EndpointsInformer) {
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

func (l *listers) createServiceLister(informer informersv1.ServiceInformer) {
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

func (l *listers) createSecretLister(informer informersv1.SecretInformer) {
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

func (l *listers) createConfigMapLister(informer informersv1.ConfigMapInformer) {
	l.configMapLister = informer.Lister()
	l.configMapInformer = informer.Informer()
	l.configMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if l.events.IsValidConfigMap(obj.(*api.ConfigMap)) {
				l.events.Notify(nil, obj)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				if l.events.IsValidConfigMap(cur.(*api.ConfigMap)) {
					l.events.Notify(old, cur)
				}
			}
		},
	})
}

func (l *listers) createPodLister(informer informersv1.PodInformer) {
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

func (l *listers) createNodeLister(informer informersv1.NodeInformer) {
	l.nodeLister = informer.Lister()
	l.nodeInformer = informer.Informer()
}
