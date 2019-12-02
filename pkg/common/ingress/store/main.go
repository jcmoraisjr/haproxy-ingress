/*
Copyright 2015 The Kubernetes Authors.

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

package store

import (
	"fmt"

	apiv1 "k8s.io/api/core/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/util/node"
)

// IngressLister makes a Store that lists Ingress.
type IngressLister struct {
	cache.Store
}

// SecretLister makes a Store that lists Secrets.
type SecretLister struct {
	Client k8s.Interface
	cache.Store
}

// GetByName searches for a secret in the local secrets Store
func (sl *SecretLister) GetByName(name string) (*apiv1.Secret, error) {
	s, exists, err := sl.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("secret %v was not found", name)
	}
	return s.(*apiv1.Secret), nil
}

// CreateOrUpdate ...
func (sl *SecretLister) CreateOrUpdate(secret *apiv1.Secret) (err error) {
	cli := sl.Client.CoreV1().Secrets(secret.Namespace)
	if _, exists, _ := sl.GetByKey(secret.Namespace + "/" + secret.Name); exists {
		_, err = cli.Update(secret)
	} else {
		_, err = cli.Create(secret)
	}
	return err
}

// ConfigMapLister makes a Store that lists Configmaps.
type ConfigMapLister struct {
	Client k8s.Interface
	cache.Store
}

// GetByName searches for a configmap in the local configmaps Store
func (cml *ConfigMapLister) GetByName(name string) (*apiv1.ConfigMap, error) {
	s, exists, err := cml.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("configmap %v was not found", name)
	}
	return s.(*apiv1.ConfigMap), nil
}

// CreateOrUpdate ...
func (cml *ConfigMapLister) CreateOrUpdate(cm *apiv1.ConfigMap) (err error) {
	cli := cml.Client.CoreV1().ConfigMaps(cm.Namespace)
	if _, exists, _ := cml.GetByKey(cm.Namespace + "/" + cm.Name); exists {
		_, err = cli.Update(cm)
	} else {
		_, err = cli.Create(cm)
	}
	return err
}

// ServiceLister makes a Store that lists Services.
type ServiceLister struct {
	cache.Store
}

// GetByName searches for a service in the local secrets Store
func (sl *ServiceLister) GetByName(name string) (*apiv1.Service, error) {
	s, exists, err := sl.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("service %v was not found", name)
	}
	return s.(*apiv1.Service), nil
}

// NodeLister makes a Store that lists Nodes.
type NodeLister struct {
	cache.Store
}

// EndpointLister makes a Store that lists Endpoints.
type EndpointLister struct {
	cache.Store
}

// GetServiceEndpoints returns the endpoints of a service, matched on service name.
func (s *EndpointLister) GetServiceEndpoints(svc *apiv1.Service) (ep apiv1.Endpoints, err error) {
	for _, m := range s.Store.List() {
		ep = *m.(*apiv1.Endpoints)
		if svc.Name == ep.Name && svc.Namespace == ep.Namespace {
			return ep, nil
		}
	}
	err = fmt.Errorf("could not find endpoints for service: %v", svc.Name)
	return
}

// PodLister makes a store that lists Pods.
type PodLister struct {
	cache.Store
}

// GetTerminatingServicePods returns the pods that are terminating and belong
// (based on the Spec.Selector) to the supplied service.
func (s *PodLister) GetTerminatingServicePods(svc *apiv1.Service) (pl []apiv1.Pod, err error) {
	list := s.Store.List()
	for _, m := range list {
		p := *m.(*apiv1.Pod)
		if isTerminatingServicePod(svc, &p) {
			pl = append(pl, p)
		}
	}
	err = nil
	return
}

// Indicates whether or not pod belongs to svc, and is in the process of terminating
func isTerminatingServicePod(svc *apiv1.Service, pod *apiv1.Pod) (termSvcPod bool) {
	termSvcPod = false
	if svc.GetNamespace() != pod.GetNamespace() {
		return
	}
	for selectorLabel, selectorValue := range svc.Spec.Selector {
		if labelValue, present := pod.Labels[selectorLabel]; !present || selectorValue != labelValue {
			return
		}
	}
	if pod.DeletionTimestamp != nil && pod.Status.Reason != node.NodeUnreachablePodReason && pod.Status.PodIP != "" {
		termSvcPod = true
	}
	return
}

// GetPod returns the pod given it's namespace and name.
func (s *PodLister) GetPod(namespace, name string) (*apiv1.Pod, error) {
	for _, m := range s.Store.List() {
		pod := *m.(*apiv1.Pod)
		if pod.Name == name && pod.Namespace == namespace {
			return &pod, nil
		}
	}
	err := fmt.Errorf("could not find pod %v/%v", namespace, name)
	return nil, err
}
