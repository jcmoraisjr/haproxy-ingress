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
	"strings"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	k8s "k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
)

// IngressLister makes a Store that lists Ingress.
type IngressLister struct {
	Lister v1beta1.IngressLister
}

// SecretLister makes a Store that lists Secrets.
type SecretLister struct {
	Client k8s.Interface
	Lister v1.SecretLister
}

// GetByName searches for a secret in the local secrets Store
func (sl *SecretLister) GetByName(name string) (*apiv1.Secret, error) {
	ns, key, err := cache.SplitMetaNamespaceKey(name)
	if err != nil {
		return nil, err
	}
	s, err := sl.Lister.Secrets(ns).Get(key)
	if _, ok := err.(*errors.StatusError); ok {
		return nil, fmt.Errorf("secret %v was not found", name)
	}
	return s, err
}

// CreateOrUpdate ...
func (sl *SecretLister) CreateOrUpdate(secret *apiv1.Secret) (err error) {
	cli := sl.Client.CoreV1().Secrets(secret.Namespace)

	if _, err := sl.GetByName(fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)); err != nil {
		_, err = cli.Create(secret)
	} else {
		_, err = cli.Update(secret)
	}

	return err
}

// ConfigMapLister makes a Store that lists ConfigMaps.
type ConfigMapLister struct {
	Client k8s.Interface
	Lister v1.ConfigMapLister
}

// GetByName searches for a ConfigMap in the local ConfigMaps Store
func (cml *ConfigMapLister) GetByName(name string) (*apiv1.ConfigMap, error) {
	ns, key, err := cache.SplitMetaNamespaceKey(name)
	if err != nil {
		return nil, err
	}
	cm, err := cml.Lister.ConfigMaps(ns).Get(key)
	if _, ok := err.(*errors.StatusError); ok {
		return nil, fmt.Errorf("configmap %v was not found", name)
	}
	return cm, err
}

// CreateOrUpdate ...
func (cml *ConfigMapLister) CreateOrUpdate(cm *apiv1.ConfigMap) (err error) {
	cli := cml.Client.CoreV1().ConfigMaps(cm.Namespace)

	if _, err := cml.GetByName(fmt.Sprintf("%s/%s", cm.Namespace, cm.Name)); err != nil {
		_, err = cli.Create(cm)
	} else {
		_, err = cli.Update(cm)
	}

	return
}

// ServiceLister makes a Store that lists Services.
type ServiceLister struct {
	Lister v1.ServiceLister
}

// GetByName searches for a service in the local secrets Store
func (sl *ServiceLister) GetByName(name string) (s *apiv1.Service, err error) {
	ns, key, err := cache.SplitMetaNamespaceKey(name)
	if err != nil {
		return nil, err
	}
	s, err = sl.Lister.Services(ns).Get(key)
	if _, ok := err.(*errors.StatusError); ok {
		return nil, fmt.Errorf("service %v was not found", name)
	}
	return
}

// NodeLister makes a Store that lists Nodes.
type NodeLister struct {
	Lister v1.NodeLister
}

// EndpointLister makes a Store that lists Endpoints.
type EndpointLister struct {
	Lister v1.EndpointsLister
}

// GetServiceEndpoints returns the endpoints of a service, matched on service name.
func (s *EndpointLister) GetServiceEndpoints(svc *apiv1.Service) (ep *apiv1.Endpoints, err error) {
	ep, err = s.Lister.Endpoints(svc.Namespace).Get(svc.Name)
	if _, ok := err.(*errors.StatusError); ok {
		return nil, fmt.Errorf("could not find endpoints for service: %v", svc.Name)
	}
	return
}

// PodLister makes a store that lists Pods.
type PodLister struct {
	Lister v1.PodLister
}

// GetTerminatingServicePods returns the pods that are terminating and belong
// (based on the Spec.Selector) to the supplied service.
func (s *PodLister) GetTerminatingServicePods(svc *apiv1.Service) (pl []apiv1.Pod, err error) {
	// converting the service selector to slice of string
	// in order to create the full match selector
	var ls []string
	for k, v := range svc.Spec.Selector {
		ls = append(ls, fmt.Sprintf("%s=%s", k, v))
	}
	// parsing the label selector from the previous selectors
	l, err := labels.Parse(strings.Join(ls, ","))
	if err != nil {
		return nil, err
	}

	list, err := s.Lister.Pods(svc.Namespace).List(l)
	if err != nil {
		return nil, err
	}

	for _, p := range list {
		if isTerminatingServicePod(svc, p) {
			pl = append(pl, *p)
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
	if pod.DeletionTimestamp != nil && pod.Status.Reason != "NodeLost" && pod.Status.PodIP != "" {
		termSvcPod = true
	}
	return
}

// GetPod returns the pod given it's namespace and name.
func (s *PodLister) GetPod(namespace, name string) (p *apiv1.Pod, err error) {
	p, err = s.Lister.Pods(namespace).Get(name)
	if _, ok := err.(*errors.StatusError); ok {
		return nil, fmt.Errorf("could not find pod %v/%v", namespace, name)
	}
	return
}
