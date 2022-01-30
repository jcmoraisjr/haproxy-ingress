/*
Copyright 2019 The HAProxy Ingress Controller Authors.

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

package helper_test

import (
	"crypto/sha1"
	"fmt"
	"net"
	"strings"
	"time"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	gatewayv1alpha1 "sigs.k8s.io/gateway-api/apis/v1alpha1"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// SecretContent ...
type SecretContent map[string]map[string][]byte

// CacheMock ...
type CacheMock struct {
	tracker convtypes.Tracker
	Changed *convtypes.ChangedObjects
	//
	IngList      []*networking.Ingress
	IngClassList []*networking.IngressClass
	SvcList      []*api.Service
	//
	GatewayA1List      []*gatewayv1alpha1.Gateway
	GatewayA1ClassList []*gatewayv1alpha1.GatewayClass
	HTTPRouteA1List    []*gatewayv1alpha1.HTTPRoute
	//
	LookupList    map[string][]net.IP
	EpList        map[string]*api.Endpoints
	ConfigMapList map[string]*api.ConfigMap
	TermPodList   map[string][]*api.Pod
	PodList       map[string]*api.Pod
	SecretTLSPath map[string]string
	SecretCAPath  map[string]string
	SecretCRLPath map[string]string
	SecretDHPath  map[string]string
	SecretContent SecretContent
}

// NewCacheMock ...
func NewCacheMock(tracker convtypes.Tracker) *CacheMock {
	return &CacheMock{
		tracker:     tracker,
		Changed:     &convtypes.ChangedObjects{},
		SvcList:     []*api.Service{},
		LookupList:  map[string][]net.IP{},
		EpList:      map[string]*api.Endpoints{},
		TermPodList: map[string][]*api.Pod{},
		SecretTLSPath: map[string]string{
			"system/ingress-default": "/tls/tls-default.pem",
		},
	}
}

func (c *CacheMock) buildResourceName(defaultNamespace, resourceName string) string {
	if defaultNamespace == "" || strings.Contains(resourceName, "/") {
		return resourceName
	}
	return defaultNamespace + "/" + resourceName
}

// ExternalNameLookup ...
func (c *CacheMock) ExternalNameLookup(externalName string) ([]net.IP, error) {
	if ip, found := c.LookupList[externalName]; found {
		return ip, nil
	}
	return nil, fmt.Errorf("hostname not found")
}

// GetIngress ...
func (c *CacheMock) GetIngress(ingressName string) (*networking.Ingress, error) {
	for _, ing := range c.IngList {
		if ing.Namespace+"/"+ing.Name == ingressName {
			return ing, nil
		}
	}
	return nil, fmt.Errorf("ingress not found: %s", ingressName)
}

// GetIngressList ...
func (c *CacheMock) GetIngressList() ([]*networking.Ingress, error) {
	return c.IngList, nil
}

// GetIngressClass ...
func (c *CacheMock) GetIngressClass(className string) (*networking.IngressClass, error) {
	for _, ingClass := range c.IngClassList {
		if ingClass.Name == className {
			return ingClass, nil
		}
	}
	return nil, fmt.Errorf("IngressClass not found: %s", className)
}

// GetGatewayA1 ...
func (c *CacheMock) GetGatewayA1(gatewayName string) (*gatewayv1alpha1.Gateway, error) {
	return nil, nil
}

// GetGatewayA1List ...
func (c *CacheMock) GetGatewayA1List() ([]*gatewayv1alpha1.Gateway, error) {
	return c.GatewayA1List, nil
}

// GetHTTPRouteA1List ...
func (c *CacheMock) GetHTTPRouteA1List(namespace string, match map[string]string) ([]*gatewayv1alpha1.HTTPRoute, error) {
	routeMatch := func(route *gatewayv1alpha1.HTTPRoute) bool {
		if namespace != "" && route.Namespace != namespace {
			return false
		}
		for k, v := range match {
			if route.Labels[k] != v {
				return false
			}
		}
		return true
	}
	var routes []*gatewayv1alpha1.HTTPRoute
	for _, route := range c.HTTPRouteA1List {
		if routeMatch(route) {
			routes = append(routes, route)
		}
	}
	return routes, nil
}

// GetService ...
func (c *CacheMock) GetService(defaultNamespace, serviceName string) (*api.Service, error) {
	fullname := c.buildResourceName(defaultNamespace, serviceName)
	sname := strings.Split(fullname, "/")
	if len(sname) == 2 {
		for _, svc := range c.SvcList {
			if svc.Namespace == sname[0] && svc.Name == sname[1] {
				return svc, nil
			}
		}
	}
	return nil, fmt.Errorf("service not found: '%s'", serviceName)
}

// GetEndpoints ...
func (c *CacheMock) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	serviceName := service.Namespace + "/" + service.Name
	if ep, found := c.EpList[serviceName]; found {
		return ep, nil
	}
	return nil, fmt.Errorf("could not find endpoints for service '%s'", serviceName)
}

// GetConfigMap ...
func (c *CacheMock) GetConfigMap(configMapName string) (*api.ConfigMap, error) {
	if configMap, found := c.ConfigMapList[configMapName]; found {
		return configMap, nil
	}
	return nil, fmt.Errorf("configmap not found: %s", configMapName)
}

// GetTerminatingPods ...
func (c *CacheMock) GetTerminatingPods(service *api.Service, track []convtypes.TrackingRef) ([]*api.Pod, error) {
	serviceName := service.Namespace + "/" + service.Name
	if pods, found := c.TermPodList[serviceName]; found {
		return pods, nil
	}
	return []*api.Pod{}, nil
}

// GetPod ...
func (c *CacheMock) GetPod(podName string) (*api.Pod, error) {
	if pod, found := c.PodList[podName]; found {
		return pod, nil
	}
	return nil, fmt.Errorf("pod not found: '%s'", podName)
}

// GetPodNamespace ...
func (c *CacheMock) GetPodNamespace() string {
	return "ingress-controller"
}

// GetTLSSecretPath ...
func (c *CacheMock) GetTLSSecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (convtypes.CrtFile, error) {
	fullname := c.buildResourceName(defaultNamespace, secretName)
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, fullname)
	if path, found := c.SecretTLSPath[fullname]; found {
		return convtypes.CrtFile{
			Filename:   path,
			SHA1Hash:   fmt.Sprintf("%x", sha1.Sum([]byte(path))),
			CommonName: "localhost.localdomain",
			NotAfter:   time.Now().AddDate(0, 0, 30),
		}, nil
	}
	return convtypes.CrtFile{}, fmt.Errorf("secret not found: '%s'", fullname)
}

// GetCASecretPath ...
func (c *CacheMock) GetCASecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (ca, crl convtypes.File, err error) {
	fullname := c.buildResourceName(defaultNamespace, secretName)
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, fullname)
	if path, found := c.SecretCAPath[fullname]; found {
		ca = convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}
	} else {
		return ca, crl, fmt.Errorf("secret not found: '%s'", fullname)
	}
	if path, found := c.SecretCRLPath[fullname]; found {
		crl = convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}
	}
	return ca, crl, nil
}

// GetDHSecretPath ...
func (c *CacheMock) GetDHSecretPath(defaultNamespace, secretName string) (convtypes.File, error) {
	fullname := c.buildResourceName(defaultNamespace, secretName)
	if path, found := c.SecretDHPath[fullname]; found {
		return convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}, nil
	}
	return convtypes.File{}, fmt.Errorf("secret not found: '%s'", fullname)
}

// GetPasswdSecretContent ...
func (c *CacheMock) GetPasswdSecretContent(defaultNamespace, secretName string, track []convtypes.TrackingRef) ([]byte, error) {
	fullname := c.buildResourceName(defaultNamespace, secretName)
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, fullname)
	if content, found := c.SecretContent[fullname]; found {
		keyName := "auth"
		if val, found := content[keyName]; found {
			return val, nil
		}
		return nil, fmt.Errorf("secret '%s' does not have file/key '%s'", fullname, keyName)
	}
	return nil, fmt.Errorf("secret not found: '%s'", fullname)
}

// SwapChangedObjects ...
func (c *CacheMock) SwapChangedObjects() *convtypes.ChangedObjects {
	changed := c.Changed
	c.Changed = &convtypes.ChangedObjects{
		GlobalConfigMapDataCur: changed.GlobalConfigMapDataNew,
		TCPConfigMapDataCur:    changed.TCPConfigMapDataNew,
	}
	// update changed.Links based on notifications
	changedLinks := convtypes.TrackingLinks{}
	addChanges := func(ctx convtypes.ResourceType, ns, n string) {
		fullname := ns + "/" + n
		changedLinks[ctx] = append(changedLinks[ctx], fullname)
	}
	for _, ing := range changed.IngressesDel {
		addChanges(convtypes.ResourceIngress, ing.Namespace, ing.Name)
	}
	for _, ing := range changed.IngressesUpd {
		addChanges(convtypes.ResourceIngress, ing.Namespace, ing.Name)
	}
	for _, ing := range changed.IngressesAdd {
		addChanges(convtypes.ResourceIngress, ing.Namespace, ing.Name)
	}
	for _, svc := range changed.ServicesDel {
		addChanges(convtypes.ResourceService, svc.Namespace, svc.Name)
	}
	for _, svc := range changed.ServicesUpd {
		addChanges(convtypes.ResourceService, svc.Namespace, svc.Name)
	}
	for _, svc := range changed.ServicesAdd {
		addChanges(convtypes.ResourceService, svc.Namespace, svc.Name)
	}
	for _, secret := range changed.SecretsDel {
		addChanges(convtypes.ResourceSecret, secret.Namespace, secret.Name)
	}
	for _, secret := range changed.SecretsUpd {
		addChanges(convtypes.ResourceSecret, secret.Namespace, secret.Name)
	}
	for _, secret := range changed.SecretsAdd {
		addChanges(convtypes.ResourceSecret, secret.Namespace, secret.Name)
	}
	for _, ep := range changed.EndpointsNew {
		addChanges(convtypes.ResourceEndpoints, ep.Namespace, ep.Name)
	}
	changed.Links = changedLinks
	// update c.IngList based on notifications
	for i, ing := range c.IngList {
		for _, ingUpd := range changed.IngressesUpd {
			if ing.Namespace == ingUpd.Namespace && ing.Name == ingUpd.Name {
				c.IngList[i] = ingUpd
			}
		}
		for j, ingDel := range changed.IngressesDel {
			if ing.Namespace == ingDel.Namespace && ing.Name == ingDel.Name {
				c.IngList[i] = c.IngList[len(c.IngList)-j-1]
			}
		}
	}
	c.IngList = c.IngList[:len(c.IngList)-len(changed.IngressesDel)]
	c.IngList = append(c.IngList, changed.IngressesAdd...)
	// update c.SvcList based on notifications
	for i, svc := range c.SvcList {
		for _, svcUpd := range changed.ServicesUpd {
			if svc.Namespace == svcUpd.Namespace && svc.Name == svcUpd.Name {
				c.SvcList[i] = svcUpd
			}
		}
		for j, svcDel := range changed.ServicesDel {
			if svc.Namespace == svcDel.Namespace && svc.Name == svcDel.Name {
				c.SvcList[i] = c.SvcList[len(c.SvcList)-j-1]
				delete(c.EpList, svc.Namespace+"/"+svc.Name)
			}
		}
	}
	// update c.SecretList based on notification
	for _, secret := range changed.SecretsDel {
		delete(c.SecretTLSPath, secret.Namespace+"/"+secret.Name)
	}
	for _, secret := range changed.SecretsAdd {
		name := secret.Namespace + "/" + secret.Name
		c.SecretTLSPath[name] = "/tls/" + name + ".pem"
	}
	// update c.EpList based on notifications
	for _, ep := range changed.EndpointsNew {
		c.EpList[ep.Namespace+"/"+ep.Name] = ep
	}
	c.SvcList = c.SvcList[:len(c.SvcList)-len(changed.ServicesDel)]
	c.SvcList = append(c.SvcList, changed.ServicesAdd...)
	return changed
}

// NeedFullSync ...
func (c *CacheMock) NeedFullSync() bool {
	return false
}
