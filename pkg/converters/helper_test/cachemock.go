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
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"

	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
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
	HTTPRouteList   []*gatewayv1.HTTPRoute
	TLSRouteList    []*gatewayv1alpha2.TLSRoute
	TCPRouteList    []*gatewayv1alpha2.TCPRoute
	GatewayList     []*gatewayv1.Gateway
	GatewayClassMap map[gatewayv1.ObjectName]*gatewayv1.GatewayClass
	//
	NsList        map[string]*api.Namespace
	LookupList    map[string][]net.IP
	EpsList       map[string][]*discoveryv1.EndpointSlice
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
		tracker:         tracker,
		Changed:         &convtypes.ChangedObjects{Links: make(convtypes.TrackingLinks)},
		SvcList:         []*api.Service{},
		GatewayList:     []*gatewayv1.Gateway{},
		GatewayClassMap: map[gatewayv1.ObjectName]*gatewayv1.GatewayClass{},
		NsList:          map[string]*api.Namespace{},
		LookupList:      map[string][]net.IP{},
		EpsList:         map[string][]*discoveryv1.EndpointSlice{},
		TermPodList:     map[string][]*api.Pod{},
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

// GetHTTPRouteList ...
func (c *CacheMock) GetHTTPRouteList() ([]*gatewayv1.HTTPRoute, error) {
	return c.HTTPRouteList, nil
}

func (c *CacheMock) GetTCPRouteList() ([]*gatewayv1alpha2.TCPRoute, error) {
	return c.TCPRouteList, nil
}

func (c *CacheMock) GetTLSRouteList() ([]*gatewayv1alpha2.TLSRoute, error) {
	return c.TLSRouteList, nil
}

func (c *CacheMock) GetReferenceGrantList() ([]*gatewayv1beta1.ReferenceGrant, error) {
	return nil, nil
}

func (c *CacheMock) GetGatewayClassMap() (map[gatewayv1.ObjectName]*gatewayv1.GatewayClass, error) {
	return c.GatewayClassMap, nil
}

// GetGatewayList ...
func (c *CacheMock) GetGatewayList() ([]*gatewayv1.Gateway, error) {
	list := slices.DeleteFunc(c.GatewayList, func(gateway *gatewayv1.Gateway) bool {
		return gateway.Spec.GatewayClassName != "haproxy"
	})
	return list, nil
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

// GetEndpointSlices ...
func (c *CacheMock) GetEndpointSlices(service *api.Service) ([]*discoveryv1.EndpointSlice, error) {
	serviceName := service.Namespace + "/" + service.Name
	if eps, found := c.EpsList[serviceName]; found {
		return eps, nil
	}
	return nil, fmt.Errorf("could not find endpointslices for service '%s'", serviceName)
}

// GetConfigMap ...
func (c *CacheMock) GetConfigMap(configMapName string) (*api.ConfigMap, error) {
	if configMap, found := c.ConfigMapList[configMapName]; found {
		return configMap, nil
	}
	return nil, fmt.Errorf("configmap not found: %s", configMapName)
}

// GetNamespace ...
func (c *CacheMock) GetNamespace(name string) (*api.Namespace, error) {
	if ns, found := c.NsList[name]; found {
		return ns, nil
	}
	return nil, fmt.Errorf("namespace not found: %s", name)
}

// GetControllerPodList ...
func (c *CacheMock) GetControllerPodList() ([]api.Pod, error) {
	return nil, nil
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
func (c *CacheMock) GetControllerPod() types.NamespacedName {
	return types.NamespacedName{Namespace: "ingress-controller", Name: "haproxy-ingress-srv1"}
}

// GetTLSSecretPath ...
func (c *CacheMock) GetTLSSecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (convtypes.CrtFile, error) {
	fullname := c.buildResourceName(defaultNamespace, secretName)
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, fullname)
	if path, found := c.SecretTLSPath[fullname]; found {
		return convtypes.CrtFile{
			Filename:    path,
			SHA1Hash:    fmt.Sprintf("%x", sha1.Sum([]byte(path))),
			Certificate: &x509.Certificate{},
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

// UpdateStatus ...
func (c *CacheMock) UpdateStatus(namedObj client.Object, apply func() bool, opt ...convtypes.CacheOptions) error {
	switch obj := namedObj.(type) {
	case *gatewayv1.GatewayClass:
		if gc, found := c.GatewayClassMap[gatewayv1.ObjectName(obj.Name)]; found {
			*obj = *gc
			if apply() {
				*gc = *obj
			}
		}
	case *gatewayv1.Gateway:
		if i := slices.IndexFunc(c.GatewayList, func(gw *gatewayv1.Gateway) bool { return gw.Namespace == obj.Namespace && gw.Name == obj.Name }); i >= 0 {
			*obj = *c.GatewayList[i]
			if apply() {
				*c.GatewayList[i] = *obj
			}
		}
	case *gatewayv1.HTTPRoute:
		if i := slices.IndexFunc(c.HTTPRouteList, func(route *gatewayv1.HTTPRoute) bool {
			return route.Namespace == obj.Namespace && route.Name == obj.Name
		}); i >= 0 {
			*obj = *c.HTTPRouteList[i]
			if apply() {
				*c.HTTPRouteList[i] = *obj
			}
		}
	case *gatewayv1alpha2.TLSRoute:
	case *gatewayv1alpha2.TCPRoute:
	default:
		return fmt.Errorf("unknown object type: (%T) %s/%s", namedObj, namedObj.GetNamespace(), namedObj.GetName())
	}
	return nil
}

// LegacySwapObjects ...
func (c *CacheMock) LegacySwapObjects() *convtypes.ChangedObjects {
	changed := c.Changed
	c.Changed = &convtypes.ChangedObjects{
		GlobalConfigMapDataCur: changed.GlobalConfigMapDataNew,
		TCPConfigMapDataCur:    changed.TCPConfigMapDataNew,
		Links:                  make(convtypes.TrackingLinks),
	}
	// update changed.Links based on notifications
	addChanges := func(ctx convtypes.ResourceType, ns, n string) {
		fullname := n
		if ns != "" {
			fullname = ns + "/" + n
		}
		tracker.TrackChanges(changed.Links, ctx, fullname)
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

	// TODO: Always adding the same list, like "everybody changed". Need a refactor to work
	// based on change notification, and after that, remove the remaining Ingress* fields
	// from ChangedObjects. A k8s fake client should be a good approach. Better to make this
	// change after cache intf refactor to better reflect controller-runtime's client intf.
	for _, gwcls := range c.GatewayClassMap {
		addChanges(convtypes.ResourceGatewayClass, "", gwcls.Name)
	}
	for _, gw := range c.GatewayList {
		addChanges(convtypes.ResourceGateway, gw.Namespace, gw.Name)
	}

	return changed
}

// NeedFullSync ...
func (c *CacheMock) NeedFullSync() bool {
	return false
}
