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

package types

import (
	"net"
	"time"

	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1alpha1"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Cache ...
type Cache interface {
	ExternalNameLookup(externalName string) ([]net.IP, error)
	GetIngress(ingressName string) (*networking.Ingress, error)
	GetIngressList() ([]*networking.Ingress, error)
	GetIngressClass(className string) (*networking.IngressClass, error)
	GetGateway(gatewayName string) (*gateway.Gateway, error)
	GetGatewayList() ([]*gateway.Gateway, error)
	GetHTTPRouteList(namespace string, match map[string]string) ([]*gateway.HTTPRoute, error)
	GetService(defaultNamespace, serviceName string) (*api.Service, error)
	GetEndpoints(service *api.Service) (*api.Endpoints, error)
	GetConfigMap(configMapName string) (*api.ConfigMap, error)
	GetTerminatingPods(service *api.Service, track TrackingTarget) ([]*api.Pod, error)
	GetPod(podName string) (*api.Pod, error)
	GetPodNamespace() string
	GetTLSSecretPath(defaultNamespace, secretName string, track TrackingTarget) (CrtFile, error)
	GetCASecretPath(defaultNamespace, secretName string, track TrackingTarget) (ca, crl File, err error)
	GetDHSecretPath(defaultNamespace, secretName string) (File, error)
	GetPasswdSecretContent(defaultNamespace, secretName string, track TrackingTarget) ([]byte, error)
	SwapChangedObjects() *ChangedObjects
	GetEndpointSlices(service *api.Service) ([]*discoveryv1.EndpointSlice, error)
}

// ChangedObjects ...
type ChangedObjects struct {
	//
	GlobalConfigMapDataCur, GlobalConfigMapDataNew map[string]string
	//
	TCPConfigMapDataCur, TCPConfigMapDataNew map[string]string
	//
	IngressesDel, IngressesUpd, IngressesAdd []*networking.Ingress
	//
	IngressClassesDel, IngressClassesUpd, IngressClassesAdd []*networking.IngressClass
	//
	GatewaysDel, GatewaysUpd, GatewaysAdd []*gateway.Gateway
	//
	GatewayClassesDel, GatewayClassesUpd, GatewayClassesAdd []*gateway.GatewayClass
	//
	HTTPRoutesDel, HTTPRoutesUpd, HTTPRoutesAdd []*gateway.HTTPRoute
	//
	TLSRoutesDel, TLSRoutesUpd, TLSRoutesAdd []*gateway.TLSRoute
	//
	TCPRoutesDel, TCPRoutesUpd, TCPRoutesAdd []*gateway.TCPRoute
	//
	UDPRoutesDel, UDPRoutesUpd, UDPRoutesAdd []*gateway.UDPRoute
	//
	BackendPoliciesDel, BackendPoliciesUpd, BackendPoliciesAdd []*gateway.BackendPolicy
	//
	EndpointsNew []*api.Endpoints
	//
	EndpointSlicesDel, EndpointSlicesUpd, EndpointSlicesAdd []*discoveryv1.EndpointSlice
	//
	ServicesDel, ServicesUpd, ServicesAdd []*api.Service
	//
	SecretsDel, SecretsUpd, SecretsAdd []*api.Secret
	//
	ConfigMapsDel, ConfigMapsUpd, ConfigMapsAdd []*api.ConfigMap
	//
	PodsNew []*api.Pod
	//
	NeedFullSync bool
	//
	Objects []string
}

// Tracker ...
type Tracker interface {
	Track(isMissing bool, track TrackingTarget, rtype ResourceType, name string)
	TrackHostname(rtype ResourceType, name, hostname string)
	TrackBackend(rtype ResourceType, name string, backendID hatypes.BackendID)
	TrackMissingOnHostname(rtype ResourceType, name, hostname string)
	TrackStorage(rtype ResourceType, name, storage string)
	TrackGateway(rtype ResourceType, name string)
	GetDirtyLinks(oldIngressList, addIngressList, oldIngressClassList, addIngressClassList, oldConfigMapList, addConfigMapList, oldServiceList, addServiceList, oldSecretList, addSecretList, addPodList []string) (dirtyIngs, dirtyHosts []string, dirtyBacks []hatypes.BackendID, dirtyUsers, dirtyStorages []string)
	GetGatewayChanged(oldSecretList, addSecretList, oldServiceList, addServiceList []string) bool
	DeleteHostnames(hostnames []string)
	DeleteBackends(backends []hatypes.BackendID)
	DeleteUserlists(userlists []string)
	DeleteStorages(storages []string)
	DeleteGateway()
}

// TrackingTarget ...
type TrackingTarget struct {
	Hostname string
	Backend  hatypes.BackendID
	Userlist string
	Gateway  bool
}

// AnnotationReader ...
type AnnotationReader interface {
	ReadAnnotations(backend *hatypes.Backend, services []*api.Service, pathLinks []hatypes.PathLink)
}

// File ...
type File struct {
	Filename string
	SHA1Hash string
}

// CrtFile ...
type CrtFile struct {
	Filename   string
	SHA1Hash   string
	CommonName string
	NotAfter   time.Time
}

// ResourceType ...
type ResourceType int

const (
	// IngressType ...
	IngressType ResourceType = iota

	// IngressClassType ...
	IngressClassType

	// ConfigMapType ...
	ConfigMapType

	// ServiceType ...
	ServiceType

	// SecretType ...
	SecretType

	// PodType ...
	PodType
)
