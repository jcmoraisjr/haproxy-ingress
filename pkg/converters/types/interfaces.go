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
	GetTerminatingPods(service *api.Service, track []TrackingRef) ([]*api.Pod, error)
	GetPod(podName string) (*api.Pod, error)
	GetPodNamespace() string
	GetTLSSecretPath(defaultNamespace, secretName string, track []TrackingRef) (CrtFile, error)
	GetCASecretPath(defaultNamespace, secretName string, track []TrackingRef) (ca, crl File, err error)
	GetDHSecretPath(defaultNamespace, secretName string) (File, error)
	GetPasswdSecretContent(defaultNamespace, secretName string, track []TrackingRef) ([]byte, error)
	SwapChangedObjects() *ChangedObjects
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
	Links   TrackingLinks
}

// ResourceType ...
type ResourceType string

// ...
const (
	ResourceIngress      ResourceType = "Ingress"
	ResourceIngressClass ResourceType = "IngressClass"

	ResourceGateway       ResourceType = "Gateway"
	ResourceGatewayClass  ResourceType = "GatewayClass"
	ResourceHTTPRoute     ResourceType = "HTTPRoute"
	ResourceTLSRoute      ResourceType = "TLSRoute"
	ResourceTCPRoute      ResourceType = "TCPRoute"
	ResourceUDPRoute      ResourceType = "UDPRoute"
	ResourceBackendPolicy ResourceType = "BackendPolicy"

	ResourceConfigMap ResourceType = "ConfigMap"
	ResourceService   ResourceType = "Service"
	ResourceSecret    ResourceType = "Secret"
	ResourcePod       ResourceType = "Pod"

	ResourceHAHostname ResourceType = "HAHostname"
	ResourceHABackend  ResourceType = "HABackend"
	ResourceHAUserlist ResourceType = "HAUserlist"

	ResourceAcmeData ResourceType = "AcmeData"
)

// TrackingRef ...
type TrackingRef struct {
	Context    ResourceType
	UniqueName string
}

// TrackingLinks ...
type TrackingLinks map[ResourceType][]string

// Tracker ...
type Tracker interface {
	TrackNames(leftContext ResourceType, leftName string, rightContext ResourceType, rightName string)
	TrackRefName(left []TrackingRef, rightContext ResourceType, rightName string)
	TrackRefs(left, right TrackingRef)
	QueryLinks(input TrackingLinks, removeMatches bool) TrackingLinks
	ClearLinks()
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
