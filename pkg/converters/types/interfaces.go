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
	"time"

	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Cache ...
type Cache interface {
	GetIngress(ingressName string) (*extensions.Ingress, error)
	GetIngressList() ([]*extensions.Ingress, error)
	GetService(serviceName string) (*api.Service, error)
	GetEndpoints(service *api.Service) (*api.Endpoints, error)
	GetTerminatingPods(service *api.Service) ([]*api.Pod, error)
	GetPod(podName string) (*api.Pod, error)
	GetTLSSecretPath(defaultNamespace, secretName string) (CrtFile, error)
	GetCASecretPath(defaultNamespace, secretName string) (ca, crl File, err error)
	GetDHSecretPath(defaultNamespace, secretName string) (File, error)
	GetSecretContent(defaultNamespace, secretName, keyName string) ([]byte, error)
	SwapChangedObjects() *ChangedObjects
	NeedFullSync() bool
}

// ChangedObjects ...
type ChangedObjects struct {
	//
	GlobalCur, GlobalNew map[string]string
	//
	TCPConfigMapCur, TCPConfigMapNew map[string]string
	//
	IngressesDel, IngressesUpd, IngressesAdd []*extensions.Ingress
	//
	Endpoints []*api.Endpoints
	//
	ServicesDel, ServicesUpd, ServicesAdd []*api.Service
	//
	SecretsDel, SecretsUpd, SecretsAdd []*api.Secret
	//
	Pods []*api.Pod
}

// Tracker ...
type Tracker interface {
	TrackHostname(rtype ResourceType, name, hostname string)
	TrackBackend(rtype ResourceType, name string, backendID hatypes.BackendID)
	TrackMissingOnHostname(rtype ResourceType, name, hostname string)
	GetDirtyLinks(oldIngressList, oldServiceList, addServiceList, oldSecretList, addSecretList []string) (dirtyIngs, dirtyHosts []string, dirtyBacks []hatypes.BackendID)
	DeleteHostnames(hostnames []string)
	DeleteBackends(backends []hatypes.BackendID)
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

	// ServiceType ...
	ServiceType

	// SecretType ...
	SecretType
)
