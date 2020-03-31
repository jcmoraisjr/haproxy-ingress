/*
Copyright 2016 The Kubernetes Authors.

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

package ingress

import (
	"fmt"
	
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/store"

	"github.com/spf13/pflag"
	apiv1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apiserver/pkg/server/healthz"
)

var (
	// DefaultSSLDirectory defines the location where the SSL certificates will be generated
	// This directory contains all the SSL certificates that are specified in Ingress rules.
	// The name of each file is <namespace>-<secret name>.pem. The content is the concatenated
	// certificate and key.
	DefaultSSLDirectory     = "/ingress-controller/ssl"
	DefaultCACertsDirectory = "/ingress-controller/cacerts"
	DefaultCrlDirectory     = "/ingress-controller/crl"
)

// Controller holds the methods to handle an Ingress backend
// TODO (#18): Make sure this is sufficiently supportive of other backends.
type Controller interface {
	// HealthChecker returns is a named healthz check that returns the ingress
	// controller status
	healthz.HealthChecker
	// SyncIngress sync load balancer config from a very early stage
	SyncIngress(item interface{}) error
	// ConfigMap content of --configmap
	SetConfig(*apiv1.ConfigMap)
	// SetListers allows the access of store listers present in the generic controller
	// This avoid the use of the kubernetes client.
	SetListers(*StoreLister)
	// Info returns information about the ingress controller
	Info() *BackendInfo
	// AcmeCheck starts a certificate missing/expiring/outdated check
	AcmeCheck() (int, error)
	// ConfigureFlags allow to configure more flags before the parsing of
	// command line arguments
	ConfigureFlags(*pflag.FlagSet)
	// OverrideFlags allow the customization of the flags in the backend
	OverrideFlags(*pflag.FlagSet)
	// UpdateIngressStatus custom callback used to update the status in an Ingress rule
	// This allows custom implementations
	// If the function returns nil the standard functions will be executed.
	UpdateIngressStatus(*extensions.Ingress) []apiv1.LoadBalancerIngress
}

// StoreLister returns the configured stores for ingresses, services,
// endpoints, secrets and configmaps.
type StoreLister struct {
	Ingress   store.IngressLister
	Service   store.ServiceLister
	Node      store.NodeLister
	Endpoint  store.EndpointLister
	Secret    store.SecretLister
	ConfigMap store.ConfigMapLister
	Pod       store.PodLister
}

// BackendInfo returns information about the backend.
// This fields contains information that helps to track issues or to
// map the running ingress controller to source code
type BackendInfo struct {
	// Name returns the name of the backend implementation
	Name string `json:"name"`
	// Release returns the running version (semver)
	Release string `json:"release"`
	// Build returns information about the git commit
	Build string `json:"build"`
	// Repository return information about the git repository
	Repository string `json:"repository"`
}

func (bi BackendInfo) String() string {
	return fmt.Sprintf(`
Name:       %v
Release:    %v
Build:      %v
Repository: %v
`, bi.Name, bi.Release, bi.Build, bi.Repository)
}
