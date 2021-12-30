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

	"github.com/spf13/pflag"
	apiv1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apiserver/pkg/server/healthz"
)

// Default<Type>Directory defines the location where HAProxy Ingress' generated
// files should be created.
//
// These vars are dynamically changed, see launch.go
var (
	DefaultCrtDirectory     = "/var/lib/haproxy/crt"
	DefaultDHParamDirectory = "/var/lib/haproxy/dhparam"
	DefaultCACertsDirectory = "/var/lib/haproxy/cacerts"
	DefaultCrlDirectory     = "/var/lib/haproxy/crl"
	DefaultVarRunDirectory  = "/var/run/haproxy"
	DefaultMapsDirectory    = "/etc/haproxy/maps"
)

// Controller holds the methods to handle an Ingress backend
// TODO (#18): Make sure this is sufficiently supportive of other backends.
type Controller interface {
	// HealthChecker returns is a named healthz check that returns the ingress
	// controller status
	healthz.HealthChecker
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
	UpdateIngressStatus(*networking.Ingress) []apiv1.LoadBalancerIngress
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
