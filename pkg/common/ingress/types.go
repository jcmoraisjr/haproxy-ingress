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
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/agentcheck"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/alias"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/healthcheck"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/hsts"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxybackend"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/secureupstream"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/snippet"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/sslpassthrough"

	"github.com/spf13/pflag"

	apiv1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apiserver/pkg/server/healthz"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/auth"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/authreq"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/authtls"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/bluegreen"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/connection"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/cors"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/ipwhitelist"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/oauth"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/ratelimit"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/redirect"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/rewrite"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/waf"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/store"
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

	// OnUpdate callback invoked from the sync queue https://k8s.io/ingress/core/blob/master/pkg/ingress/controller/controller.go#L387
	// when an update occurs. This is executed frequently because Ingress
	// controllers watches changes in:
	// - Ingresses: main work
	// - Secrets: referenced from Ingress rules with TLS configured
	// - ConfigMaps: where the controller reads custom configuration
	// - Services: referenced from Ingress rules and required to obtain
	//	 information about ports and annotations
	// - Endpoints: referenced from Services and what the backend uses
	//	 to route traffic
	// Any update to services, endpoints, secrets (only those referenced from Ingress)
	// and ingress trigger the execution.
	// Notifications of type Add, Update and Delete:
	// https://github.com/kubernetes/kubernetes/blob/master/pkg/client/cache/controller.go#L164
	//
	// Configuration returns the translation from Ingress rules containing
	// information about all the upstreams (service endpoints ) "virtual"
	// servers (FQDN) and all the locations inside each server. Each
	// location contains information about all the annotations were configured
	// https://k8s.io/ingress/core/blob/master/pkg/ingress/types.go#L83
	// The backend returns an error if was not possible to update the configuration.
	//
	OnUpdate(Configuration) error
	// SyncIngress sync load balancer config from a very early stage
	SyncIngress(item interface{}) error
	// ConfigMap content of --configmap
	SetConfig(*apiv1.ConfigMap)
	// SetListers allows the access of store listers present in the generic controller
	// This avoid the use of the kubernetes client.
	SetListers(*StoreLister)
	// BackendDefaults returns the minimum settings required to configure the
	// communication to endpoints
	BackendDefaults() defaults.Backend
	// Info returns information about the ingress controller
	Info() *BackendInfo
	// ConfigureFlags allow to configure more flags before the parsing of
	// command line arguments
	ConfigureFlags(*pflag.FlagSet)
	// OverrideFlags allow the customization of the flags in the backend
	OverrideFlags(*pflag.FlagSet)
	// DefaultIngressClass just return the default ingress class
	DefaultIngressClass() string
	// UpdateIngressStatus custom callback used to update the status in an Ingress rule
	// This allows custom implementations
	// If the function returns nil the standard functions will be executed.
	UpdateIngressStatus(*extensions.Ingress) []apiv1.LoadBalancerIngress
	// DefaultEndpoint returns the Endpoint to use as default when the
	// referenced service does not exists. This should return the content
	// of to the default backend
	DefaultEndpoint() Endpoint
	// Indicates whether or not this controller supports a "drain" mode where unavailable
	// and terminating pods are included in the list of returned pods and used to direct
	// certain traffic (e.g., traffic using persistence) to terminating/unavailable pods.
	DrainSupport() bool
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

// Configuration holds the definition of all the parts required to describe all
// ingresses reachable by the ingress controller (using a filter by namespace)
type Configuration struct {
	// Backends are a list of backends used by all the Ingress rules in the
	// ingress controller. This list includes the default backend
	Backends []*Backend `json:"backends,omitEmpty"`
	// Servers
	Servers []*Server `json:"servers,omitEmpty"`
	// TCPEndpoints contain endpoints for tcp streams handled by this backend
	// +optional
	TCPEndpoints []L4Service `json:"tcpEndpoints,omitempty"`
	// UDPEndpoints contain endpoints for udp streams handled by this backend
	// +optional
	UDPEndpoints []L4Service `json:"udpEndpoints,omitempty"`
	// PassthroughBackend contains the backends used for SSL passthrough.
	// It contains information about the associated Server Name Indication (SNI).
	// +optional
	PassthroughBackends []*SSLPassthroughBackend `json:"passthroughBackends,omitempty"`
}

// Backend describes one or more remote server/s (endpoints) associated with a service
// +k8s:deepcopy-gen=true
type Backend struct {
	// Name represents an unique apiv1.Service name formatted as <namespace>-<name>-<port>
	Name    string             `json:"name"`
	Service *apiv1.Service     `json:"service,omitempty"`
	Port    intstr.IntOrString `json:"port"`
	// Secure indicates if the communication protocol between the backend and the endpoint
	// is HTTP or HTTPS and also an optional client certificate for TLS authentication and
	// the certificate authority bundle to validate server certificate. The endpoint/s must
	// provide a TLS connection.
	Secure secureupstream.Secure `json:"secure"`
	// SSLPassthrough indicates that Ingress controller will delegate TLS termination to the endpoints.
	SSLPassthrough bool `json:"sslPassthrough"`
	// Endpoints contains the list of endpoints currently running
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// StickySessionAffinitySession contains the StickyConfig object with stickiness configuration
	SessionAffinity SessionAffinityConfig `json:"sessionAffinityConfig"`
	// BalanceAlgorithm has the per backend load balancing algorithm
	BalanceAlgorithm string `json:"balanceAlgorithm"`
	// SlotsIncrement defines the size of the increment when the number of servers of the backend need to grow
	SlotsIncrement int `json:"slotsIncrement"`
	// BlueGreen has the blue/green deployment configuration
	BlueGreen bluegreen.Config `json:"blueGreen"`
	// Proxy has proxy configurations used on the backend, eg version of the proxy protocol
	Proxy proxybackend.Config `json:"proxyBackend"`
	// ConfigurationSnippet contains additional configuration to be considered in the backend configuration
	ConfigurationSnippet snippet.Config `json:"configurationSnippet"`
	// Connection has backend or server connection limits and timeouts
	Connection connection.Config `json:"connection"`
	// Consistent hashing by NGINX variable
	UpstreamHashBy string `json:"upstream-hash-by,omitempty"`
	// Haproxy DNS resolver
	UseResolver string `json:"useResolver"`
	// Health check configuration for the back end
	HealthCheck healthcheck.Config `json:"healthCheck"`
	// Agent check configuration for the back end
	AgentCheck agentcheck.Config `json:"agentCheck"`
}

// SessionAffinityConfig describes different affinity configurations for new sessions.
// Once a session is mapped to a backend based on some affinity setting, it
// retains that mapping till the backend goes down, or the ingress controller
// restarts. Exactly one of these values will be set on the upstream, since multiple
// affinity values are incompatible. Once set, the backend makes no guarantees
// about honoring updates.
// +k8s:deepcopy-gen=true
type SessionAffinityConfig struct {
	AffinityType          string                `json:"name"`
	CookieSessionAffinity CookieSessionAffinity `json:"cookieSessionAffinity"`
}

// CookieSessionAffinity defines the structure used in Affinity configured by Cookies.
// +k8s:deepcopy-gen=true
type CookieSessionAffinity struct {
	Name      string              `json:"name"`
	Strategy  string              `json:"strategy"`
	Hash      string              `json:"hash"`
	Dynamic   bool                `json:"dynamic"`
	Locations map[string][]string `json:"locations,omitempty"`
}

// Endpoint describes a kubernetes endpoint in a backend
// +k8s:deepcopy-gen=true
type Endpoint struct {
	// Address IP address of the endpoint
	Address string `json:"address"`
	// Port number of the TCP port
	Port string `json:"port"`
	// Weight is the blue/green deployment weight this endpoint should
	// configure. It represents the proportional load this endpoint
	// should receive relative to the sum of all weights. A value of
	// zero means the server will not receive any request.
	// Note that this is a per-endpoint configuration, so different
	// number of replicas need to be adjusted accordingly.
	Weight    int `json:"weight"`
	WeightRef *bluegreen.DeployWeight
	// Indicates whether or not this endpoint is currently draining (not available
	// or terminating). This is a transient value that configures Weight as zero.
	Draining bool `json:"draining"`
	// Target returns a reference to the object providing the endpoint
	Target *apiv1.ObjectReference `json:"target,omitempty"`
}

// Server describes a website
type Server struct {
	// Hostname returns the FQDN of the server
	Hostname string `json:"hostname"`
	// SSLPassthrough indicates if the TLS termination is realized in
	// the server or in the remote endpoint
	SSLPassthrough sslpassthrough.Config `json:"sslPassthrough"`
	// SSLCertificate path to the SSL certificate on disk
	SSLCertificate string `json:"sslCertificate"`
	// SSLExpireTime has the expire date of this certificate
	SSLExpireTime time.Time `json:"sslExpireTime"`
	// SSLPemChecksum returns the checksum of the certificate file on disk.
	// There is no restriction in the hash generator. This checksim can be
	// used to  determine if the secret changed without the use of file
	// system notifications
	SSLPemChecksum string `json:"sslPemChecksum"`
	// Locations list of URIs configured in the server.
	Locations []*Location `json:"locations,omitempty"`
	// Alias return the alias of the server name
	Alias alias.Config `json:"alias,omitempty"`
	// RedirectFromToWWW returns if a redirect to/from prefix www is required
	RedirectFromToWWW bool `json:"redirectFromToWWW,omitempty"`
	// CertificateAuth indicates the this server requires mutual authentication
	// +optional
	CertificateAuth authtls.AuthSSLConfig `json:"certificateAuth"`

	// ServerSnippet returns the snippet of server
	// +optional
	ServerSnippet string `json:"serverSnippet"`
}

// Location describes an URI inside a server.
// Also contains additional information about annotations in the Ingress.
//
// Important:
// The implementation of annotations is optional
//
// In some cases when more than one annotations is defined a particular order in the execution
// is required.
// The chain in the execution order of annotations should be:
// - Whitelist
// - RateLimit
// - BasicDigestAuth
// - ExternalAuth
// - Redirect
type Location struct {
	// Path is an extended POSIX regex as defined by IEEE Std 1003.1,
	// (i.e this follows the egrep/unix syntax, not the perl syntax)
	// matched against the path of an incoming request. Currently it can
	// contain characters disallowed from the conventional "path"
	// part of a URL as defined by RFC 3986. Paths must begin with
	// a '/'. If unspecified, the path defaults to a catch all sending
	// traffic to the backend.
	Path string `json:"path"`
	// IsDefBackend indicates if service specified in the Ingress
	// contains active endpoints or not. Returning true means the location
	// uses the default backend.
	IsDefBackend bool `json:"isDefBackend"`
	// Ingress returns the ingress from which this location was generated
	Ingress *extensions.Ingress `json:"ingress"`
	// Backend describes the name of the backend to use.
	Backend string `json:"backend"`
	// HTTPPassBackend describes the optional name of the plain http backend of a ssl passthrough server.
	HTTPPassBackend string `json:"httpPassBackend"`
	// Service describes the referenced services from the ingress
	Service *apiv1.Service `json:"service,omitempty"`
	// Port describes to which port from the service
	Port intstr.IntOrString `json:"port"`
	// Overwrite the Host header passed into the backend. Defaults to
	// vhost of the incoming request.
	// +optional
	UpstreamVhost string `json:"upstream-vhost"`
	// BasicDigestAuth returns authentication configuration for
	// an Ingress rule.
	// +optional
	BasicDigestAuth auth.BasicDigest `json:"basicDigestAuth,omitempty"`
	// Denied returns an error when this location cannot not be allowed
	// Requesting a denied location should return HTTP code 403.
	Denied error `json:"denied,omitempty"`
	// HSTS defines per Location HTTP Strict Transport Security
	HSTS hsts.Config `json:"hsts,omitempty"`
	// CorsConfig returns the Cors Configration for the ingress rule
	// +optional
	CorsConfig cors.CorsConfig `json:"corsConfig,omitempty"`
	// ExternalAuth indicates the access to this location requires
	// authentication using an external provider
	// +optional
	ExternalAuth authreq.External `json:"externalAuth,omitempty"`
	// OAuth has external oauth configuration
	OAuth oauth.Config `json:"oauth,omitempty"`
	// RateLimit describes a limit in the number of connections per IP
	// address or connections per second.
	// The Redirect annotation precedes RateLimit
	// +optional
	RateLimit ratelimit.RateLimit `json:"rateLimit,omitempty"`
	// Redirect describes a temporal o permanent redirection this location.
	// +optional
	Redirect redirect.Redirect `json:"redirect,omitempty"`
	// Rewrite describes the redirection this location.
	// +optional
	Rewrite rewrite.Redirect `json:"rewrite,omitempty"`
	// Whitelist indicates only connections from certain client
	// addresses or networks are allowed.
	// +optional
	Whitelist ipwhitelist.SourceRange `json:"whitelist,omitempty"`
	// Proxy contains information about timeouts and buffer sizes
	// to be used in connections against endpoints
	// +optional
	Proxy proxy.Configuration `json:"proxy,omitempty"`
	// UsePortInRedirects indicates if redirects must specify the port
	// +optional
	UsePortInRedirects bool `json:"usePortInRedirects"`
	// VtsFilterKey contains the vts filter key on the location level
	// https://github.com/vozlt/nginx-module-vts#vhost_traffic_status_filter_by_set_key
	// +optional
	VtsFilterKey string `json:"vtsFilterKey,omitempty"`
	// WAF has per location web application firewall configs
	WAF waf.Config `json:"waf"`
	// ConfigurationSnippet contains additional configuration for the backend
	// to be considered in the configuration of the location
	ConfigurationSnippet snippet.Config `json:"configurationSnippet"`
	// ClientBodyBufferSize allows for the configuration of the client body
	// buffer size for a specific location.
	// +optional
	ClientBodyBufferSize string `json:"clientBodyBufferSize,omitempty"`
	// DefaultBackend allows the use of a custom default backend for this location.
	// +optional
	DefaultBackend *apiv1.Service `json:"defaultBackend,omitempty"`
}

// SSLPassthroughBackend describes a SSL upstream server configured
// as passthrough (no TLS termination in the ingress controller)
// The endpoints must provide the TLS termination exposing the required SSL certificate.
// The ingress controller only pipes the underlying TCP connection
type SSLPassthroughBackend struct {
	Service *apiv1.Service     `json:"service,omitEmpty"`
	Port    intstr.IntOrString `json:"port"`
	// Backend describes the endpoints to use.
	Backend string `json:"namespace,omitempty"`
	// HTTPPassBackend describes the optional name of the plain http backend of a ssl passthrough server.
	HTTPPassBackend string `json:"httpPassBackend"`
	// Hostname returns the FQDN of the server
	Hostname string `json:"hostname"`
}

// L4Service describes a L4 Ingress service.
type L4Service struct {
	// Port external port to expose
	Port int `json:"port"`
	// Backend of the service
	Backend L4Backend `json:"backend"`
	// Endpoints active endpoints of the service
	Endpoints []Endpoint `json:"endpoins,omitEmpty"`
}

// L4Backend describes the kubernetes service behind L4 Ingress service
type L4Backend struct {
	Port      intstr.IntOrString `json:"port"`
	Name      string             `json:"name"`
	Namespace string             `json:"namespace"`
	Protocol  apiv1.Protocol     `json:"protocol"`
	// +optional
	ProxyProtocol ProxyProtocol `json:"proxyProtocol"`
	SSLCert       SSLCert       `json:"sslCert"`
}

// ProxyProtocol describes if the proxy protocol should be configured
// on decoding (receiving a connection from a client) and encoding (send
// a connection to a backend service). If EncodeVersion is empty, proxy
// protocol should not be used
type ProxyProtocol struct {
	Decode        bool   `json:"decode"`
	EncodeVersion string `json:"encode"`
}
