/*
Copyright 2017 The Kubernetes Authors.

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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/authtls"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/cors"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/dnsresolvers"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/hsts"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/oauth"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/ratelimit"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/redirect"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/rewrite"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/waf"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
)

type (
	// ControllerConfig has ingress generated and some transformations
	// compatible with HAProxy
	ControllerConfig struct {
		ConfigFrontend      []string
		Userlists           map[string]Userlist
		Servers             []*ingress.Server
		Backends            []*ingress.Backend
		DefaultServer       *HAProxyServer
		HAServers           []*HAProxyServer
		TCPEndpoints        []ingress.L4Service
		UDPEndpoints        []ingress.L4Service
		PassthroughBackends []*ingress.SSLPassthroughBackend
		HAPassthrough       []*HAProxyPassthrough
		StatsSSLCert        *ingress.SSLCert
		Cfg                 *HAProxyConfig
		BackendSlots        map[string]*HAProxyBackendSlots
		DNSResolvers        map[string]dnsresolvers.DNSResolver
		Procs               *HAProxyProcs
	}
	// HAProxyConfig has HAProxy specific configurations from ConfigMap
	HAProxyConfig struct {
		defaults.Backend       `json:",squash"`
		SSLCiphers             string `json:"ssl-ciphers"`
		SSLOptions             string `json:"ssl-options"`
		SSLDHParam             `json:",squash"`
		NbprocBalance          int    `json:"nbproc-balance"`
		NbprocSSL              int    `json:"nbproc-ssl"`
		Nbthread               int    `json:"nbthread"`
		LoadServerState        bool   `json:"load-server-state"`
		TimeoutHTTPRequest     string `json:"timeout-http-request"`
		TimeoutConnect         string `json:"timeout-connect"`
		TimeoutClient          string `json:"timeout-client"`
		TimeoutClientFin       string `json:"timeout-client-fin"`
		TimeoutServer          string `json:"timeout-server"`
		TimeoutQueue           string `json:"timeout-queue"`
		TimeoutServerFin       string `json:"timeout-server-fin"`
		TimeoutStop            string `json:"timeout-stop"`
		TimeoutTunnel          string `json:"timeout-tunnel"`
		TimeoutKeepAlive       string `json:"timeout-keep-alive"`
		BindIPAddrTCP          string `json:"bind-ip-addr-tcp"`
		BindIPAddrHTTP         string `json:"bind-ip-addr-http"`
		BindIPAddrStats        string `json:"bind-ip-addr-stats"`
		BindIPAddrHealthz      string `json:"bind-ip-addr-healthz"`
		Syslog                 string `json:"syslog-endpoint"`
		ModSecurity            string `json:"modsecurity-endpoints"`
		BackendCheckInterval   string `json:"backend-check-interval"`
		ConfigFrontend         string `json:"config-frontend"`
		Forwardfor             string `json:"forwardfor"`
		MaxConn                int    `json:"max-connections"`
		NoTLSRedirect          string `json:"no-tls-redirect-locations"`
		SSLHeadersPrefix       string `json:"ssl-headers-prefix"`
		HealthzPort            int    `json:"healthz-port"`
		HTTPStoHTTPPort        int    `json:"https-to-http-port"`
		StatsPort              int    `json:"stats-port"`
		StatsAuth              string `json:"stats-auth"`
		StatsSSLCert           string `json:"stats-ssl-cert"`
		CookieKey              string `json:"cookie-key"`
		StrictHost             bool   `json:"strict-host"`
		DynamicScaling         bool   `json:"dynamic-scaling"`
		StatsSocket            string
		UseProxyProtocol       bool   `json:"use-proxy-protocol"`
		StatsProxyProtocol     bool   `json:"stats-proxy-protocol"`
		UseHostOnHTTPS         bool   `json:"use-host-on-https"`
		HTTPPort               int    `json:"http-port"`
		HTTPLogFormat          string `json:"http-log-format"`
		HTTPSPort              int    `json:"https-port"`
		HTTPSLogFormat         string `json:"https-log-format"`
		TCPLogFormat           string `json:"tcp-log-format"`
		DrainSupport           bool   `json:"drain-support"`
		DNSResolvers           string `json:"dns-resolvers"`
		DNSTimeoutRetry        string `json:"dns-timeout-retry"`
		DNSHoldObsolete        string `json:"dns-hold-obsolete"`
		DNSHoldValid           string `json:"dns-hold-valid"`
		DNSAcceptedPayloadSize int    `json:"dns-accepted-payload-size"`
		DNSClusterDomain       string `json:"dns-cluster-domain"`
	}
	// Userlist list of users for basic authentication
	Userlist struct {
		ListName string
		Realm    string
		Users    []AuthUser
	}
	// AuthUser authorization info for basic authentication
	AuthUser struct {
		Username  string
		Password  string
		Encrypted bool
	}
	// SSLDHParam Diffie-Hellman related options
	SSLDHParam struct {
		DefaultMaxSize int    `json:"ssl-dh-default-max-size"`
		SecretName     string `json:"ssl-dh-param"`
		Filename       string
		PemSHA         string
	}
	// HAProxyServer and HAProxyLocation build some missing pieces
	// from ingress.Server used by HAProxy
	HAProxyServer struct {
		IsDefaultServer    bool                  `json:"isDefaultServer"`
		IsCACert           bool                  `json:"isCACert"`
		UseHTTP            bool                  `json:"useHTTP"`
		UseHTTPS           bool                  `json:"useHTTPS"`
		Hostname           string                `json:"hostname"`
		HostnameIsWildcard bool                  `json:"hostnameIsWildcard"`
		HostnameLabel      string                `json:"hostnameLabel"`
		HostnameSocket     string                `json:"hostnameSocket"`
		ACLLabel           string                `json:"aclLabel"`
		SSLCertificate     string                `json:"sslCertificate"`
		SSLPemChecksum     string                `json:"sslPemChecksum"`
		RootLocation       *HAProxyLocation      `json:"defaultLocation"`
		Locations          []*HAProxyLocation    `json:"locations,omitempty"`
		SSLRedirect        bool                  `json:"sslRedirect"`
		HSTS               *hsts.Config          `json:"hsts"`
		CORS               *cors.CorsConfig      `json:"cors"`
		WAF                *waf.Config           `json:"waf"`
		HasRateLimit       bool                  `json:"hasRateLimit"`
		OAuth              *oauth.Config         `json:"oauth,omitempty"`
		CertificateAuth    authtls.AuthSSLConfig `json:"certificateAuth,omitempty"`
		Alias              string                `json:"alias,omitempty"`
		AliasIsRegex       bool                  `json:"aliasIsRegex"`
	}
	// HAProxyLocation has location data as a HAProxy friendly syntax
	HAProxyLocation struct {
		IsRootLocation       bool                `json:"isRootLocation"`
		IsDefBackend         bool                `json:"isDefBackend"`
		Path                 string              `json:"path"`
		Backend              string              `json:"backend"`
		OAuth                oauth.Config        `json:"oauth"`
		CORS                 cors.CorsConfig     `json:"cors"`
		HSTS                 hsts.Config         `json:"hsts"`
		WAF                  waf.Config          `json:"waf"`
		Rewrite              rewrite.Redirect    `json:"rewrite,omitempty"`
		Redirect             redirect.Redirect   `json:"redirect,omitempty"`
		Userlist             Userlist            `json:"userlist,omitempty"`
		Proxy                proxy.Configuration `json:"proxy,omitempty"`
		RateLimit            ratelimit.RateLimit `json:"rateLimit,omitempty"`
		SSLRedirect          bool                `json:"sslRedirect,omitempty"`
		HAMatchPath          string              `json:"haMatchPath"`
		HAMatchTxnPath       string              `json:"haMatchTxnPath"`
		HAWhitelist          string              `json:"whitelist,omitempty"`
		HARateLimitWhiteList string              `json:"rateLimitWhiteList,omitempty"`
	}
	// HAProxyPassthrough has SSL passthrough configurations
	HAProxyPassthrough struct {
		Hostname           string `json:"hostname"`
		Alias              bool   `json:"alias"`
		ACLLabel           string `json:"aclLabel"`
		Backend            string `json:"backend"`
		HTTPPassBackend    string `json:"httpPassBackend"`
		HostnameIsWildcard bool   `json:"hostnameIsWildcard"`
	}
	// HAProxyBackendSlots contains used and empty backend server definitions
	HAProxyBackendSlots struct {
		// map from ip:port to server name
		Slots []HAProxyBackendSlot
		// resolver name used for this Backend definition
		UseResolver string
		// total slots for backend, even if Slots[] is empty, eg using resolver
		TotalSlots int
	}
	// HAProxyBackendSlot combines BackendServerName with an ingress.Endpoint
	HAProxyBackendSlot struct {
		BackendServerName string
		BackendEndpoint   *ingress.Endpoint
		Target            string
	}
	// HAProxyProcs process and thread related configuration
	HAProxyProcs struct {
		Nbproc          int
		NbprocBalance   int
		NbprocSSL       int
		Nbthread        int
		BindprocBalance string
		BindprocSSL     string
		CPUMap          string
	}
)
