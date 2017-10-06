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
	"k8s.io/ingress/core/pkg/ingress"
	"k8s.io/ingress/core/pkg/ingress/annotations/authtls"
	"k8s.io/ingress/core/pkg/ingress/annotations/proxy"
	"k8s.io/ingress/core/pkg/ingress/annotations/ratelimit"
	"k8s.io/ingress/core/pkg/ingress/annotations/redirect"
	"k8s.io/ingress/core/pkg/ingress/annotations/rewrite"
	"k8s.io/ingress/core/pkg/ingress/defaults"
)

type (
	// ControllerConfig has ingress generated and some transformations
	// compatible with HAProxy
	ControllerConfig struct {
		Userlists           map[string]Userlist
		Servers             []*ingress.Server
		Backends            []*ingress.Backend
		DefaultServer       *HAProxyServer
		HAServers           []*HAProxyServer
		TCPEndpoints        []ingress.L4Service
		UDPEndpoints        []ingress.L4Service
		PassthroughBackends []*ingress.SSLPassthroughBackend
		Cfg                 *HAProxyConfig
		BackendSlots        map[string]HAProxyBackendSlots
	}
	// HAProxyConfig has HAProxy specific configurations from ConfigMap
	HAProxyConfig struct {
		defaults.Backend            `json:",squash"`
		SSLCiphers                  string `json:"ssl-ciphers"`
		SSLOptions                  string `json:"ssl-options"`
		SSLDHParam                  `json:",squash"`
		TimeoutHTTPRequest          string `json:"timeout-http-request"`
		TimeoutConnect              string `json:"timeout-connect"`
		TimeoutClient               string `json:"timeout-client"`
		TimeoutClientFin            string `json:"timeout-client-fin"`
		TimeoutServer               string `json:"timeout-server"`
		TimeoutServerFin            string `json:"timeout-server-fin"`
		TimeoutTunnel               string `json:"timeout-tunnel"`
		TimeoutKeepAlive            string `json:"timeout-keep-alive"`
		Syslog                      string `json:"syslog-endpoint"`
		BalanceAlgorithm            string `json:"balance-algorithm"`
		BackendCheckInterval        string `json:"backend-check-interval"`
		Forwardfor                  string `json:"forwardfor"`
		MaxConn                     int    `json:"max-connections"`
		HSTS                        bool   `json:"hsts"`
		HSTSMaxAge                  string `json:"hsts-max-age"`
		HSTSIncludeSubdomains       bool   `json:"hsts-include-subdomains"`
		HSTSPreload                 bool   `json:"hsts-preload"`
		HealthzPort                 int    `json:"healthz-port"`
		HTTPStoHTTPPort             int    `json:"https-to-http-port"`
		StatsPort                   int    `json:"stats-port"`
		StatsAuth                   string `json:"stats-auth"`
		DynamicScaling              bool   `json:"dynamic-scaling"`
		BackendServerSlotsIncrement int    `json:"backend-server-slots-increment"`
		StatsSocket                 string
		UseProxyProtocol            bool   `json:"use-proxy-protocol"`
		StatsProxyProtocol          bool   `json:"stats-proxy-protocol"`
		HTTPLogFormat               string `json:"http-log-format"`
		TCPLogFormat                string `json:"tcp-log-format"`
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
		IsDefaultServer bool                  `json:"isDefaultServer"`
		UseHTTP         bool                  `json:"useHTTP"`
		UseHTTPS        bool                  `json:"useHTTPS"`
		Hostname        string                `json:"hostname"`
		HostnameLabel   string                `json:"hostnameLabel"`
		SSLCertificate  string                `json:"sslCertificate"`
		SSLPemChecksum  string                `json:"sslPemChecksum"`
		RootLocation    *HAProxyLocation      `json:"defaultLocation"`
		Locations       []*HAProxyLocation    `json:"locations,omitempty"`
		SSLRedirect     bool                  `json:"sslRedirect"`
		HasRateLimit    bool                  `json:"hasRateLimit"`
		CertificateAuth authtls.AuthSSLConfig `json:"certificateAuth,omitempty"`
		Alias           string                `json:"alias,omitempty"`
	}
	// HAProxyLocation has location data as a HAProxy friendly syntax
	HAProxyLocation struct {
		IsRootLocation       bool                 `json:"isDefaultLocation"`
		Path                 string               `json:"path"`
		Backend              string               `json:"backend"`
		Rewrite              rewrite.Redirect     `json:"rewrite,omitempty"`
		Redirect             redirect.Redirect    `json:"redirect,omitempty"`
		Userlist             Userlist             `json:"userlist,omitempty"`
		Proxy                *proxy.Configuration `json:"proxy,omitempty"`
		RateLimit            ratelimit.RateLimit  `json:"rateLimit,omitempty"`
		HAMatchPath          string               `json:"haMatchPath"`
		HAWhitelist          string               `json:"whitelist,omitempty"`
		HARateLimitWhiteList string               `json:"rateLimitWhiteList,omitempty"`
	}
	// HAProxyBackendSlots contains used and empty backend server definitions
	HAProxyBackendSlots struct {
		// map from ip:port to server name
		FullSlots map[string]HAProxyBackendSlot
		// list of unused server names
		EmptySlots []string
	}
	// HAProxyBackendSlot combines BackendServerName with an ingress.Endpoint
	HAProxyBackendSlot struct {
		BackendServerName string
		BackendEndpoint   *ingress.Endpoint
	}
)
