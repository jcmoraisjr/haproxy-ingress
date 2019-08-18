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

// ConfigGlobals ...
type ConfigGlobals struct {
	BindIPAddrHealthz            string `json:"bind-ip-addr-healthz"`
	BindIPAddrHTTP               string `json:"bind-ip-addr-http"`
	BindIPAddrStats              string `json:"bind-ip-addr-stats"`
	BindIPAddrTCP                string `json:"bind-ip-addr-tcp"`
	ConfigDefaults               string `json:"config-defaults"`
	ConfigFrontend               string `json:"config-frontend"`
	ConfigGlobal                 string `json:"config-global"`
	CookieKey                    string `json:"cookie-key"`
	DNSAcceptedPayloadSize       int    `json:"dns-accepted-payload-size"`
	DNSClusterDomain             string `json:"dns-cluster-domain"`
	DNSHoldObsolete              string `json:"dns-hold-obsolete"`
	DNSHoldValid                 string `json:"dns-hold-valid"`
	DNSResolvers                 string `json:"dns-resolvers"`
	DNSTimeoutRetry              string `json:"dns-timeout-retry"`
	DrainSupport                 bool   `json:"drain-support"`
	DrainSupportRedispatch       bool   `json:"drain-support-redispatch"`
	Forwardfor                   string `json:"forwardfor"`
	HealthzPort                  int    `json:"healthz-port"`
	HTTPLogFormat                string `json:"http-log-format"`
	HTTPPort                     int    `json:"http-port"`
	HTTPSLogFormat               string `json:"https-log-format"`
	HTTPSPort                    int    `json:"https-port"`
	HTTPStoHTTPPort              int    `json:"https-to-http-port"`
	LoadServerState              bool   `json:"load-server-state"`
	MaxConnections               int    `json:"max-connections"`
	ModsecurityEndpoints         string `json:"modsecurity-endpoints"`
	ModsecurityTimeoutHello      string `json:"modsecurity-timeout-hello"`
	ModsecurityTimeoutIdle       string `json:"modsecurity-timeout-idle"`
	ModsecurityTimeoutProcessing string `json:"modsecurity-timeout-processing"`
	NbprocBalance                int    `json:"nbproc-balance"`
	NbprocSSL                    int    `json:"nbproc-ssl"`
	Nbthread                     int    `json:"nbthread"`
	NoTLSRedirectLocations       string `json:"no-tls-redirect-locations"`
	SSLCiphers                   string `json:"ssl-ciphers"`
	SSLDHDefaultMaxSize          int    `json:"ssl-dh-default-max-size"`
	SSLDHParam                   string `json:"ssl-dh-param"`
	SSLEngine                    string `json:"ssl-engine"`
	SSLHeadersPrefix             string `json:"ssl-headers-prefix"`
	SSLModeAsync                 bool   `json:"ssl-mode-async"`
	SSLOptions                   string `json:"ssl-options"`
	StatsAuth                    string `json:"stats-auth"`
	StatsPort                    int    `json:"stats-port"`
	StatsProxyProtocol           bool   `json:"stats-proxy-protocol"`
	StatsSSLCert                 string `json:"stats-ssl-cert"`
	StrictHost                   bool   `json:"strict-host"`
	SyslogEndpoint               string `json:"syslog-endpoint"`
	SyslogFormat                 string `json:"syslog-format"`
	SyslogTag                    string `json:"syslog-tag"`
	TCPLogFormat                 string `json:"tcp-log-format"`
	TimeoutClient                string `json:"timeout-client"`
	TimeoutClientFin             string `json:"timeout-client-fin"`
	TimeoutConnect               string `json:"timeout-connect"`
	TimeoutHTTPRequest           string `json:"timeout-http-request"`
	TimeoutKeepAlive             string `json:"timeout-keep-alive"`
	TimeoutQueue                 string `json:"timeout-queue"`
	TimeoutServer                string `json:"timeout-server"`
	TimeoutServerFin             string `json:"timeout-server-fin"`
	TimeoutStop                  string `json:"timeout-stop"`
	TimeoutTunnel                string `json:"timeout-tunnel"`
	UseProxyProtocol             bool   `json:"use-proxy-protocol"`
}
