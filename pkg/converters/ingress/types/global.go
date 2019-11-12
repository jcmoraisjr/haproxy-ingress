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

// Global config
const (
	GlobalBindIPAddrHealthz            = "bind-ip-addr-healthz"
	GlobalBindIPAddrHTTP               = "bind-ip-addr-http"
	GlobalBindIPAddrStats              = "bind-ip-addr-stats"
	GlobalBindIPAddrTCP                = "bind-ip-addr-tcp"
	GlobalConfigDefaults               = "config-defaults"
	GlobalConfigFrontend               = "config-frontend"
	GlobalConfigGlobal                 = "config-global"
	GlobalCookieKey                    = "cookie-key"
	GlobalDNSAcceptedPayloadSize       = "dns-accepted-payload-size"
	GlobalDNSClusterDomain             = "dns-cluster-domain"
	GlobalDNSHoldObsolete              = "dns-hold-obsolete"
	GlobalDNSHoldValid                 = "dns-hold-valid"
	GlobalDNSResolvers                 = "dns-resolvers"
	GlobalDNSTimeoutRetry              = "dns-timeout-retry"
	GlobalDrainSupport                 = "drain-support"
	GlobalDrainSupportRedispatch       = "drain-support-redispatch"
	GlobalForwardfor                   = "forwardfor"
	GlobalFrontingProxyPort            = "fronting-proxy-port"
	GlobalHealthzPort                  = "healthz-port"
	GlobalHTTPLogFormat                = "http-log-format"
	GlobalHTTPPort                     = "http-port"
	GlobalHTTPSLogFormat               = "https-log-format"
	GlobalHTTPSPort                    = "https-port"
	GlobalHTTPStoHTTPPort              = "https-to-http-port"
	GlobalLoadServerState              = "load-server-state"
	GlobalMaxConnections               = "max-connections"
	GlobalModsecurityEndpoints         = "modsecurity-endpoints"
	GlobalModsecurityTimeoutHello      = "modsecurity-timeout-hello"
	GlobalModsecurityTimeoutIdle       = "modsecurity-timeout-idle"
	GlobalModsecurityTimeoutProcessing = "modsecurity-timeout-processing"
	GlobalNbprocBalance                = "nbproc-balance"
	GlobalNbprocSSL                    = "nbproc-ssl"
	GlobalNbthread                     = "nbthread"
	GlobalNoTLSRedirectLocations       = "no-tls-redirect-locations"
	GlobalSSLCiphers                   = "ssl-ciphers"
	GlobalSSLCipherSuites              = "ssl-cipher-suites"
	GlobalSSLDHDefaultMaxSize          = "ssl-dh-default-max-size"
	GlobalSSLDHParam                   = "ssl-dh-param"
	GlobalSSLEngine                    = "ssl-engine"
	GlobalSSLHeadersPrefix             = "ssl-headers-prefix"
	GlobalSSLModeAsync                 = "ssl-mode-async"
	GlobalSSLOptions                   = "ssl-options"
	GlobalStatsAuth                    = "stats-auth"
	GlobalStatsPort                    = "stats-port"
	GlobalStatsProxyProtocol           = "stats-proxy-protocol"
	GlobalStatsSSLCert                 = "stats-ssl-cert"
	GlobalStrictHost                   = "strict-host"
	GlobalSyslogEndpoint               = "syslog-endpoint"
	GlobalSyslogFormat                 = "syslog-format"
	GlobalSyslogLength                 = "syslog-length"
	GlobalSyslogTag                    = "syslog-tag"
	GlobalTCPLogFormat                 = "tcp-log-format"
	GlobalTimeoutStop                  = "timeout-stop"
	GlobalTLSALPN                      = "tls-alpn"
	GlobalUseHTX                       = "use-htx"
	GlobalUseProxyProtocol             = "use-proxy-protocol"
)
