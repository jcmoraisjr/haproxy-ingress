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

// Host Annotations
const (
	HostAppRoot                = "app-root"
	HostAuthTLSErrorPage       = "auth-tls-error-page"
	HostAuthTLSSecret          = "auth-tls-secret"
	HostAuthTLSStrict          = "auth-tls-strict"
	HostAuthTLSVerifyClient    = "auth-tls-verify-client"
	HostCertSigner             = "cert-signer"
	HostPathType               = "path-type"
	HostServerAlias            = "server-alias"
	HostServerAliasRegex       = "server-alias-regex"
	HostSSLCiphers             = "ssl-ciphers"
	HostSSLCipherSuites        = "ssl-cipher-suites"
	HostSSLOptionsHost         = "ssl-options-host"
	HostSSLPassthrough         = "ssl-passthrough"
	HostSSLPassthroughHTTPPort = "ssl-passthrough-http-port"
	HostTLSALPN                = "tls-alpn"
	HostVarNamespace           = "var-namespace"
)

var (
	// AnnHost ...
	AnnHost = map[string]struct{}{
		HostAppRoot:                {},
		HostAuthTLSErrorPage:       {},
		HostAuthTLSSecret:          {},
		HostAuthTLSStrict:          {},
		HostAuthTLSVerifyClient:    {},
		HostCertSigner:             {},
		HostServerAlias:            {},
		HostPathType:               {},
		HostServerAliasRegex:       {},
		HostSSLCiphers:             {},
		HostSSLCipherSuites:        {},
		HostSSLOptionsHost:         {},
		HostSSLPassthrough:         {},
		HostSSLPassthroughHTTPPort: {},
		HostTLSALPN:                {},
		HostVarNamespace:           {},
	}
)

// Backend Annotations
const (
	BackAffinity               = "affinity"
	BackAgentCheckAddr         = "agent-check-addr"
	BackAgentCheckInterval     = "agent-check-interval"
	BackAgentCheckPort         = "agent-check-port"
	BackAgentCheckSend         = "agent-check-send"
	BackAuthRealm              = "auth-realm"
	BackAuthSecret             = "auth-secret"
	BackAuthTLSCertHeader      = "auth-tls-cert-header"
	BackAuthType               = "auth-type"
	BackBackendCheckInterval   = "backend-check-interval"
	BackBackendProtocol        = "backend-protocol"
	BackBackendServerNaming    = "backend-server-naming"
	BackBackendServerSlotsInc  = "backend-server-slots-increment"
	BackBalanceAlgorithm       = "balance-algorithm"
	BackBlueGreenBalance       = "blue-green-balance"
	BackBlueGreenCookie        = "blue-green-cookie"
	BackBlueGreenDeploy        = "blue-green-deploy"
	BackBlueGreenHeader        = "blue-green-header"
	BackBlueGreenMode          = "blue-green-mode"
	BackConfigBackend          = "config-backend"
	BackCorsAllowCredentials   = "cors-allow-credentials"
	BackCorsAllowHeaders       = "cors-allow-headers"
	BackCorsAllowMethods       = "cors-allow-methods"
	BackCorsAllowOrigin        = "cors-allow-origin"
	BackCorsEnable             = "cors-enable"
	BackCorsExposeHeaders      = "cors-expose-headers"
	BackCorsMaxAge             = "cors-max-age"
	BackDynamicScaling         = "dynamic-scaling"
	BackHeaders                = "headers"
	BackHealthCheckAddr        = "health-check-addr"
	BackHealthCheckFallCount   = "health-check-fall-count"
	BackHealthCheckInterval    = "health-check-interval"
	BackHealthCheckPort        = "health-check-port"
	BackHealthCheckRiseCount   = "health-check-rise-count"
	BackHealthCheckURI         = "health-check-uri"
	BackHSTS                   = "hsts"
	BackHSTSIncludeSubdomains  = "hsts-include-subdomains"
	BackHSTSMaxAge             = "hsts-max-age"
	BackHSTSPreload            = "hsts-preload"
	BackInitialWeight          = "initial-weight"
	BackLimitConnections       = "limit-connections"
	BackLimitRPS               = "limit-rps"
	BackLimitWhitelist         = "limit-whitelist"
	BackMaxconnServer          = "maxconn-server"
	BackMaxQueueServer         = "maxqueue-server"
	BackOAuth                  = "oauth"
	BackOAuthHeaders           = "oauth-headers"
	BackOAuthURIPrefix         = "oauth-uri-prefix"
	BackProxyBodySize          = "proxy-body-size"
	BackProxyProtocol          = "proxy-protocol"
	BackRewriteTarget          = "rewrite-target"
	BackSlotsMinFree           = "slots-min-free"
	BackSecureBackends         = "secure-backends"
	BackSecureCrtSecret        = "secure-crt-secret"
	BackSecureVerifyCASecret   = "secure-verify-ca-secret"
	BackServiceUpstream        = "service-upstream"
	BackSessionCookieDynamic   = "session-cookie-dynamic"
	BackSessionCookieKeywords  = "session-cookie-keywords"
	BackSessionCookieName      = "session-cookie-name"
	BackSessionCookiePreserve  = "session-cookie-preserve"
	BackSessionCookieShared    = "session-cookie-shared"
	BackSessionCookieStrategy  = "session-cookie-strategy"
	BackSessionCookieValue     = "session-cookie-value-strategy"
	BackSSLCipherSuitesBackend = "ssl-cipher-suites-backend"
	BackSSLCiphersBackend      = "ssl-ciphers-backend"
	BackSSLFingerprintLower    = "ssl-fingerprint-lower"
	BackSSLOptionsBackend      = "ssl-options-backend"
	BackSSLRedirect            = "ssl-redirect"
	BackTimeoutConnect         = "timeout-connect"
	BackTimeoutHTTPRequest     = "timeout-http-request"
	BackTimeoutKeepAlive       = "timeout-keep-alive"
	BackTimeoutQueue           = "timeout-queue"
	BackTimeoutServer          = "timeout-server"
	BackTimeoutServerFin       = "timeout-server-fin"
	BackTimeoutTunnel          = "timeout-tunnel"
	BackUseResolver            = "use-resolver"
	BackWAF                    = "waf"
	BackWAFMode                = "waf-mode"
	BackWhitelistSourceRange   = "whitelist-source-range"
)

// Extra Annotations
const (
	ExtraTLSAcme = "kubernetes.io/tls-acme"
)
