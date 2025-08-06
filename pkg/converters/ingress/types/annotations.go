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

// TCP Service Annotations
const (
	TCPConfigTCPService     = "config-tcp-service"
	TCPTCPServiceLogFormat  = "tcp-service-log-format"
	TCPTCPServicePort       = "tcp-service-port"
	TCPTCPServiceProxyProto = "tcp-service-proxy-protocol"
)

var (
	// AnnTCP ...
	AnnTCP = map[string]struct{}{
		TCPConfigTCPService:     {},
		TCPTCPServiceLogFormat:  {},
		TCPTCPServicePort:       {},
		TCPTCPServiceProxyProto: {},
	}
)

// Host Annotations
const (
	HostAcmePreferredChain      = "acme-preferred-chain"
	HostAppRoot                 = "app-root"
	HostAuthTLSErrorPage        = "auth-tls-error-page"
	HostAuthTLSSecret           = "auth-tls-secret"
	HostAuthTLSStrict           = "auth-tls-strict"
	HostAuthTLSVerifyClient     = "auth-tls-verify-client"
	HostCertSigner              = "cert-signer"
	HostHTTPResponse421         = "http-response-421"
	HostHTTPResponse495         = "http-response-495"
	HostHTTPResponse496         = "http-response-496"
	HostRedirectFrom            = "redirect-from"
	HostRedirectFromRegex       = "redirect-from-regex"
	HostServerAlias             = "server-alias"
	HostServerAliasRegex        = "server-alias-regex"
	HostSSLAlwaysAddHTTPS       = "ssl-always-add-https"
	HostSSLAlwaysFollowRedirect = "ssl-always-follow-redirect"
	HostSSLCiphers              = "ssl-ciphers"
	HostSSLCipherSuites         = "ssl-cipher-suites"
	HostSSLOptionsHost          = "ssl-options-host"
	HostSSLPassthrough          = "ssl-passthrough"
	HostSSLPassthroughHTTPPort  = "ssl-passthrough-http-port"
	HostTLSALPN                 = "tls-alpn"
	HostVarNamespace            = "var-namespace"
)

var (
	// AnnHost ...
	AnnHost = map[string]struct{}{
		HostAcmePreferredChain:     {},
		HostAppRoot:                {},
		HostAuthTLSErrorPage:       {},
		HostAuthTLSSecret:          {},
		HostAuthTLSStrict:          {},
		HostAuthTLSVerifyClient:    {},
		HostCertSigner:             {},
		HostHTTPResponse421:        {},
		HostHTTPResponse495:        {},
		HostHTTPResponse496:        {},
		HostRedirectFrom:           {},
		HostRedirectFromRegex:      {},
		HostServerAlias:            {},
		HostServerAliasRegex:       {},
		HostSSLAlwaysAddHTTPS:      {},
		HostSSLCiphers:             {},
		HostSSLCipherSuites:        {},
		HostSSLOptionsHost:         {},
		HostSSLPassthrough:         {},
		HostSSLPassthroughHTTPPort: {},
		HostTLSALPN:                {},
		HostVarNamespace:           {},
	}

	// AnnDuo is the list of annotations that should be added
	// on both host and backend annotations list.
	// TODO: merge tcp, host and backend config keys into a single list?
	AnnDuo = map[string]struct{}{
		BackAuthExternalPlacement: {},
		BackAuthHeadersFail:       {},
		BackAuthHeadersRequest:    {},
		BackAuthHeadersSucceed:    {},
		BackAuthMethod:            {},
		BackAuthSignin:            {},
		BackAuthURL:               {},
	}
)

// Backend Annotations
const (
	BackAffinity               = "affinity"
	BackAgentCheckAddr         = "agent-check-addr"
	BackAgentCheckInterval     = "agent-check-interval"
	BackAgentCheckPort         = "agent-check-port"
	BackAgentCheckSend         = "agent-check-send"
	BackAllowlistSourceRange   = "allowlist-source-range"
	BackAllowlistSourceHeader  = "allowlist-source-header"
	BackAssignBackendServerID  = "assign-backend-server-id"
	BackAuthExternalPlacement  = "auth-external-placement"
	BackAuthHeadersFail        = "auth-headers-fail"
	BackAuthHeadersRequest     = "auth-headers-request"
	BackAuthHeadersSucceed     = "auth-headers-succeed"
	BackAuthMethod             = "auth-method"
	BackAuthRealm              = "auth-realm"
	BackAuthSecret             = "auth-secret"
	BackAuthSignin             = "auth-signin"
	BackAuthTLSCertHeader      = "auth-tls-cert-header"
	BackAuthURL                = "auth-url"
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
	BackCorsAllowOriginRegex   = "cors-allow-origin-regex"
	BackCorsEnable             = "cors-enable"
	BackCorsExposeHeaders      = "cors-expose-headers"
	BackCorsMaxAge             = "cors-max-age"
	BackDenylistSourceRange    = "denylist-source-range"
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
	BackHTTPHeaderMatch        = "http-header-match"
	BackHTTPHeaderMatchRegex   = "http-header-match-regex"
	BackHTTPResponse200        = "http-response-200"
	BackHTTPResponse400        = "http-response-400"
	BackHTTPResponse401        = "http-response-401"
	BackHTTPResponse403        = "http-response-403"
	BackHTTPResponse405        = "http-response-405"
	BackHTTPResponse407        = "http-response-407"
	BackHTTPResponse408        = "http-response-408"
	BackHTTPResponse410        = "http-response-410"
	BackHTTPResponse413        = "http-response-413"
	BackHTTPResponse425        = "http-response-425"
	BackHTTPResponse429        = "http-response-429"
	BackHTTPResponse500        = "http-response-500"
	BackHTTPResponse501        = "http-response-501"
	BackHTTPResponse502        = "http-response-502"
	BackHTTPResponse503        = "http-response-503"
	BackHTTPResponse504        = "http-response-504"
	BackInitialWeight          = "initial-weight"
	BackLimitConnections       = "limit-connections"
	BackLimitRPS               = "limit-rps"
	BackLimitWhitelist         = "limit-whitelist"
	BackMaxconnServer          = "maxconn-server"
	BackMaxQueueServer         = "maxqueue-server"
	BackOAuth                  = "oauth"
	BackOAuthHeaders           = "oauth-headers"
	BackOAuthURIPrefix         = "oauth-uri-prefix"
	BackPathType               = "path-type"
	BackProxyBodySize          = "proxy-body-size"
	BackProxyProtocol          = "proxy-protocol"
	BackRedirectTo             = "redirect-to"
	BackRewriteTarget          = "rewrite-target"
	BackSlotsMinFree           = "slots-min-free"
	BackSecureBackends         = "secure-backends"
	BackSecureCrtSecret        = "secure-crt-secret"
	BackSecureSNI              = "secure-sni"
	BackSecureVerifyCASecret   = "secure-verify-ca-secret"
	BackSecureVerifyHostname   = "secure-verify-hostname"
	BackServiceUpstream        = "service-upstream"
	BackSessionCookieDomain    = "session-cookie-domain"
	BackSessionCookieDynamic   = "session-cookie-dynamic"
	BackSessionCookieKeywords  = "session-cookie-keywords"
	BackSessionCookieName      = "session-cookie-name"
	BackSessionCookiePreserve  = "session-cookie-preserve"
	BackSessionCookieSameSite  = "session-cookie-same-site"
	BackSessionCookieShared    = "session-cookie-shared"
	BackSessionCookieStrategy  = "session-cookie-strategy"
	BackSessionCookieValue     = "session-cookie-value-strategy"
	BackSourceAddressIntf      = "source-address-intf"
	BackSSLCipherSuitesBackend = "ssl-cipher-suites-backend"
	BackSSLCiphersBackend      = "ssl-ciphers-backend"
	BackSSLFingerprintLower    = "ssl-fingerprint-lower"
	BackSSLFingerprintSha2Bits = "ssl-fingerprint-sha2-bits"
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
