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
	HostAuthTLSVerifyClient    = "auth-tls-verify-client"
	HostAuthTLSSecret          = "auth-tls-secret"
	HostServerAlias            = "server-alias"
	HostServerAliasRegex       = "server-alias-regex"
	HostSSLPassthrough         = "ssl-passthrough"
	HostSSLPassthroughHTTPPort = "ssl-passthrough-http-port"
	HostTimeoutClient          = "timeout-client"
	HostTimeoutClientFin       = "timeout-client-fin"
)

var (
	// AnnHost ...
	AnnHost = map[string]struct{}{
		HostAppRoot:                {},
		HostAuthTLSErrorPage:       {},
		HostAuthTLSVerifyClient:    {},
		HostAuthTLSSecret:          {},
		HostServerAlias:            {},
		HostServerAliasRegex:       {},
		HostSSLPassthrough:         {},
		HostSSLPassthroughHTTPPort: {},
		HostTimeoutClient:          {},
		HostTimeoutClientFin:       {},
	}
)

// Backend Annotations
const (
	BackAffinity              = "affinity"
	BackAuthRealm             = "auth-realm"
	BackAuthSecret            = "auth-secret"
	BackAuthTLSCertHeader     = "auth-tls-cert-header"
	BackAuthType              = "auth-type"
	BackBalanceAlgorithm      = "balance-algorithm"
	BackBlueGreenBalance      = "blue-green-balance"
	BackBlueGreenDeploy       = "blue-green-deploy"
	BackBlueGreenMode         = "blue-green-mode"
	BackConfigBackend         = "config-backend"
	BackCorsAllowCredentials  = "cors-allow-credentials"
	BackCorsAllowHeaders      = "cors-allow-headers"
	BackCorsAllowMethods      = "cors-allow-methods"
	BackCorsAllowOrigin       = "cors-allow-origin"
	BackCorsEnable            = "cors-enable"
	BackCorsExposeHeaders     = "cors-expose-headers"
	BackCorsMaxAge            = "cors-max-age"
	BackHSTS                  = "hsts"
	BackHSTSIncludeSubdomains = "hsts-include-subdomains"
	BackHSTSMaxAge            = "hsts-max-age"
	BackHSTSPreload           = "hsts-preload"
	BackLimitConnections      = "limit-connections"
	BackLimitRPS              = "limit-rps"
	BackLimitWhitelist        = "limit-whitelist"
	BackMaxconnServer         = "maxconn-server"
	BackMaxQueueServer        = "maxqueue-server"
	BackOAuth                 = "oauth"
	BackOAuthHeaders          = "oauth-headers"
	BackOAuthURIPrefix        = "oauth-uri-prefix"
	BackProxyBodySize         = "proxy-body-size"
	BackProxyProtocol         = "proxy-protocol"
	BackRewriteTarget         = "rewrite-target"
	BackSlotsIncrement        = "slots-increment"
	BackSecureBackends        = "secure-backends"
	BackSecureCrtSecret       = "secure-crt-secret"
	BackSecureVerifyCASecret  = "secure-verify-ca-secret"
	BackSessionCookieDynamic  = "session-cookie-dynamic"
	BackSessionCookieName     = "session-cookie-name"
	BackSessionCookieStrategy = "session-cookie-strategy"
	BackSSLRedirect           = "ssl-redirect"
	BackTimeoutConnect        = "timeout-connect"
	BackTimeoutHTTPRequest    = "timeout-http-request"
	BackTimeoutKeepAlive      = "timeout-keep-alive"
	BackTimeoutQueue          = "timeout-queue"
	BackTimeoutServer         = "timeout-server"
	BackTimeoutServerFin      = "timeout-server-fin"
	BackTimeoutTunnel         = "timeout-tunnel"
	BackUseResolver           = "use-resolver"
	BackWAF                   = "waf"
	BackWhitelistSourceRange  = "whitelist-source-range"
)
