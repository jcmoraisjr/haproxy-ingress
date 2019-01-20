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

// FrontendAnnotations ...
type FrontendAnnotations struct {
	Source                 Source `json:"-"`
	AppRoot                string `json:"app-root"`
	AuthTLSCertHeader      bool   `json:"auth-tls-cert-header"`
	AuthTLSErrorPage       string `json:"auth-tls-error-page"`
	AuthTLSSecret          string `json:"auth-tls-secret"`
	ServerAlias            string `json:"server-alias"`
	ServerAliasRegex       string `json:"server-alias-regex"`
	SSLPassthrough         bool   `json:"ssl-passthrough"`
	SSLPassthroughHTTPPort int    `json:"ssl-passthrough-http-port"`
	TimeoutClient          string `json:"timeout-client"`
	TimeoutClientFin       string `json:"timeout-client-fin"`
}

// BackendAnnotations ...
type BackendAnnotations struct {
	Source                Source `json:"-"`
	Affinity              string `json:"affinity"`
	AuthRealm             string `json:"auth-realm"`
	AuthSecret            string `json:"auth-secret"`
	AuthType              string `json:"auth-type"`
	BalanceAlgorithm      string `json:"balance-algorithm"`
	BlueGreenBalance      string `json:"blue-green-balance"`
	BlueGreenDeploy       string `json:"blue-green-deploy"`
	BlueGreenMode         string `json:"blue-green-mode"`
	ConfigBackend         string `json:"config-backend"`
	CookieKey             string `json:"cookie-key"`
	CorsAllowCredentials  bool   `json:"cors-allow-credentials"`
	CorsAllowHeaders      string `json:"cors-allow-headers"`
	CorsAllowMethods      string `json:"cors-allow-methods"`
	CorsAllowOrigin       string `json:"cors-allow-origin"`
	CorsEnable            bool   `json:"cors-enable"`
	CorsMaxAge            int    `json:"cors-max-age"`
	HSTS                  bool   `json:"hsts"`
	HSTSIncludeSubdomains bool   `json:"hsts-include-subdomains"`
	HSTSMaxAge            int    `json:"hsts-max-age"`
	HSTSPreload           bool   `json:"hsts-preload"`
	LimitConnections      int    `json:"limit-connections"`
	LimitRPS              int    `json:"limit-rps"`
	LimitWhitelist        string `json:"limit-whitelist"`
	MaxconnServer         int    `json:"maxconn-server"`
	MaxQueueServer        int    `json:"maxqueue-server"`
	OAuth                 string `json:"oauth"`
	OAuthHeaders          string `json:"oauth-headers"`
	OAuthURIPrefix        string `json:"oauth-uri-prefix"`
	ProxyBodySize         string `json:"proxy-body-size"`
	ProxyProtocol         string `json:"proxy-protocol"`
	RewriteTarget         string `json:"rewrite-target"`
	SlotsIncrement        int    `json:"slots-increment"`
	SecureBackends        bool   `json:"secure-backends"`
	SecureCrtSecret       string `json:"secure-crt-secret"`
	SecureVerifyCASecret  string `json:"secure-verify-ca-secret"`
	SessionCookieName     string `json:"session-cookie-name"`
	SessionCookieStrategy string `json:"session-cookie-strategy"`
	SSLRedirect           bool   `json:"ssl-redirect"`
	TimeoutConnect        string `json:"timeout-connect"`
	TimeoutHTTPRequest    string `json:"timeout-http-request"`
	TimeoutKeepAlive      string `json:"timeout-keep-alive"`
	TimeoutQueue          string `json:"timeout-queue"`
	TimeoutServer         string `json:"timeout-server"`
	TimeoutServerFin      string `json:"timeout-server-fin"`
	TimeoutStop           string `json:"timeout-stop"`
	TimeoutTunnel         string `json:"timeout-tunnel"`
	UseResolver           string `json:"use-resolver"`
	WAF                   string `json:"waf"`
	WhitelistSourceRange  string `json:"whitelist-source-range"`
}

// Source ...
type Source struct {
	Namespace string
	Name      string
	Type      string
}

func (s Source) String() string {
	return s.Type + " '" + s.Namespace + "/" + s.Name + "'"
}
