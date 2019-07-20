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

package haproxy

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
	yaml "gopkg.in/yaml.v2"

	ha_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/helper_test"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  BACKEND TESTCASES
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

func TestBackends(t *testing.T) {
	testCases := []struct {
		doconfig  func(g *hatypes.Global, b *hatypes.Backend)
		path      []string
		srvsuffix string
		expected  string
	}{
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.Cookie.Name = "ingress-controller"
				b.Cookie.Strategy = "insert"
			},
			srvsuffix: "cookie s1",
			expected: `
    cookie ingress-controller insert indirect nocache httponly`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.Cookie.Name = "Ingress"
				b.Cookie.Strategy = "prefix"
				b.Cookie.Dynamic = true
			},
			expected: `
    cookie Ingress prefix dynamic
    dynamic-cookie-key "Ingress"`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.Cors.Enabled = true
				b.Cors.AllowOrigin = "*"
				b.Cors.AllowHeaders =
					"DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
				b.Cors.AllowMethods = "GET, PUT, POST, DELETE, PATCH, OPTIONS"
				b.Cors.MaxAge = 86400
			},
			expected: `
    http-request use-service lua.send-response if METH_OPTIONS
    http-response set-status 204 reason "No Content" if METH_OPTIONS
    http-response set-header Content-Type                 "text/plain" if METH_OPTIONS
    http-response set-header Content-Length               "0" if METH_OPTIONS
    http-response set-header Access-Control-Allow-Origin  "*" if METH_OPTIONS
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if METH_OPTIONS
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization" if METH_OPTIONS
    http-response set-header Access-Control-Max-Age       "86400" if METH_OPTIONS
    http-response set-header Access-Control-Allow-Origin  "*"
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				p1 := b.AddPath("/")
				p2 := b.AddPath("/path")
				p3 := b.AddPath("/uri")
				b.HSTS = []*hatypes.BackendConfigHSTS{
					{
						Paths: hatypes.NewBackendPaths(p1),
						Config: hatypes.HSTS{
							Enabled:    true,
							MaxAge:     15768000,
							Preload:    true,
							Subdomains: true,
						},
					},
					{
						Paths: hatypes.NewBackendPaths(p2, p3),
						Config: hatypes.HSTS{
							Enabled:    true,
							MaxAge:     15768000,
							Preload:    false,
							Subdomains: false,
						},
					},
				}
			},
			expected: `
    # path01 = /
    # path02 = /path
    # path03 = /uri
    http-request set-var(txn.pathID) path,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath.map,_nomatch)
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" if { ssl_fc } { var(txn.pathID) path01 }
    http-response set-header Strict-Transport-Security "max-age=15768000" if { ssl_fc } { var(txn.pathID) path02 path03 }`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				g.ForwardFor = "add"
			},
			expected: `
    http-request set-header X-Original-Forwarded-For %[hdr(x-forwarded-for)] if { hdr(x-forwarded-for) -m found }
    http-request del-header x-forwarded-for
    option forwardfor`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.RewriteURL = "/"
			},
			path: []string{"/app"},
			expected: `
    reqrep ^([^:\ ]*)\ /app/?(.*)$     \1\ /\2`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.RewriteURL = "/other"
			},
			path: []string{"/app"},
			expected: `
    reqrep ^([^:\ ]*)\ /app(.*)$       \1\ /other\2`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.RewriteURL = "/other/"
			},
			path: []string{"/app", "/app/sub"},
			expected: `
    reqrep ^([^:\ ]*)\ /app/sub(.*)$       \1\ /other/\2
    reqrep ^([^:\ ]*)\ /app(.*)$       \1\ /other/\2`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				p1 := b.AddPath("/app")
				p2 := b.AddPath("/api")
				p3 := b.AddPath("/path")
				b.Whitelist = []*hatypes.BackendConfigWhitelist{
					{
						Paths:  hatypes.NewBackendPaths(p1, p2),
						Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
					},
					{
						Paths:  hatypes.NewBackendPaths(p3),
						Config: []string{"192.168.95.0/24"},
					},
				}
			},
			expected: `
    # path01 = /
    # path03 = /api
    # path02 = /app
    # path04 = /path
    http-request set-var(txn.pathID) path,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath.map,_nomatch)
    http-request deny if { var(txn.pathID) path03 path02 } !{ src 10.0.0.0/8 192.168.0.0/16 }
    http-request deny if { var(txn.pathID) path04 } !{ src 192.168.95.0/24 }`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				p1 := b.AddPath("/app")
				p2 := b.AddPath("/api")
				p3 := b.AddPath("/path")
				b.Whitelist = []*hatypes.BackendConfigWhitelist{
					{
						Paths:  hatypes.NewBackendPaths(p1, p2),
						Config: []string{},
					},
					{
						Paths:  hatypes.NewBackendPaths(p3),
						Config: []string{"192.168.95.0/24"},
					},
				}
			},
			expected: `
    # path01 = /
    # path03 = /api
    # path02 = /app
    # path04 = /path
    http-request set-var(txn.pathID) path,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath.map,_nomatch)
    http-request deny if { var(txn.pathID) path04 } !{ src 192.168.95.0/24 }`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.WhitelistTCP = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.ModeTCP = true
			},
			expected: `
    tcp-request content reject if !{ src 10.0.0.0/8 192.168.0.0/16 }`,
		},
		{
			doconfig: func(g *hatypes.Global, b *hatypes.Backend) {
				b.OAuth.Impl = "oauth2_proxy"
				b.OAuth.BackendName = "system_oauth_4180"
				b.OAuth.URIPrefix = "/oauth2"
				b.OAuth.Headers = map[string]string{"X-Auth-Request-Email": "auth_response_email"}
			},
			expected: `
    http-request set-header X-Real-IP %[src]
    http-request lua.auth-request system_oauth_4180 /oauth2/auth
    http-request redirect location /oauth2/start?rd=%[path] if !{ path_beg /oauth2/ } !{ var(txn.auth_response_successful) -m bool }
    http-request set-header X-Auth-Request-Email %[var(txn.auth_response_email)] if { var(txn.auth_response_email) -m found }`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		if len(test.path) == 0 {
			test.path = []string{"/"}
		}
		if test.srvsuffix != "" {
			test.srvsuffix = " " + test.srvsuffix
		}

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.AcquireHost("d1.local")
		for _, p := range test.path {
			h.AddPath(b, p)
		}
		test.doconfig(c.config.Global(), b)

		var mode string
		if b.ModeTCP {
			mode = "tcp"
		} else {
			mode = "http"
		}

		c.instance.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode ` + mode + test.expected + `
    server s1 172.17.0.11:8080 weight 100` + test.srvsuffix + `
<<backends-default>>
<<frontends-default>>
`)

		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  TEMPLATES
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

func TestInstanceBare(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceEmpty(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.AcquireHost("empty").AddPath(c.config.AcquireBackend("default", "empty", "8080"), "/")
	c.instance.Update()

	c.checkConfig(`
global
    daemon
    stats socket /var/run/haproxy.sock level admin expose-fd listeners
    maxconn 2000
    hard-stop-after 15m
    lua-load /usr/local/etc/haproxy/lua/send-response.lua
    lua-load /usr/local/etc/haproxy/lua/auth-request.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-options no-sslv3
defaults
    log global
    maxconn 2000
    option redispatch
    option dontlognull
    option http-server-close
    option http-keep-alive
    timeout client          50s
    timeout client-fin      50s
    timeout connect         5s
    timeout http-keep-alive 1m
    timeout http-request    5s
    timeout queue           5s
    timeout server          50s
    timeout server-fin      50s
    timeout tunnel          1h
backend default_empty_8080
    mode http
backend _error404
    mode http
    errorfile 400 /usr/local/etc/haproxy/errors/404.http
    http-request deny deny_status 400
backend _error495
    mode http
    errorfile 400 /usr/local/etc/haproxy/errors/495.http
    http-request deny deny_status 400
backend _error496
    mode http
    errorfile 400 /usr/local/etc/haproxy/errors/496.http
    http-request deny deny_status 400
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _error404
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _error404
`)

	c.checkMap("_global_http_front.map", `
empty/ default_empty_8080`)
	c.checkMap("_global_https_redir.map", `
empty/ no`)
	c.checkMap("_front001_host.map", `
empty/ default_empty_8080`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceDefaultHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.ConfigDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	h = c.config.AcquireHost("*")
	h.AddPath(b, "/")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true

	b = c.config.AcquireBackend("d2", "app", "8080")
	h = c.config.AcquireHost("d2.local")
	h.AddPath(b, "/app")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend _default_backend
    mode http
    server s0 172.17.0.99:8080 weight 100
<<backend-errors>>
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    use_backend d1_app_8080
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    http-request set-var(req.base) base,lower,regsub(:[0-9]+/,/)
    http-request set-var(req.hostbackend) var(req.base),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    http-request set-var(txn.namespace) var(req.base),map_beg(/etc/haproxy/maps/_front001_k8s_ns.map,-)
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    use_backend d1_app_8080
`)

	c.checkMap("_global_http_front.map", `
`)
	c.checkMap("_global_https_redir.map", `
d2.local/app yes
`)
	c.checkMap("_front001_k8s_ns.map", `
d2.local/app d2
`)
	c.checkMap("_front001_host.map", `
d2.local/app d2_app_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSingleFrontendSingleBind(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.ConfigDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d1.pem"
	h.TLS.TLSHash = "1"

	b = c.config.AcquireBackend("d2", "app", "8080")
	h = c.config.AcquireHost("d2.local")
	h.AddPath(b, "/app")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d2.pem"
	h.TLS.TLSHash = "2"

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend _default_backend
    mode http
    server s0 172.17.0.99:8080 weight 100
<<backend-errors>>
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _default_backend
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem crt /var/haproxy/certs/_public
    http-request set-var(req.base) base,lower,regsub(:[0-9]+/,/)
    http-request set-var(req.hostbackend) var(req.base),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    http-request set-var(txn.namespace) var(req.base),map_beg(/etc/haproxy/maps/_front001_k8s_ns.map,-)
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _default_backend
`)

	c.checkMap("_global_http_front.map", `
`)
	c.checkMap("_global_https_redir.map", `
d1.local/ yes
d2.local/app yes
`)
	c.checkMap("_front001_host.map", `
d1.local/ d1_app_8080
d2.local/app d2_app_8080
`)
	c.checkMap("_front001_k8s_ns.map", `
d1.local/ d1
d2.local/app -
`)

	c.checkCerts(`
certdirs:
- dir: /var/haproxy/certs/_public
  certs:
  - /var/haproxy/ssl/certs/d1.pem
  - /var/haproxy/ssl/certs/d2.pem`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSingleFrontendTwoBindsCA(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.ConfigDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d", "app", "8080")
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	b.SSL.AddCertHeader = true
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d1.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAErrorPage = "http://d1.local/error.html"

	h = c.config.AcquireHost("d2.local")
	h.AddPath(b, "/")
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d2.local.pem"
	h.TLS.CAHash = "2"

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d_app_8080
    mode http
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]
    http-request set-header X-SSL-Client-Cert %{+Q}[ssl_c_der,base64]
    server s1 172.17.0.11:8080 weight 100
backend _default_backend
    mode http
    server s0 172.17.0.99:8080 weight 100
<<backend-errors>>
listen _front__tls
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    ## _front001/_socket001
    use-server _server_socket001 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket001.list }
    server _server_socket001 unix@/var/run/_socket001.sock send-proxy-v2 weight 0
    ## _front001/_socket002
    use-server _server_socket002 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket002.list }
    server _server_socket002 unix@/var/run/_socket002.sock send-proxy-v2 weight 0
    # TODO default backend
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _default_backend
frontend _front001
    mode http
    bind unix@/var/run/_socket001.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem ca-file /var/haproxy/ssl/ca/d1.local.pem verify optional ca-ignore-err all crt-ignore-err all
    bind unix@/var/run/_socket002.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem ca-file /var/haproxy/ssl/ca/d2.local.pem verify optional ca-ignore-err all crt-ignore-err all
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    <<tls-del-headers>>
    http-request set-header x-ha-base %[ssl_fc_sni]%[path]
    http-request set-var(req.snibackend) hdr(x-ha-base),lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_sni.map,_nomatch)
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -f /etc/haproxy/maps/_front001_no_crt.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -f /etc/haproxy/maps/_front001_inv_crt.list
    http-request set-var(req.tls_nocrt_redir) ssl_fc_sni,lower,map(/etc/haproxy/maps/_front001_no_crt_redir.map,_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map(/etc/haproxy/maps/_front001_inv_crt_redir.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request redirect location %[var(req.tls_nocrt_redir)] code 303 if { var(req.tls_nocrt_redir) -m found } !{ var(req.tls_nocrt_redir) _internal }
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) _internal }
    use_backend _error496 if { var(req.tls_nocrt_redir) _internal }
    use_backend _error495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    use_backend %[var(req.snibackend)] unless { var(req.snibackend) _nomatch }
    default_backend _default_backend
`)

	c.checkMap("_socket001.list", `
d1.local
`)
	c.checkMap("_socket002.list", `
d2.local
`)
	c.checkMap("_global_http_front.map", `
`)
	c.checkMap("_global_https_redir.map", `
d1.local/ yes
d2.local/ yes
`)
	c.checkMap("_front001_host.map", `
`)
	c.checkMap("_front001_sni.map", `
d1.local/ d_app_8080
d2.local/ d_app_8080
`)
	c.checkMap("_front001_no_crt.list", `
d1.local
d2.local
`)
	c.checkMap("_front001_inv_crt.list", `
d1.local
d2.local
`)
	c.checkMap("_front001_no_crt_redir.map", `
d1.local http://d1.local/error.html
`)
	c.checkMap("_front001_inv_crt_redir.map", `
d1.local http://d1.local/error.html
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceTwoFrontendsThreeBindsCA(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.ConfigDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d", "appca", "8080")
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.Timeout.Client = "1s"
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d1.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAVerifyOptional = true
	h.TLS.CAErrorPage = "http://d1.local/error.html"

	h = c.config.AcquireHost("d21.local")
	h.AddPath(b, "/")
	h.Timeout.Client = "2s"
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d.pem"
	h.TLS.TLSHash = "1"
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d2.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAVerifyOptional = true
	h.TLS.CAErrorPage = "http://d21.local/error.html"

	h = c.config.AcquireHost("d22.local")
	h.AddPath(b, "/")
	h.Timeout.Client = "2s"
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d.pem"
	h.TLS.TLSHash = "1"
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d2.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAErrorPage = "http://d22.local/error.html"

	b = c.config.AcquireBackend("d", "app", "8080")
	h = c.config.AcquireHost("d3.local")
	h.AddPath(b, "/")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h.Timeout.Client = "2s"

	h = c.config.AcquireHost("d4.local")
	h.AddPath(b, "/")
	h.Timeout.Client = "2s"

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d_app_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
backend d_appca_8080
    mode http
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if { ssl_fc }
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if { ssl_fc }
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if { ssl_fc }
    server s1 172.17.0.11:8080 weight 100
backend _default_backend
    mode http
    server s0 172.17.0.99:8080 weight 100
<<backend-errors>>
listen _front__tls
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    ## _front001/_socket001
    use-server _server_socket001 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket001.list }
    server _server_socket001 unix@/var/run/_socket001.sock send-proxy-v2 weight 0
    ## _front002/_socket002
    use-server _server_socket002 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket002.list }
    server _server_socket002 unix@/var/run/_socket002.sock send-proxy-v2 weight 0
    ## _front002/_socket003
    use-server _server_socket003 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket003.list }
    server _server_socket003 unix@/var/run/_socket003.sock send-proxy-v2 weight 0
    # TODO default backend
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _default_backend
frontend _front001
    mode http
    bind unix@/var/run/_socket001.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem ca-file /var/haproxy/ssl/ca/d1.local.pem verify optional ca-ignore-err all crt-ignore-err all
    timeout client 1s
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    <<tls-del-headers>>
    http-request set-header x-ha-base %[ssl_fc_sni]%[path]
    http-request set-var(req.snibackend) hdr(x-ha-base),lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_sni.map,_nomatch)
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -f /etc/haproxy/maps/_front001_inv_crt.list
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map(/etc/haproxy/maps/_front001_inv_crt_redir.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) _internal }
    use_backend _error495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    use_backend %[var(req.snibackend)] unless { var(req.snibackend) _nomatch }
    default_backend _default_backend
frontend _front002
    mode http
    bind unix@/var/run/_socket002.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem crt /var/haproxy/certs/_socket002 ca-file /var/haproxy/ssl/ca/d2.local.pem verify optional ca-ignore-err all crt-ignore-err all
    bind unix@/var/run/_socket003.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    timeout client 2s
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front002_host.map,_nomatch)
    <<tls-del-headers>>
    http-request set-header x-ha-base %[ssl_fc_sni]%[path]
    http-request set-var(req.snibackend) hdr(x-ha-base),lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front002_sni.map,_nomatch)
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -f /etc/haproxy/maps/_front002_no_crt.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -f /etc/haproxy/maps/_front002_inv_crt.list
    http-request set-var(req.tls_nocrt_redir) ssl_fc_sni,lower,map(/etc/haproxy/maps/_front002_no_crt_redir.map,_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map(/etc/haproxy/maps/_front002_inv_crt_redir.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request redirect location %[var(req.tls_nocrt_redir)] code 303 if { var(req.tls_nocrt_redir) -m found } !{ var(req.tls_nocrt_redir) _internal }
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) _internal }
    use_backend _error496 if { var(req.tls_nocrt_redir) _internal }
    use_backend _error495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    use_backend %[var(req.snibackend)] unless { var(req.snibackend) _nomatch }
    default_backend _default_backend
`)

	c.checkMap("_socket001.list", `
d1.local
`)
	c.checkMap("_socket002.list", `
d21.local
d22.local
`)
	c.checkMap("_socket003.list", `
d3.local
d4.local
`)
	c.checkMap("_global_http_front.map", `
d1.local/ d_appca_8080
d21.local/ d_appca_8080
d22.local/ d_appca_8080
d3.local/ d_app_8080
d4.local/ d_app_8080
`)
	c.checkMap("_global_https_redir.map", `
d1.local/ no
d21.local/ no
d22.local/ no
d3.local/ no
d4.local/ no
`)
	c.checkMap("_front001_host.map", `
`)
	c.checkMap("_front001_sni.map", `
d1.local/ d_appca_8080
`)
	c.checkMap("_front001_inv_crt.list", `
d1.local`)
	c.checkMap("_front001_inv_crt_redir.map", `
d1.local http://d1.local/error.html
`)
	c.checkMap("_front002_host.map", `
d3.local/ d_app_8080
d4.local/ d_app_8080
`)
	c.checkMap("_front002_sni.map", `
d21.local/ d_appca_8080
d22.local/ d_appca_8080
`)
	c.checkMap("_front002_no_crt.list", `
d22.local
`)
	c.checkMap("_front002_inv_crt.list", `
d21.local
d22.local
`)
	c.checkMap("_front002_no_crt_redir.map", `
d22.local http://d22.local/error.html
`)
	c.checkMap("_front002_inv_crt_redir.map", `
d21.local http://d21.local/error.html
d22.local http://d22.local/error.html
`)

	c.checkCerts(`
certdirs:
- dir: /var/haproxy/certs/_socket002
  certs:
  - /var/haproxy/ssl/certs/d.pem`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSomePaths(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.ConfigDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d", "app0", "8080")
	h = c.config.AcquireHost("d.local")
	h.AddPath(b, "/")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.AcquireBackend("d", "app1", "8080")
	h.AddPath(b, "/app")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.AcquireBackend("d", "app2", "8080")
	h.AddPath(b, "/app/sub")
	b.Endpoints = []*hatypes.Endpoint{endpointS21, endpointS22}

	b = c.config.AcquireBackend("d", "app3", "8080")
	h.AddPath(b, "/sub")
	b.Endpoints = []*hatypes.Endpoint{endpointS31, endpointS32, endpointS33}

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d_app0_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d_app1_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d_app2_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
    server s22 172.17.0.122:8080 weight 100
backend d_app3_8080
    mode http
    server s31 172.17.0.131:8080 weight 100
    server s32 172.17.0.132:8080 weight 100
    server s33 172.17.0.133:8080 weight 100
backend _default_backend
    mode http
    server s0 172.17.0.99:8080 weight 100
<<backend-errors>>
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _default_backend
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _default_backend
`)

	c.checkMap("_global_http_front.map", `
d.local/sub d_app3_8080
d.local/app/sub d_app2_8080
`)
	c.checkMap("_global_https_redir.map", `
d.local/sub no
d.local/app/sub no
d.local/app yes
d.local/ yes
`)
	c.checkMap("_front001_host.map", `
d.local/sub d_app3_8080
d.local/app/sub d_app2_8080
d.local/app d_app1_8080
d.local/ d_app0_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSSLPassthrough(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d2", "app", "8080")
	h = c.config.AcquireHost("d2.local")
	h.AddPath(b, "/")
	b.SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS31}
	h.SSLPassthrough = true

	b = c.config.AcquireBackend("d3", "app-ssl", "8443")
	h = c.config.AcquireHost("d3.local")
	h.AddPath(b, "/")
	b.Endpoints = []*hatypes.Endpoint{endpointS41s}
	h.SSLPassthrough = true

	b = c.config.AcquireBackend("d3", "app-http", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS41h}
	h.HTTPPassthroughBackend = b

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d2_app_8080
    mode http
    server s31 172.17.0.131:8080 weight 100
backend d3_app-http_8080
    mode http
    server s41h 172.17.0.141:8080 weight 100
backend d3_app-ssl_8443
    mode http
    server s41s 172.17.0.141:8443 weight 100
<<backends-default>>
listen _front__tls
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content set-var(req.sslpassback) req.ssl_sni,lower,map(/etc/haproxy/maps/_global_sslpassthrough.map,_nomatch)
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend %[var(req.sslpassback)] unless { var(req.sslpassback) _nomatch }
    # TODO default backend
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _error404`)

	c.checkMap("_global_sslpassthrough.map", `
d2.local d2_app_8080
d3.local d3_app-ssl_8443`)
	c.checkMap("_global_http_front.map", `
d3.local/ d3_app-http_8080`)
	c.checkMap("_global_https_redir.map", `
d2.local/ yes
d3.local/ no`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceRootRedirect(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	b.SSLRedirect = false
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")
	h.RootRedirect = "/app"

	b = c.config.AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	b.SSLRedirect = true
	h = c.config.AcquireHost("d2.local")
	h.AddPath(b, "/app1")
	h.AddPath(b, "/app2")
	h.RootRedirect = "/app1"

	c.instance.Update()

	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    http-request set-var(req.host) hdr(host),lower,regsub(:[0-9]+/,/)
    http-request set-var(req.rootredir) var(req.host),map(/etc/haproxy/maps/_global_http_root_redir.map,_nomatch)
    http-request redirect location %[var(req.rootredir)] if { path / } !{ var(req.rootredir) _nomatch }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _error404
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    http-request set-var(req.host) hdr(host),lower,regsub(:[0-9]+/,/)
    http-request set-var(req.rootredir) var(req.host),map(/etc/haproxy/maps/_front001_root_redir.map,_nomatch)
    http-request redirect location %[var(req.rootredir)] if { path / } !{ var(req.rootredir) _nomatch }
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _error404
`)

	c.checkMap("_global_http_front.map", `
d1.local/ d1_app_8080
`)
	c.checkMap("_global_https_redir.map", `
d1.local/ no
d2.local/app2 yes
d2.local/app1 yes
`)
	c.checkMap("_global_http_root_redir.map", `
d1.local /app
d2.local /app1
`)
	c.checkMap("_front001_host.map", `
d1.local/ d1_app_8080
d2.local/app2 d2_app_8080
d2.local/app1 d2_app_8080
`)
	c.checkMap("_front001_root_redir.map", `
d1.local /app
d2.local /app1
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceAlias(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")
	h.Alias.AliasName = "*.d1.local"

	b = c.config.AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h = c.config.AcquireHost("d2.local")
	h.AddPath(b, "/")
	h.Alias.AliasName = "sub.d2.local"
	h.Alias.AliasRegex = "^[a-z]+\\.d2\\.local$"

	b = c.config.AcquireBackend("d3", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS31}
	h = c.config.AcquireHost("d3.local")
	h.AddPath(b, "/")
	h.Alias.AliasRegex = ".*d3\\.local$"

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
backend d3_app_8080
    mode http
    server s31 172.17.0.131:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _error404
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    http-request set-var(req.base) base,lower,regsub(:[0-9]+/,/)
    http-request set-var(req.hostbackend) var(req.base),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front001_host_regex.map,_nomatch) if { var(req.hostbackend) _nomatch }
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _error404
`)

	c.checkMap("_global_https_redir.map", `
d1.local/ no
d2.local/ no
d3.local/ no
`)
	c.checkMap("_global_http_front.map", `
d1.local/ d1_app_8080
d2.local/ d2_app_8080
d3.local/ d3_app_8080
`)
	c.checkMap("_front001_host.map", `
d1.local/ d1_app_8080
d2.local/ d2_app_8080
sub.d2.local/ d2_app_8080
d3.local/ d3_app_8080
`)
	c.checkMap("_front001_host_regex.map", `
^[^.]+\.d1\.local/ d1_app_8080
^[a-z]+\.d2\.local$/ d2_app_8080
.*d3\.local$/ d3_app_8080
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceRewriteTarget(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	b.RewriteURL = "/internal"

	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/app")
	h.AddPath(b, "/uri")

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    reqrep ^([^:\ ]*)\ /uri(.*)$       \1\ /internal\2
    reqrep ^([^:\ ]*)\ /app(.*)$       \1\ /internal\2
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestUserlist(t *testing.T) {
	type list struct {
		name  string
		users []hatypes.User
	}
	testCase := []struct {
		lists    []list
		listname string
		realm    string
		config   string
	}{
		{
			lists: []list{
				{
					name: "default_usr",
					users: []hatypes.User{
						{Name: "usr1", Passwd: "clear1", Encrypted: false},
					},
				},
			},
			listname: "default_usr",
			config: `
userlist default_usr
    user usr1 insecure-password clear1`,
		},
		{
			lists: []list{
				{
					name: "default_auth",
					users: []hatypes.User{
						{Name: "usr1", Passwd: "clear1", Encrypted: false},
						{Name: "usr2", Passwd: "xxxx", Encrypted: true},
					},
				},
			},
			listname: "default_auth",
			realm:    "usrlist",
			config: `
userlist default_auth
    user usr1 insecure-password clear1
    user usr2 password xxxx`,
		},
		{
			lists: []list{
				{
					name: "default_auth1",
					users: []hatypes.User{
						{Name: "usr1", Passwd: "clear1", Encrypted: false},
					},
				},
				{
					name: "default_auth2",
					users: []hatypes.User{
						{Name: "usr2", Passwd: "xxxx", Encrypted: true},
					},
				},
			},
			listname: "default_auth1",
			realm:    "multi list",
			config: `
userlist default_auth1
    user usr1 insecure-password clear1
userlist default_auth2
    user usr2 password xxxx`,
		},
	}
	for _, test := range testCase {
		c := setup(t)

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.AcquireHost("d1.local")
		h.AddPath(b, "/")

		for _, list := range test.lists {
			c.config.AddUserlist(list.name, list.users)
		}
		b.Userlist.Name = test.listname
		b.Userlist.Realm = test.realm

		var realm string
		if test.realm != "" {
			realm = fmt.Sprintf(` realm "%s"`, test.realm)
		}

		c.instance.Update()
		c.checkConfig(`
<<global>>
<<defaults>>` + test.config + `
backend d1_app_8080
    mode http
    http-request auth` + realm + ` if !{ http_auth(` + test.listname + `) }
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
`)
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestModSecurity(t *testing.T) {
	testCases := []struct {
		waf        string
		endpoints  []string
		backendExp string
		modsecExp  string
	}{
		{
			waf:        "modsecurity",
			endpoints:  []string{},
			backendExp: ``,
			modsecExp:  ``,
		},
		{
			waf:        "",
			endpoints:  []string{"10.0.0.101:12345"},
			backendExp: ``,
			modsecExp: `
    server modsec-spoa0 10.0.0.101:12345`,
		},
		{
			waf:       "modsecurity",
			endpoints: []string{"10.0.0.101:12345"},
			backendExp: `
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request deny if { var(txn.modsec.code) -m int gt 0 }`,
			modsecExp: `
    server modsec-spoa0 10.0.0.101:12345`,
		},
		{
			waf:       "modsecurity",
			endpoints: []string{"10.0.0.101:12345", "10.0.0.102:12345"},
			backendExp: `
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request deny if { var(txn.modsec.code) -m int gt 0 }`,
			modsecExp: `
    server modsec-spoa0 10.0.0.101:12345
    server modsec-spoa1 10.0.0.102:12345`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		b.WAF = test.waf
		h = c.config.AcquireHost("d1.local")
		h.AddPath(b, "/")
		c.config.Global().ModSecurity.Endpoints = test.endpoints

		c.instance.Update()

		var modsec string
		if test.modsecExp != "" {
			modsec = `
backend spoe-modsecurity
    mode tcp
    timeout connect 5s
    timeout server  5s` + test.modsecExp
		}
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http` + test.backendExp + `
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>` + modsec)

		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceWildcardHostname(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	b.SSLRedirect = true
	h = c.config.AcquireHost("d1.local")
	h.AddPath(b, "/")
	h = c.config.AcquireHost("*.app.d1.local")
	h.AddPath(b, "/")
	h = c.config.AcquireHost("*.sub.d1.local")
	h.AddPath(b, "/")
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d1.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAVerifyOptional = true
	h.TLS.CAErrorPage = "http://sub.d1.local/error.html"

	b = c.config.AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	b.SSLRedirect = false
	h = c.config.AcquireHost("*.d2.local")
	h.AddPath(b, "/")
	h.RootRedirect = "/app"
	h.Timeout.Client = "10s"

	c.instance.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
<<backends-default>>
listen _front__tls
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    ## _front001/_socket001
    use-server _server_socket001 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket001.list }
    server _server_socket001 unix@/var/run/_socket001.sock send-proxy-v2 weight 0
    ## _front001/_socket002
    use-server _server_socket002 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket002.list }
    server _server_socket002 unix@/var/run/_socket002.sock send-proxy-v2 weight 0
    ## _front002/_socket003
    use-server _server_socket003 if { req.ssl_sni -i -f /etc/haproxy/maps/_socket003.list }
    server _server_socket003 unix@/var/run/_socket003.sock send-proxy-v2 weight 0
    ## _front001/_socket001 wildcard
    use-server _server_socket001_wildcard if { req.ssl_sni -i -m reg -f /etc/haproxy/maps/_socket001_regex.list }
    server _server_socket001_wildcard unix@/var/run/_socket001.sock send-proxy-v2 weight 0
    ## _front001/_socket002 wildcard
    use-server _server_socket002_wildcard if { req.ssl_sni -i -m reg -f /etc/haproxy/maps/_socket002_regex.list }
    server _server_socket002_wildcard unix@/var/run/_socket002.sock send-proxy-v2 weight 0
    ## _front002/_socket003 wildcard
    use-server _server_socket003_wildcard if { req.ssl_sni -i -m reg -f /etc/haproxy/maps/_socket003_regex.list }
    server _server_socket003_wildcard unix@/var/run/_socket003.sock send-proxy-v2 weight 0
    # TODO default backend
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request set-var(req.redir) var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch)
    http-request redirect scheme https if { var(req.redir) yes }
    http-request redirect scheme https if { var(req.redir) _nomatch } { var(req.base),map_reg(/etc/haproxy/maps/_global_https_redir_regex.map,_nomatch) yes }
    http-request set-var(req.host) hdr(host),lower,regsub(:[0-9]+/,/)
    http-request set-var(req.rootredir) var(req.host),map(/etc/haproxy/maps/_global_http_root_redir.map,_nomatch)
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_global_http_root_redir_regex.map,_nomatch) if { var(req.rootredir) _nomatch }
    http-request redirect location %[var(req.rootredir)] if { path / } !{ var(req.rootredir) _nomatch }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_global_http_front_regex.map,_nomatch) if { var(req.backend) _nomatch }
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _error404
frontend _front001
    mode http
    bind unix@/var/run/_socket001.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    bind unix@/var/run/_socket002.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem ca-file /var/haproxy/ssl/ca/d1.local.pem verify optional ca-ignore-err all crt-ignore-err all
    http-request set-var(req.base) base,lower,regsub(:[0-9]+/,/)
    http-request set-var(req.hostbackend) var(req.base),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front001_host_regex.map,_nomatch) if { var(req.hostbackend) _nomatch }
    <<tls-del-headers>>
    http-request set-header x-ha-base %[ssl_fc_sni]%[path]
    http-request set-var(req.snibase) hdr(x-ha-base),lower,regsub(:[0-9]+/,/)
    http-request set-var(req.snibackend) var(req.snibase),map_beg(/etc/haproxy/maps/_front001_sni.map,_nomatch)
    http-request set-var(req.snibackend) var(req.snibase),map_reg(/etc/haproxy/maps/_front001_sni_regex.map,_nomatch) if { var(req.snibackend) _nomatch }
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -f /etc/haproxy/maps/_front001_inv_crt.list
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front001_inv_crt_regex.list
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map(/etc/haproxy/maps/_front001_inv_crt_redir.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front001_inv_crt_redir_regex.map,_internal) if { var(req.tls_invalidcrt_redir) _internal }
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) _internal }
    use_backend _error495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    use_backend %[var(req.snibackend)] unless { var(req.snibackend) _nomatch }
    default_backend _error404
frontend _front002
    mode http
    bind unix@/var/run/_socket003.sock accept-proxy ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    timeout client 10s
    http-request set-var(req.base) base,lower,regsub(:[0-9]+/,/)
    http-request set-var(req.hostbackend) var(req.base),map_beg(/etc/haproxy/maps/_front002_host.map,_nomatch)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front002_host_regex.map,_nomatch) if { var(req.hostbackend) _nomatch }
    http-request set-var(req.host) hdr(host),lower,regsub(:[0-9]+/,/)
    http-request set-var(req.rootredir) var(req.host),map(/etc/haproxy/maps/_front002_root_redir.map,_nomatch)
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front002_root_redir_regex.map,_nomatch) if { var(req.rootredir) _nomatch }
    http-request redirect location %[var(req.rootredir)] if { path / } !{ var(req.rootredir) _nomatch }
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _error404
`)

	c.checkMap("_socket001.list", `
d1.local
`)
	c.checkMap("_socket002.list", `
`)
	c.checkMap("_socket003.list", `
`)
	c.checkMap("_socket001_regex.list", `
^[^.]+\.app\.d1\.local$
`)
	c.checkMap("_socket002_regex.list", `
^[^.]+\.sub\.d1\.local$
`)
	c.checkMap("_socket003_regex.list", `
^[^.]+\.d2\.local$
`)
	c.checkMap("_global_http_front.map", `
`)
	c.checkMap("_global_http_front_regex.map", `
^[^.]+\.d2\.local/ d2_app_8080
`)
	c.checkMap("_global_https_redir.map", `
d1.local/ yes
`)
	c.checkMap("_global_https_redir_regex.map", `
^[^.]+\.app\.d1\.local/ yes
^[^.]+\.sub\.d1\.local/ yes
^[^.]+\.d2\.local/ no
`)
	c.checkMap("_global_http_root_redir.map", `
`)
	c.checkMap("_global_http_root_redir_regex.map", `
^[^.]+\.d2\.local$ /app
`)
	c.checkMap("_front001_host.map", `
d1.local/ d1_app_8080
`)
	c.checkMap("_front001_host_regex.map", `
^[^.]+\.app\.d1\.local/ d1_app_8080
`)
	c.checkMap("_front001_sni.map", `
`)
	c.checkMap("_front001_sni_regex.map", `
^[^.]+\.sub\.d1\.local/ d1_app_8080
`)
	c.checkMap("_front001_inv_crt.list", `
`)
	c.checkMap("_front001_inv_crt_regex.list", `
^[^.]+\.sub\.d1\.local$
`)
	c.checkMap("_front001_inv_crt_redir.map", `
`)
	c.checkMap("_front001_inv_crt_redir_regex.map", `
^[^.]+\.sub\.d1\.local$ http://sub.d1.local/error.html
`)
	c.checkMap("_front002_host.map", `
`)
	c.checkMap("_front002_host_regex.map", `
^[^.]+\.d2\.local/ d2_app_8080
`)
	c.checkMap("_front002_root_redir.map", `
`)
	c.checkMap("_front002_root_redir_regex.map", `
^[^.]+\.d2\.local$ /app
`)

	c.logger.CompareLogging(defaultLogging)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  BUILDERS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

type testConfig struct {
	t          *testing.T
	logger     *helper_test.LoggerMock
	bindUtils  *ha_helper.BindUtilsMock
	instance   Instance
	config     Config
	tempdir    string
	configfile string
}

func setup(t *testing.T) *testConfig {
	logger := &helper_test.LoggerMock{T: t}
	tempdir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("error creating tempdir: %v", err)
	}
	configfile := tempdir + "/haproxy.cfg"
	instance := CreateInstance(logger, &ha_helper.BindUtilsMock{}, InstanceOptions{
		HAProxyConfigFile: configfile,
	}).(*instance)
	if err := instance.templates.NewTemplate(
		"haproxy.tmpl",
		"../../rootfs/etc/haproxy/template/haproxy.tmpl",
		configfile,
		0,
		2048,
	); err != nil {
		t.Errorf("error parsing haproxy.tmpl: %v", err)
	}
	if err := instance.mapsTemplate.NewTemplate(
		"map.tmpl",
		"../../rootfs/etc/haproxy/maptemplate/map.tmpl",
		"",
		0,
		2048,
	); err != nil {
		t.Errorf("error parsing map.tmpl: %v", err)
	}
	bindUtils := &ha_helper.BindUtilsMock{}
	config := createConfig(bindUtils, options{
		mapsTemplate: instance.mapsTemplate,
		mapsDir:      tempdir,
	})
	instance.curConfig = config
	config.ConfigDefaultX509Cert("/var/haproxy/ssl/certs/default.pem")
	c := &testConfig{
		t:          t,
		logger:     logger,
		bindUtils:  bindUtils,
		instance:   instance,
		config:     config,
		tempdir:    tempdir,
		configfile: configfile,
	}
	c.configGlobal()
	return c
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
	if err := os.RemoveAll(c.tempdir); err != nil {
		c.t.Errorf("error removing tempdir: %v", err)
	}
}

func (c *testConfig) configGlobal() {
	global := c.config.Global()
	global.Cookie.Key = "Ingress"
	global.MaxConn = 2000
	global.SSL.Ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
	global.SSL.DHParam.Filename = "/var/haproxy/tls/dhparam.pem"
	global.SSL.HeadersPrefix = "X-SSL"
	global.SSL.Options = "no-sslv3"
	global.StatsSocket = "/var/run/haproxy.sock"
	global.Timeout.Client = "50s"
	global.Timeout.ClientFin = "50s"
	global.Timeout.Connect = "5s"
	global.Timeout.HTTPRequest = "5s"
	global.Timeout.KeepAlive = "1m"
	global.Timeout.Queue = "5s"
	global.Timeout.Server = "50s"
	global.Timeout.ServerFin = "50s"
	global.Timeout.Stop = "15m"
	global.Timeout.Tunnel = "1h"
}

var endpointS0 = &hatypes.Endpoint{
	Name:   "s0",
	IP:     "172.17.0.99",
	Port:   8080,
	Weight: 100,
}
var endpointS1 = &hatypes.Endpoint{
	Name:   "s1",
	IP:     "172.17.0.11",
	Port:   8080,
	Weight: 100,
}
var endpointS21 = &hatypes.Endpoint{
	Name:   "s21",
	IP:     "172.17.0.121",
	Port:   8080,
	Weight: 100,
}
var endpointS22 = &hatypes.Endpoint{
	Name:   "s22",
	IP:     "172.17.0.122",
	Port:   8080,
	Weight: 100,
}
var endpointS31 = &hatypes.Endpoint{
	Name:   "s31",
	IP:     "172.17.0.131",
	Port:   8080,
	Weight: 100,
}
var endpointS32 = &hatypes.Endpoint{
	Name:   "s32",
	IP:     "172.17.0.132",
	Port:   8080,
	Weight: 100,
}
var endpointS33 = &hatypes.Endpoint{
	Name:   "s33",
	IP:     "172.17.0.133",
	Port:   8080,
	Weight: 100,
}
var endpointS41s = &hatypes.Endpoint{
	Name:   "s41s",
	IP:     "172.17.0.141",
	Port:   8443,
	Weight: 100,
}
var endpointS41h = &hatypes.Endpoint{
	Name:   "s41h",
	IP:     "172.17.0.141",
	Port:   8080,
	Weight: 100,
}

var defaultLogging = `
INFO (test) reload was skipped
INFO HAProxy successfully reloaded`

func _yamlMarshal(in interface{}) string {
	out, _ := yaml.Marshal(in)
	return string(out)
}

func (c *testConfig) checkConfig(expected string) {
	actual := strings.Replace(c.readConfig(c.configfile), c.tempdir, "/etc/haproxy/maps", -1)
	replace := map[string]string{
		"<<global>>": `global
    daemon
    stats socket /var/run/haproxy.sock level admin expose-fd listeners
    maxconn 2000
    hard-stop-after 15m
    lua-load /usr/local/etc/haproxy/lua/send-response.lua
    lua-load /usr/local/etc/haproxy/lua/auth-request.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-options no-sslv3`,
		"<<defaults>>": `defaults
    log global
    maxconn 2000
    option redispatch
    option dontlognull
    option http-server-close
    option http-keep-alive
    timeout client          50s
    timeout client-fin      50s
    timeout connect         5s
    timeout http-keep-alive 1m
    timeout http-request    5s
    timeout queue           5s
    timeout server          50s
    timeout server-fin      50s
    timeout tunnel          1h`,
		"<<backend-errors>>": `backend _error495
    mode http
    errorfile 400 /usr/local/etc/haproxy/errors/495.http
    http-request deny deny_status 400
backend _error496
    mode http
    errorfile 400 /usr/local/etc/haproxy/errors/496.http
    http-request deny deny_status 400`,
		"<<backends-default>>": `backend _error404
    mode http
    errorfile 400 /usr/local/etc/haproxy/errors/404.http
    http-request deny deny_status 400
<<backend-errors>>`,
		"    <<tls-del-headers>>": `    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert`,
		"<<frontends-default>>": `frontend _front_http
    mode http
    bind :80
    http-request set-var(req.base) base,regsub(:[0-9]+/,/)
    http-request redirect scheme https if { var(req.base),map_beg(/etc/haproxy/maps/_global_https_redir.map,_nomatch) yes }
    <<tls-del-headers>>
    http-request set-var(req.backend) var(req.base),map_beg(/etc/haproxy/maps/_global_http_front.map,_nomatch)
    use_backend %[var(req.backend)] unless { var(req.backend) _nomatch }
    default_backend _error404
frontend _front001
    mode http
    bind :443 ssl alpn h2,http/1.1 crt /var/haproxy/ssl/certs/default.pem
    http-request set-var(req.hostbackend) base,lower,regsub(:[0-9]+/,/),map_beg(/etc/haproxy/maps/_front001_host.map,_nomatch)
    <<tls-del-headers>>
    use_backend %[var(req.hostbackend)] unless { var(req.hostbackend) _nomatch }
    default_backend _error404`,
	}
	for {
		changed := false
		for old, new := range replace {
			after := strings.Replace(expected, old, new, -1)
			if after != expected {
				changed = true
			}
			expected = after
		}
		if !changed {
			break
		}
	}
	c.compareText("haproxy.cfg", actual, expected)
}

func (c *testConfig) checkMap(mapName, expected string) {
	actual := c.readConfig(c.tempdir + "/" + mapName)
	c.compareText(mapName, actual, expected)
}

func (c *testConfig) checkCerts(expected string) {
	actual := _yamlMarshal(c.bindUtils)
	c.compareText("certs", actual, expected)
}

var replaceComments = regexp.MustCompile(`(?m)^[ \t]{0,2}(#.*)?[\r\n]+`)

func (c *testConfig) readConfig(fileName string) string {
	config, err := ioutil.ReadFile(fileName)
	if err != nil {
		c.t.Errorf("error reading config file: %v", err)
		return ""
	}
	configStr := replaceComments.ReplaceAllString(string(config), ``)
	return configStr
}

func (c *testConfig) compareText(name, actual, expected string) {
	txtActual := "\n" + strings.Trim(actual, "\n")
	txtExpected := "\n" + strings.Trim(expected, "\n")
	if txtActual != txtExpected {
		c.t.Error("\ndiff of " + name + ":" + diff.Diff(txtExpected, txtActual))
	}
}
