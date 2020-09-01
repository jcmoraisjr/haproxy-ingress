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
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
	yaml "gopkg.in/yaml.v2"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  BACKEND TESTCASES
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

func TestBackends(t *testing.T) {
	testCases := []struct {
		doconfig  func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend)
		path      []string
		skipSrv   bool
		srvsuffix string
		expected  string
		expFronts string
		expCheck  map[string]string
	}{
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "ingress-controller"
				b.Cookie.Strategy = "insert"
				b.Cookie.Keywords = "indirect nocache httponly"
			},
			srvsuffix: "cookie s1",
			expected: `
    cookie ingress-controller insert indirect nocache httponly`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "Ingress"
				b.Cookie.Strategy = "prefix"
				b.Cookie.Dynamic = true
			},
			expected: `
    cookie Ingress prefix dynamic
    dynamic-cookie-key "Ingress"`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "Ingress"
				b.Cookie.Strategy = "insert"
				b.Cookie.Dynamic = true
				b.Cookie.Shared = true
				b.Cookie.Keywords = "indirect nocache httponly"
				h.AddPath(b, "/other", hatypes.MatchBegin)
			},
			expected: `
    cookie Ingress insert indirect nocache httponly domain d1.local dynamic
    dynamic-cookie-key "Ingress"`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:      true,
					AllowOrigin:  "*",
					AllowHeaders: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:       86400,
				}
				b.Cors = []*hatypes.BackendConfigCors{
					{
						Paths:  createBackendPaths(b, "d1.local/", "d1.local/sub"),
						Config: config,
					},
				}
			},
			path: []string{"/", "/sub"},
			expected: `
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS
    http-request use-service lua.send-cors-preflight if METH_OPTIONS
    http-response set-header Access-Control-Allow-Origin  "*"
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:          true,
					AllowOrigin:      "*",
					AllowHeaders:     "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods:     "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:           86400,
					AllowCredentials: true,
				}
				b.Cors = []*hatypes.BackendConfigCors{
					{
						Paths:  createBackendPaths(b, "d1.local/"),
						Config: config,
					},
					{
						Paths:  createBackendPaths(b, "d1.local/sub"),
						Config: hatypes.Cors{},
					},
				}
			},
			path: []string{"/", "/sub"},
			expected: `
    # path01 = d1.local/
    # path02 = d1.local/sub
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS { var(txn.pathID) path01 }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) path01 }
    http-response set-header Access-Control-Allow-Origin  "*" if { var(txn.pathID) path01 }
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) path01 }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization" if { var(txn.pathID) path01 }
    http-response set-header Access-Control-Allow-Credentials "true" if { var(txn.pathID) path01 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/sub path02
d1.local/ path01`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.HSTS = []*hatypes.BackendConfigHSTS{
					{
						Paths: createBackendPaths(b, "d1.local/"),
						Config: hatypes.HSTS{
							Enabled:    true,
							MaxAge:     15768000,
							Preload:    true,
							Subdomains: true,
						},
					},
					{
						Paths: createBackendPaths(b, "d1.local/path", "d1.local/uri"),
						Config: hatypes.HSTS{
							Enabled:    true,
							MaxAge:     15768000,
							Preload:    false,
							Subdomains: false,
						},
					},
				}
			},
			path: []string{"/", "/path", "/uri"},
			expected: `
    acl https-request ssl_fc
    # path01 = d1.local/
    # path02 = d1.local/path
    # path03 = d1.local/uri
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" if https-request { var(txn.pathID) path01 }
    http-response set-header Strict-Transport-Security "max-age=15768000" if https-request { var(txn.pathID) path02 path03 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/uri path03
d1.local/path path02
d1.local/ path01`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				g.ForwardFor = "add"
			},
			expected: `
    http-request set-header X-Original-Forwarded-For %[hdr(x-forwarded-for)] if { hdr(x-forwarded-for) -m found }
    http-request del-header x-forwarded-for
    option forwardfor`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.RewriteURL = []*hatypes.BackendConfigStr{
					{
						Paths:  createBackendPaths(b, "d1.local/app"),
						Config: "/",
					},
				}
			},
			path: []string{"/app"},
			expected: `
    http-request replace-uri ^/app/?(.*)$     /\1`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.RewriteURL = []*hatypes.BackendConfigStr{
					{
						Paths:  createBackendPaths(b, "d1.local/app"),
						Config: "/other",
					},
				}
			},
			path: []string{"/app"},
			expected: `
    http-request replace-uri ^/app(.*)$       /other\1`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.RewriteURL = []*hatypes.BackendConfigStr{
					{
						Paths:  createBackendPaths(b, "d1.local/app", "d1.local/app/sub"),
						Config: "/other/",
					},
				}
			},
			path: []string{"/app", "/app/sub"},
			expected: `
    http-request replace-uri ^/app(.*)$       /other/\1
    http-request replace-uri ^/app/sub(.*)$       /other/\1`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.RewriteURL = []*hatypes.BackendConfigStr{
					{
						Paths:  createBackendPaths(b, "d1.local/path1"),
						Config: "/sub1",
					},
					{
						Paths:  createBackendPaths(b, "d1.local/path2", "d1.local/path3"),
						Config: "/sub2",
					},
				}
			},
			path: []string{"/path1", "/path2", "/path3"},
			expected: `
    # path01 = d1.local/path1
    # path02 = d1.local/path2
    # path03 = d1.local/path3
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request replace-uri ^/path1(.*)$       /sub1\1     if { var(txn.pathID) path01 }
    http-request replace-uri ^/path2(.*)$       /sub2\1     if { var(txn.pathID) path02 }
    http-request replace-uri ^/path3(.*)$       /sub2\1     if { var(txn.pathID) path03 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/path3 path03
d1.local/path2 path02
d1.local/path1 path01`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.WhitelistHTTP = []*hatypes.BackendConfigWhitelist{
					{
						Paths:  createBackendPaths(b, "d1.local/app", "d1.local/api"),
						Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
					},
					{
						Paths:  createBackendPaths(b, "d1.local/path"),
						Config: []string{"192.168.95.0/24"},
					},
				}
			},
			path: []string{"/app", "/api", "/path"},
			expected: `
    # path02 = d1.local/api
    # path01 = d1.local/app
    # path03 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    acl wlist_src0 src 10.0.0.0/8 192.168.0.0/16
    http-request deny if { var(txn.pathID) path02 path01 } !wlist_src0
    acl wlist_src1 src 192.168.95.0/24
    http-request deny if { var(txn.pathID) path03 } !wlist_src1`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/path path03
d1.local/app path01
d1.local/api path02`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				h.FindPath("/app").Match = hatypes.MatchExact
				h.FindPath("/path").Match = hatypes.MatchPrefix
				h.FindPath("/api/v[0-9]+/").Match = hatypes.MatchRegex
				b.WhitelistHTTP = []*hatypes.BackendConfigWhitelist{
					{
						Paths:  createBackendPaths(b, "d1.local/app", "d1.local/api", "d1.local/path", "d1.local/api/v[0-9]+/"),
						Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
					},
					{
						Paths:  createBackendPaths(b, "d1.local/"),
						Config: []string{"172.17.0.0/16"},
					},
				}
			},
			path: []string{"/", "/app", "/api", "/path", "/api/v[0-9]+/"},
			expected: `
    # path01 = d1.local/
    # path03 = d1.local/api
    # path05 = d1.local/api/v[0-9]+/
    # path02 = d1.local/app
    # path04 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),map_str(/etc/haproxy/maps/_back_d1_app_8080_idpath__exact.map)
    http-request set-var(txn.pathID) var(req.base),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpath__prefix.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) var(req.base),map_reg(/etc/haproxy/maps/_back_d1_app_8080_idpath__regex.map) if !{ var(txn.pathID) -m found }
    acl wlist_src0 src 10.0.0.0/8 192.168.0.0/16
    http-request deny if { var(txn.pathID) path03 path05 path02 path04 } !wlist_src0
    acl wlist_src1 src 172.17.0.0/16
    http-request deny if { var(txn.pathID) path01 } !wlist_src1`,
			expFronts: "<<frontends-default-match-4>>",
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__exact.map": `
d1.local/app path02`,
				"_back_d1_app_8080_idpath__prefix.map": `
d1.local/path path04`,
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/api path03
d1.local/ path01`,
				"_back_d1_app_8080_idpath__regex.map": `
^d1\.local/api/v[0-9]+/ path05`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.WhitelistHTTP = []*hatypes.BackendConfigWhitelist{
					{
						Paths:  createBackendPaths(b, "d1.local/app", "d1.local/api"),
						Config: []string{},
					},
					{
						Paths: createBackendPaths(b, "d1.local/path"),
						Config: []string{
							"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5",
							"1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10",
							"1.1.1.11",
						},
					},
				}
			},
			path: []string{"/app", "/api", "/path"},
			expected: `
    # path02 = d1.local/api
    # path01 = d1.local/app
    # path03 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    acl wlist_src1 src 1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 1.1.1.8 1.1.1.9 1.1.1.10
    acl wlist_src1 src 1.1.1.11
    http-request deny if { var(txn.pathID) path03 } !wlist_src1`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/path path03
d1.local/app path01
d1.local/api path02`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.WhitelistTCP = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.ModeTCP = true
			},
			expected: `
    acl wlist_src src 10.0.0.0/8 192.168.0.0/16
    tcp-request content reject if !wlist_src`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.MaxBodySize = b.CreateConfigInt(1024)
			},
			path: []string{"/", "/app"},
			expected: `
    http-request use-service lua.send-413 if { req.body_size,sub(1024) gt 0 }`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.MaxBodySize = []*hatypes.BackendConfigInt{
					{
						Paths:  createBackendPaths(b, "d1.local/app"),
						Config: 2048,
					},
					{
						Paths:  createBackendPaths(b, "d1.local/"),
						Config: 0,
					},
				}
			},
			path: []string{"/", "/app"},
			expected: `
    # path01 = d1.local/
    # path02 = d1.local/app
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request use-service lua.send-413 if { var(txn.pathID) path02 } { req.body_size,sub(2048) gt 0 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local/app path02
d1.local/ path01`,
			},
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Headers = []*hatypes.BackendHeader{
					{Name: "Name", Value: "Value"},
				}
			},
			expected: `
    http-request set-header Name Value`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Headers = []*hatypes.BackendHeader{
					{Name: "X-ID", Value: "abc"},
					{Name: "Host", Value: "app.domain"},
				}
			},
			expected: `
    http-request set-header X-ID abc
    http-request set-header Host app.domain`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
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
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.HealthCheck.Interval = "2s"
			},
			srvsuffix: "check inter 2s",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.HealthCheck.URI = "/check"
				b.HealthCheck.Port = 4000
			},
			expected: `
    option httpchk /check`,
			srvsuffix: "check port 4000",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.AgentCheck.Port = 8000
				b.AgentCheck.Interval = "2s"
			},
			srvsuffix: "agent-check agent-port 8000 agent-inter 2s",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
			},
			srvsuffix: "ssl verify none",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.Ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256"
				b.Server.CipherSuites = "TLS_AES_128_GCM_SHA256"
			},
			srvsuffix: "ssl ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ciphersuites TLS_AES_128_GCM_SHA256 verify none",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CrtFilename = "/var/haproxy/ssl/client.pem"
				b.Server.CipherSuites = "TLS_AES_128_GCM_SHA256"
				b.Server.Options = "no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets"
			},
			srvsuffix: "ssl ciphersuites TLS_AES_128_GCM_SHA256 no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets crt /var/haproxy/ssl/client.pem verify none",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CrtFilename = "/var/haproxy/ssl/client.pem"
			},
			srvsuffix: "ssl crt /var/haproxy/ssl/client.pem verify none",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
			},
			srvsuffix: "ssl verify required ca-file /var/haproxy/ssl/ca.pem",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
				b.Server.CRLFilename = "/var/haproxy/ssl/crl.pem"
			},
			srvsuffix: "ssl verify required ca-file /var/haproxy/ssl/ca.pem crl-file /var/haproxy/ssl/crl.pem",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Protocol = "h2"
			},
			srvsuffix: "proto h2",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Protocol = "h2"
				b.Server.Secure = true
			},
			srvsuffix: "proto h2 alpn h2 ssl verify none",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Protocol = "h2"
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
			},
			srvsuffix: "proto h2 alpn h2 ssl verify required ca-file /var/haproxy/ssl/ca.pem",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Limit.Connections = 200
				b.Limit.RPS = 20
				b.Limit.Whitelist = []string{"192.168.0.0/16", "10.1.1.101"}
			},
			expected: `
    stick-table type ip size 200k expire 5m store conn_cur,conn_rate(1s)
    http-request track-sc1 src
    acl wlist_conn src 192.168.0.0/16 10.1.1.101
    http-request deny deny_status 429 if !wlist_conn { sc1_conn_cur gt 200 }
    http-request deny deny_status 429 if !wlist_conn { sc1_conn_rate gt 20 }`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Limit.RPS = 20
			},
			expected: `
    stick-table type ip size 200k expire 5m store conn_cur,conn_rate(1s)
    http-request track-sc1 src
    http-request deny deny_status 429 if { sc1_conn_rate gt 20 }`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Limit.Connections = 200
			},
			expected: `
    stick-table type ip size 200k expire 5m store conn_cur,conn_rate(1s)
    http-request track-sc1 src
    http-request deny deny_status 429 if { sc1_conn_cur gt 200 }`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.ModeTCP = true
				b.Limit.Connections = 200
				b.Limit.RPS = 20
				b.Limit.Whitelist = []string{"192.168.0.0/16", "10.1.1.101"}
			},
			expected: `
    stick-table type ip size 200k expire 5m store conn_cur,conn_rate(1s)
    tcp-request content track-sc1 src
    acl wlist_conn src 192.168.0.0/16 10.1.1.101
    tcp-request content reject if !wlist_conn { sc1_conn_cur gt 200 }
    tcp-request content reject if !wlist_conn { sc1_conn_rate gt 20 }`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.SendProxy = "send-proxy-v2"
			},
			srvsuffix: "send-proxy-v2",
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.BlueGreen.CookieName = "ServerName"
				e1, e2, e3 := *endpointS31, *endpointS32, *endpointS33
				b.Endpoints = []*hatypes.Endpoint{&e1, &e2, &e3}
				b.Endpoints[0].Label = "blue"
			},
			skipSrv: true,
			expected: `
    use-server s31 if { req.cook(ServerName) blue }
    server s31 172.17.0.131:8080 weight 100
    server s32 172.17.0.132:8080 weight 100
    server s33 172.17.0.133:8080 weight 100`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.BlueGreen.HeaderName = "X-Svc"
				e1, e2, e3 := *endpointS31, *endpointS32, *endpointS33
				b.Endpoints = []*hatypes.Endpoint{&e1, &e2, &e3}
				b.Endpoints[1].Label = "green"
			},
			skipSrv: true,
			expected: `
    use-server s32 if { req.hdr(X-Svc) green }
    server s31 172.17.0.131:8080 weight 100
    server s32 172.17.0.132:8080 weight 100
    server s33 172.17.0.133:8080 weight 100`,
		},
		{
			doconfig: func(g *hatypes.Global, h *hatypes.Host, b *hatypes.Backend) {
				b.BlueGreen.CookieName = "ServerName"
				b.BlueGreen.HeaderName = "X-Svc"
				e1, e2, e3 := *endpointS31, *endpointS32, *endpointS33
				b.Endpoints = []*hatypes.Endpoint{&e1, &e2, &e3}
				b.Endpoints[1].Label = "green"
				b.Endpoints[2].Label = "green"
			},
			skipSrv: true,
			expected: `
    use-server s32 if { req.hdr(X-Svc) green }
    use-server s33 if { req.hdr(X-Svc) green }
    use-server s32 if { req.cook(ServerName) green }
    use-server s33 if { req.cook(ServerName) green }
    server s31 172.17.0.131:8080 weight 100
    server s32 172.17.0.132:8080 weight 100
    server s33 172.17.0.133:8080 weight 100`,
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

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		for _, p := range test.path {
			h.AddPath(b, p, hatypes.MatchBegin)
		}
		test.doconfig(c.config.Global(), h, b)

		var mode string
		if b.ModeTCP {
			mode = "tcp"
		} else {
			mode = "http"
		}

		if test.expFronts == "" {
			test.expFronts = "<<frontends-default>>"
		}

		var srv string
		if !test.skipSrv {
			srv = `
    server s1 172.17.0.11:8080 weight 100` + test.srvsuffix
		}
		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode ` + mode + test.expected + srv + `
<<backends-default>>
` + test.expFronts + `
<<support>>
`)

		for mapName, content := range test.expCheck {
			c.checkMap(mapName, content)
		}

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

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceGlobalBind(t *testing.T) {
	testCases := []struct {
		bind          hatypes.GlobalBindConfig
		expectedHTTP  string
		expectedHTTPS string
	}{
		// 0
		{},
		// 1
		{
			bind: hatypes.GlobalBindConfig{
				HTTPBind:    ":80",
				HTTPSBind:   ":443",
				AcceptProxy: true,
			},
			expectedHTTP:  "bind :80 accept-proxy",
			expectedHTTPS: "bind :443 accept-proxy ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all",
		},
		// 2
		{
			bind: hatypes.GlobalBindConfig{
				HTTPBind:  "127.0.0.1:80",
				HTTPSBind: "127.0.0.1:443",
			},
			expectedHTTP:  "bind 127.0.0.1:80",
			expectedHTTPS: "bind 127.0.0.1:443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all",
		},
	}
	for _, test := range testCases {
		c := setup(t)
		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		h.AddPath(b, "/", hatypes.MatchBegin)

		c.config.Global().Bind = test.bind
		if test.expectedHTTP != "" {
			test.expectedHTTP = "\n    " + test.expectedHTTP
		}
		if test.expectedHTTPS != "" {
			test.expectedHTTPS = "\n    " + test.expectedHTTPS
		}

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http` + test.expectedHTTP + `
    <<https-redirect>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http` + test.expectedHTTPS + `
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceEmpty(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.Hosts().AcquireHost("empty").AddPath(c.config.Backends().AcquireBackend("default", "empty", "8080"), "/", hatypes.MatchBegin)
	c.Update()

	c.checkConfig(`
global
    daemon
    unix-bind user haproxy group haproxy mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
    ssl-default-bind-options no-sslv3
    ssl-default-server-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256
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
    http-request use-service lua.send-404
<<frontends-default>>
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
empty/ default_empty_8080`)
	c.checkMap("_front_redir_tohttps__begin.map", `
empty/ no`)
	c.checkMap("_front_https_host__begin.map", `
empty/ default_empty_8080`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceMatch(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	b := c.config.Backends().AcquireBackend("default", "d1", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h := c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/app", hatypes.MatchPrefix)
	h.AddPath(b, "/api/v[0-9]+/", hatypes.MatchRegex)
	c.Update()

	c.checkConfig(`
<<global>>
<<defaults>>
backend default_d1_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),map_dir(/etc/haproxy/maps/_front_redir_tohttps__prefix.map)
    http-request set-var(req.redir) var(req.base),map_reg(/etc/haproxy/maps/_front_redir_tohttps__regex.map) if !{ var(req.redir) -m found }
    http-request redirect scheme https if { var(req.redir) yes }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_dir(/etc/haproxy/maps/_front_http_host__prefix.map)
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map) if !{ var(req.backend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),map_dir(/etc/haproxy/maps/_front_https_host__prefix.map)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_redir_tohttps__prefix.map", `
d1.local/app no`)
	c.checkMap("_front_redir_tohttps__regex.map", `
^d1\.local/api/v[0-9]+/ no`)
	c.checkMap("_front_http_host__prefix.map", `
d1.local/app default_d1_8080`)
	c.checkMap("_front_http_host__regex.map", `
^d1\.local/api/v[0-9]+/ default_d1_8080`)
	c.checkMap("_front_https_host__prefix.map", `
d1.local/app default_d1_8080`)
	c.checkMap("_front_https_host__regex.map", `
^d1\.local/api/v[0-9]+/ default_d1_8080`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontingProxyUseProto(t *testing.T) {
	testCases := []struct {
		frontingBind     string
		domain           string
		expectedFront    string
		expectedMap      string
		expectedRegexMap string
		expectedACL      string
		expectedSetvar   string
	}{
		// 0
		{
			frontingBind: ":8000",
			domain:       "d1.local",
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    acl fronting-proxy so_id 11
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map) if !fronting-proxy
    http-request redirect scheme https if !fronting-proxy { var(req.redir) yes }
    http-request set-header X-Forwarded-Proto http if !fronting-proxy
    http-request del-header X-SSL-Client-CN if !fronting-proxy
    http-request del-header X-SSL-Client-DN if !fronting-proxy
    http-request del-header X-SSL-Client-SHA1 if !fronting-proxy
    http-request del-header X-SSL-Client-Cert if !fronting-proxy
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap: "d1.local/ d1_app_8080",
			expectedACL: `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list`,
			expectedSetvar: `
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map)
    http-request set-var(req.snibackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt`,
		},
		// 1
		{
			frontingBind: ":8000",
			domain:       "*.d1.local",
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    acl fronting-proxy so_id 11
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),map_reg(/etc/haproxy/maps/_front_redir_tohttps__regex.map) if !fronting-proxy
    http-request redirect scheme https if !fronting-proxy { var(req.redir) yes }
    http-request set-header X-Forwarded-Proto http if !fronting-proxy
    http-request del-header X-SSL-Client-CN if !fronting-proxy
    http-request del-header X-SSL-Client-DN if !fronting-proxy
    http-request del-header X-SSL-Client-SHA1 if !fronting-proxy
    http-request del-header X-SSL-Client-Cert if !fronting-proxy
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedRegexMap: `^[^.]+\.d1\.local/ d1_app_8080`,
			expectedACL: `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-host-need-crt var(req.host) -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list`,
			expectedSetvar: `
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map)
    http-request set-var(req.snibackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt`,
		},
		// 2
		{
			frontingBind: ":80",
			domain:       "d1.local",
			expectedFront: `
    mode http
    bind :80
    acl fronting-proxy hdr(X-Forwarded-Proto) -m found
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map) if !fronting-proxy
    http-request redirect scheme https if !fronting-proxy { var(req.redir) yes }
    http-request set-header X-Forwarded-Proto http if !fronting-proxy
    http-request del-header X-SSL-Client-CN if !fronting-proxy
    http-request del-header X-SSL-Client-DN if !fronting-proxy
    http-request del-header X-SSL-Client-SHA1 if !fronting-proxy
    http-request del-header X-SSL-Client-Cert if !fronting-proxy
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap: "d1.local/ d1_app_8080",
			expectedACL: `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list`,
			expectedSetvar: `
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map)
    http-request set-var(req.snibackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		h = c.config.Hosts().AcquireHost(test.domain)
		h.AddPath(b, "/", hatypes.MatchBegin)
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		b.HSTS = []*hatypes.BackendConfigHSTS{
			{
				Paths: createBackendPaths(b, test.domain+"/"),
				Config: hatypes.HSTS{
					Enabled:    true,
					MaxAge:     15768000,
					Subdomains: true,
					Preload:    true,
				},
			},
		}
		h.TLS.CAHash = "1"
		h.TLS.CAFilename = "/var/haproxy/ssl/ca.pem"
		c.config.Global().Bind.FrontingBind = test.frontingBind
		c.config.Global().Bind.FrontingSockID = 11
		c.config.Global().Bind.FrontingUseProto = true

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl https-request ssl_fc
    acl https-request var(txn.proto) https
    acl local-offload ssl_fc
    http-request set-var(txn.proto) hdr(X-Forwarded-Proto)
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if local-offload
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if local-offload
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if local-offload
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" if https-request
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http` + test.expectedFront + `
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert` + test.expectedACL + test.expectedSetvar + `
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-496 if { var(req.tls_nocrt_redir) _internal }
    http-request use-service lua.send-421 if !tls-has-crt tls-host-need-crt
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend _error404
<<support>>
`)
		if test.expectedMap != "" {
			c.checkMap("_front_http_host__begin.map", test.expectedMap)
		}
		if test.expectedRegexMap != "" {
			c.checkMap("_front_http_host__regex.map", test.expectedRegexMap)
		}
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceFrontingProxyIgnoreProto(t *testing.T) {
	testCases := []struct {
		frontingBind     string
		domain           string
		expectedFront    string
		expectedMap      string
		expectedRegexMap string
		expectedACL      string
		expectedSetvar   string
	}{
		// 0
		{
			frontingBind: ":8000",
			domain:       "d1.local",
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap: "d1.local/ d1_app_8080",
			expectedACL: `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list`,
			expectedSetvar: `
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map)
    http-request set-var(req.snibackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt`,
		},
		// 1
		{
			frontingBind: ":8000",
			domain:       "*.d1.local",
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedRegexMap: `^[^.]+\.d1\.local/ d1_app_8080`,
			expectedACL: `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-host-need-crt var(req.host) -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list`,
			expectedSetvar: `
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map)
    http-request set-var(req.snibackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt`,
		},
		// 2
		{
			frontingBind: ":80",
			domain:       "d1.local",
			expectedFront: `
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap: "d1.local/ d1_app_8080",
			expectedACL: `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list`,
			expectedSetvar: `
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map)
    http-request set-var(req.snibackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		h = c.config.Hosts().AcquireHost(test.domain)
		h.AddPath(b, "/", hatypes.MatchBegin)
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		b.HSTS = []*hatypes.BackendConfigHSTS{
			{
				Paths: createBackendPaths(b, test.domain+"/"),
				Config: hatypes.HSTS{
					Enabled:    true,
					MaxAge:     15768000,
					Subdomains: true,
					Preload:    true,
				},
			},
		}
		h.TLS.CAHash = "1"
		h.TLS.CAFilename = "/var/haproxy/ssl/ca.pem"
		c.config.Global().Bind.FrontingBind = test.frontingBind
		c.config.Global().Bind.FrontingSockID = 11
		c.config.Global().Bind.FrontingUseProto = false

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl local-offload ssl_fc
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if local-offload
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if local-offload
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if local-offload
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload"
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http` + test.expectedFront + `
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert` + test.expectedACL + test.expectedSetvar + `
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-496 if { var(req.tls_nocrt_redir) _internal }
    http-request use-service lua.send-421 if !tls-has-crt tls-host-need-crt
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend _error404
<<support>>
`)
		if test.expectedMap != "" {
			c.checkMap("_front_http_host__begin.map", test.expectedMap)
		}
		if test.expectedRegexMap != "" {
			c.checkMap("_front_http_host__regex.map", test.expectedRegexMap)
		}
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceTCPBackend(t *testing.T) {
	testCases := []struct {
		doconfig func(c *testConfig)
		expected string
		logging  string
	}{
		// 0
		{
			doconfig: func(c *testConfig) {
				b := c.config.TCPBackends().Acquire("postgresql", 5432)
				b.AddEndpoint("172.17.0.2", 5432)
			},
			expected: `
listen _tcp_postgresql_5432
    bind :5432
    mode tcp
    server srv001 172.17.0.2:5432`,
		},
		// 1
		{
			doconfig: func(c *testConfig) {
				b := c.config.TCPBackends().Acquire("pq", 5432)
				b.AddEndpoint("172.17.0.2", 5432)
				b.AddEndpoint("172.17.0.3", 5432)
				b.CheckInterval = "2s"
			},
			expected: `
listen _tcp_pq_5432
    bind :5432
    mode tcp
    server srv001 172.17.0.2:5432 check port 5432 inter 2s
    server srv002 172.17.0.3:5432 check port 5432 inter 2s`,
		},
		// 2
		{
			doconfig: func(c *testConfig) {
				b := c.config.TCPBackends().Acquire("pq", 5432)
				b.AddEndpoint("172.17.0.2", 5432)
				b.SSL.Filename = "/var/haproxy/ssl/pq.pem"
				b.ProxyProt.EncodeVersion = "v2"
			},
			expected: `
listen _tcp_pq_5432
    bind :5432 ssl crt /var/haproxy/ssl/pq.pem
    mode tcp
    server srv001 172.17.0.2:5432 send-proxy-v2`,
		},
		// 3
		{
			doconfig: func(c *testConfig) {
				b := c.config.TCPBackends().Acquire("pq", 5432)
				b.AddEndpoint("172.17.0.2", 5432)
				b.SSL.Filename = "/var/haproxy/ssl/pq.pem"
				b.ProxyProt.Decode = true
				b.ProxyProt.EncodeVersion = "v1"
				b.CheckInterval = "2s"
				c.config.Global().Bind.TCPBindIP = "127.0.0.1"
			},
			expected: `
listen _tcp_pq_5432
    bind 127.0.0.1:5432 ssl crt /var/haproxy/ssl/pq.pem accept-proxy
    mode tcp
    server srv001 172.17.0.2:5432 check port 5432 inter 2s send-proxy`,
		},
		// 4
		{
			doconfig: func(c *testConfig) {
				b := c.config.TCPBackends().Acquire("pq", 5432)
				b.AddEndpoint("172.17.0.2", 5432)
				b.SSL.Filename = "/var/haproxy/ssl/pq.pem"
				b.SSL.CAFilename = "/var/haproxy/ssl/pqca.pem"
				b.ProxyProt.EncodeVersion = "v2"
			},
			expected: `
listen _tcp_pq_5432
    bind :5432 ssl crt /var/haproxy/ssl/pq.pem ca-file /var/haproxy/ssl/pqca.pem verify required
    mode tcp
    server srv001 172.17.0.2:5432 send-proxy-v2`,
		},
		// 5
		{
			doconfig: func(c *testConfig) {
				b := c.config.TCPBackends().Acquire("pq", 5432)
				b.AddEndpoint("172.17.0.2", 5432)
				b.SSL.Filename = "/var/haproxy/ssl/pq.pem"
				b.SSL.CAFilename = "/var/haproxy/ssl/pqca.pem"
				b.SSL.CRLFilename = "/var/haproxy/ssl/pqcrl.pem"
				b.ProxyProt.EncodeVersion = "v2"
			},
			expected: `
listen _tcp_pq_5432
    bind :5432 ssl crt /var/haproxy/ssl/pq.pem ca-file /var/haproxy/ssl/pqca.pem verify required crl-file /var/haproxy/ssl/pqcrl.pem
    mode tcp
    server srv001 172.17.0.2:5432 send-proxy-v2`,
		},
	}
	for _, test := range testCases {
		c := setup(t)
		test.doconfig(c)
		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>` + test.expected + `
backend _error404
    mode http
    http-request use-service lua.send-404
<<frontend-http-clean>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
<<support>>
`)
		logging := test.logging
		if logging == "" {
			logging = defaultLogging
		}
		c.logger.CompareLogging(logging)
		c.teardown()
	}
}

func TestInstanceDefaultHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().SetDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	h = c.config.Hosts().AcquireHost(hatypes.DefaultHost)
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/app", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true

	c.Update()
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
frontend _front_http
    mode http
    bind :80
    <<https-redirect>>
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map)
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<http-headers>>
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    use_backend d1_app_8080
    default_backend _default_backend
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map)
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend d1_app_8080
    default_backend _default_backend
<<support>>
`)

	c.checkMap("_front_redir_tohttps__begin.map", `
d2.local/app yes
`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem
`)
	c.checkMap("_front_namespace__begin.map", `
d2.local/app d2
`)
	c.checkMap("_front_https_host__begin.map", `
d2.local/app d2_app_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceStrictHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/path", hatypes.MatchBegin)
	c.config.Global().StrictHost = true

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>
`)
	c.checkMap("_front_redir_tohttps__begin.map", `
d1.local/path no
d1.local/ no
`)
	c.checkMap("_front_http_host__begin.map", `
d1.local/path d1_app_8080
d1.local/ _error404
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local/path d1_app_8080
d1.local/ _error404
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceStrictHostDefaultHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/path", hatypes.MatchBegin)

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h = c.config.Hosts().AcquireHost(hatypes.DefaultHost)
	h.AddPath(b, "/", hatypes.MatchBegin)

	c.config.Global().StrictHost = true

	c.Update()
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
<<frontend-http>>
    use_backend d2_app_8080
    default_backend _error404
<<frontend-https>>
    use_backend d2_app_8080
    default_backend _error404
<<support>>
`)
	c.checkMap("_front_redir_tohttps__begin.map", `
d1.local/path no
d1.local/ no
`)
	c.checkMap("_front_http_host__begin.map", `
d1.local/path d1_app_8080
d1.local/ d2_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local/path d1_app_8080
d1.local/ d2_app_8080
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontend(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().SetDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d1.pem"
	h.TLS.TLSHash = "1"

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/app", hatypes.MatchPrefix)
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d2.pem"
	h.TLS.TLSHash = "2"

	c.Update()
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
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),map_dir(/etc/haproxy/maps/_front_redir_tohttps__prefix.map)
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map) if !{ var(req.redir) -m found }
    http-request redirect scheme https if { var(req.redir) yes }
    http-request set-var(txn.namespace) var(req.base),map_dir(/etc/haproxy/maps/_front_namespace__prefix.map)
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map) if !{ var(txn.namespace) -m found }
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<http-headers>>
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _default_backend
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),map_dir(/etc/haproxy/maps/_front_https_host__prefix.map)
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(txn.namespace) var(req.base),map_dir(/etc/haproxy/maps/_front_namespace__prefix.map)
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map) if !{ var(txn.namespace) -m found }
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _default_backend
<<support>>
`)

	c.checkMap("_front_redir_tohttps__begin.map", `
d1.local/ yes
`)
	c.checkMap("_front_redir_tohttps__prefix.map", `
d2.local/app yes
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local/ d1_app_8080
`)
	c.checkMap("_front_https_host__prefix.map", `
d2.local/app d2_app_8080
`)
	c.checkMap("_front_namespace__begin.map", `
d1.local/ d1
`)
	c.checkMap("_front_namespace__prefix.map", `
d2.local/app -
`)

	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem
/var/haproxy/ssl/certs/d1.pem d1.local
/var/haproxy/ssl/certs/d2.pem d2.local
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontendCA(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().SetDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d", "app", "8080")
	h = c.config.Hosts().AcquireHost("*.d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d1.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAErrorPage = "http://d1.local/error.html"

	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d2.local.pem"
	h.TLS.CAHash = "2"
	h.TLS.CRLFilename = "/var/haproxy/ssl/ca/d2.local.crl.pem"
	h.TLS.CRLHash = "2"
	h.TLS.CAErrorPage = "http://d2.local/error.html"

	h = c.config.Hosts().AcquireHost("d3.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.TLS.Ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"

	h = c.config.Hosts().AcquireHost("d4.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.TLS.CipherSuites = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

	h = c.config.Hosts().AcquireHost("d5.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.TLS.ALPN = "h2"

	h = c.config.Hosts().AcquireHost("d6.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.TLS.Options = "ssl-min-ver TLSv1.0 ssl-max-ver TLSv1.2"

	b.SSLRedirect = b.CreateConfigBool(true)
	b.TLS.AddCertHeader = true
	b.TLS.FingerprintLower = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d_app_8080
    mode http
    acl local-offload ssl_fc
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex,lower]
    http-request set-header X-SSL-Client-Cert %{+Q}[ssl_c_der,base64]
    server s1 172.17.0.11:8080 weight 100
backend _default_backend
    mode http
    server s0 172.17.0.99:8080 weight 100
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map)
    http-request set-var(req.redir) var(req.base),map_reg(/etc/haproxy/maps/_front_redir_tohttps__regex.map) if !{ var(req.redir) -m found }
    http-request redirect scheme https if { var(req.redir) yes }
    <<http-headers>>
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _default_backend
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-need-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map)
    http-request set-var(req.snibackend) var(req.snibase),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map) if !{ var(req.snibackend) -m found }
    http-request set-var(req.snibackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_sni__begin.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.snibackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map) if !{ var(req.snibackend) -m found } !tls-has-crt !tls-host-need-crt
    http-request set-var(req.tls_nocrt_redir) ssl_fc_sni,lower,map_str(/etc/haproxy/maps/_front_tls_missingcrt_pages__exact.map,_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_nocrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front_tls_missingcrt_pages__regex.map,_internal) if { var(req.tls_nocrt_redir) _internal }
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_str(/etc/haproxy/maps/_front_tls_invalidcrt_pages__exact.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front_tls_invalidcrt_pages__regex.map,_internal) if { var(req.tls_invalidcrt_redir) _internal }
    http-request redirect location %[var(req.tls_nocrt_redir)] code 303 if { var(req.tls_nocrt_redir) -m found } !{ var(req.tls_nocrt_redir) _internal }
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) _internal }
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-496 if { var(req.tls_nocrt_redir) _internal }
    http-request use-service lua.send-421 if !tls-has-crt tls-host-need-crt
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend _default_backend
<<support>>
`)

	c.checkMap("_front_redir_tohttps__begin.map", `
d2.local/ yes
d3.local/ yes
d4.local/ yes
d5.local/ yes
d6.local/ yes
`)
	c.checkMap("_front_redir_tohttps__regex.map", `
^[^.]+\.d1\.local/ yes
`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem
/var/haproxy/ssl/certs/default.pem [ca-file /var/haproxy/ssl/ca/d1.local.pem verify optional] *.d1.local
/var/haproxy/ssl/certs/default.pem [ca-file /var/haproxy/ssl/ca/d2.local.pem verify optional crl-file /var/haproxy/ssl/ca/d2.local.crl.pem] d2.local
/var/haproxy/ssl/certs/default.pem [ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384] d3.local
/var/haproxy/ssl/certs/default.pem [ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256] d4.local
/var/haproxy/ssl/certs/default.pem [alpn h2] d5.local
/var/haproxy/ssl/certs/default.pem [ssl-min-ver TLSv1.0 ssl-max-ver TLSv1.2] d6.local
`)
	c.checkMap("_front_https_host__begin.map", `
d3.local/ d_app_8080
d4.local/ d_app_8080
d5.local/ d_app_8080
d6.local/ d_app_8080
`)
	c.checkMap("_front_https_sni__begin.map", `
d2.local/ d_app_8080
`)
	c.checkMap("_front_https_sni__regex.map", `
^[^.]+\.d1\.local/ d_app_8080
`)
	c.checkMap("_front_tls_needcrt__exact.list", `
d2.local
`)
	c.checkMap("_front_tls_needcrt__regex.list", `
^[^.]+\.d1\.local$
`)
	c.checkMap("_front_tls_auth__exact.list", `
d2.local
`)
	c.checkMap("_front_tls_auth__regex.list", `
^[^.]+\.d1\.local$
`)
	c.checkMap("_front_tls_missingcrt_pages__exact.map", `
d2.local http://d2.local/error.html
`)
	c.checkMap("_front_tls_invalidcrt_pages__regex.map", `
^[^.]+\.d1\.local$ http://d1.local/error.html
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSomePaths(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().SetDefaultBackend(def)

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d", "app0", "8080")
	h = c.config.Hosts().AcquireHost("d.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d", "app1", "8080")
	h.AddPath(b, "/app", hatypes.MatchBegin)
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d", "app2", "8080")
	h.AddPath(b, "/app/sub", hatypes.MatchBegin)
	b.Endpoints = []*hatypes.Endpoint{endpointS21, endpointS22}

	b = c.config.Backends().AcquireBackend("d", "app3", "8080")
	h.AddPath(b, "/sub", hatypes.MatchBegin)
	b.Endpoints = []*hatypes.Endpoint{endpointS31, endpointS32, endpointS33}

	c.Update()
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
<<frontend-http>>
    default_backend _default_backend
<<frontend-https>>
    default_backend _default_backend
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d.local/sub d_app3_8080
d.local/app/sub d_app2_8080
`)
	c.checkMap("_front_redir_tohttps__begin.map", `
d.local/sub no
d.local/app/sub no
d.local/app yes
d.local/ yes
`)
	c.checkMap("_front_https_host__begin.map", `
d.local/sub d_app3_8080
d.local/app/sub d_app2_8080
d.local/app d_app1_8080
d.local/ d_app0_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceCustomFrontend(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	c.config.Global().CustomFrontend = []string{
		"# new header",
		"http-response set-header X-Server HAProxy",
	}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    <<https-redirect>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    # new header
    http-response set-header X-Server HAProxy
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert
    # new header
    http-response set-header X-Server HAProxy
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSSLRedirect(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app-api", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.SSLRedirect = b.CreateConfigBool(true)

	b = c.config.Backends().AcquireBackend("d2", "app-front", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h = c.config.Hosts().AcquireHost("d2.local")
	h.TLS.TLSFilename = ""
	h.TLS.TLSHash = ""
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.SSLRedirect = b.CreateConfigBool(true)

	c.config.Global().SSL.RedirectCode = 301

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app-api_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d2_app-front_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map)
    http-request redirect scheme https code 301 if { var(req.redir) yes }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
<<frontend-https>>
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_redir_tohttps__begin.map", `
d1.local/ yes
d2.local/ no
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSSLPassthrough(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS31}
	h.SetSSLPassthrough(true)

	b = c.config.Backends().AcquireBackend("d3", "app-ssl", "8443")
	h = c.config.Hosts().AcquireHost("d3.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.Endpoints = []*hatypes.Endpoint{endpointS41s}
	h.SetSSLPassthrough(true)

	b = c.config.Backends().AcquireBackend("d3", "app-http", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS41h}
	h.HTTPPassthroughBackend = b.ID

	c.Update()
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
    tcp-request content set-var(req.sslpassback) req.ssl_sni,lower,map_str(/etc/haproxy/maps/_front_sslpassthrough__exact.map)
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend %[var(req.sslpassback)] if { var(req.sslpassback) -m found }
    server _default_server_https_socket unix@/var/run/haproxy/_https_socket.sock send-proxy-v2
<<frontend-http>>
    default_backend _error404
frontend _front_https
    mode http
    bind unix@/var/run/haproxy/_https_socket.sock accept-proxy ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_sslpassthrough__exact.map", `
d2.local d2_app_8080
d3.local d3_app-ssl_8443`)
	c.checkMap("_front_http_host__begin.map", `
d3.local/ d3_app-http_8080`)
	c.checkMap("_front_redir_tohttps__begin.map", `
d2.local/ yes
d3.local/ no`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceRootRedirect(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	h = c.config.Hosts().AcquireHost("*.d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.RootRedirect = "/app"
	b.SSLRedirect = b.CreateConfigBool(false)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/app1", hatypes.MatchBegin)
	h.AddPath(b, "/app2", hatypes.MatchBegin)
	h.RootRedirect = "/app1"
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS21}

	c.Update()

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
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map)
    http-request set-var(req.redir) var(req.base),map_reg(/etc/haproxy/maps/_front_redir_tohttps__regex.map) if !{ var(req.redir) -m found }
    http-request redirect scheme https if { var(req.redir) yes }
    http-request set-var(req.rootredir) var(req.host),map_str(/etc/haproxy/maps/_front_redir_fromroot__exact.map)
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map) if !{ var(req.rootredir) -m found }
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.rootredir) var(req.host),map_str(/etc/haproxy/maps/_front_redir_fromroot__exact.map)
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map) if !{ var(req.rootredir) -m found }
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_http_host__regex.map", `
^[^.]+\.d1\.local/ d1_app_8080
`)
	c.checkMap("_front_redir_tohttps__begin.map", `
d2.local/app2 yes
d2.local/app1 yes
`)
	c.checkMap("_front_redir_tohttps__regex.map", `
^[^.]+\.d1\.local/ no
`)
	c.checkMap("_front_redir_fromroot__exact.map", `
d2.local /app1
`)
	c.checkMap("_front_redir_fromroot__regex.map", `
^[^.]+\.d1\.local$ /app
`)
	c.checkMap("_front_https_host__begin.map", `
d2.local/app2 d2_app_8080
d2.local/app1 d2_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[^.]+\.d1\.local/ d1_app_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceAlias(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.Alias.AliasName = "*.d1.local"

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.Alias.AliasName = "sub.d2.local"
	h.Alias.AliasRegex = "^[a-z]+\\.d2\\.local$"

	b = c.config.Backends().AcquireBackend("d3", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS31}
	h = c.config.Hosts().AcquireHost("d3.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.Alias.AliasRegex = "d3\\.local$"

	c.Update()
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
    <<https-redirect>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map) if !{ var(req.backend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_redir_tohttps__begin.map", `
d1.local/ no
d2.local/ no
d3.local/ no
`)
	c.checkMap("_front_http_host__begin.map", `
d1.local/ d1_app_8080
d2.local/ d2_app_8080
d3.local/ d3_app_8080
sub.d2.local/ d2_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local/ d1_app_8080
d2.local/ d2_app_8080
d3.local/ d3_app_8080
sub.d2.local/ d2_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[a-z]+\.d2\.local/ d2_app_8080
^[^.]+\.d1\.local/ d1_app_8080
d3\.local/ d3_app_8080
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSyslog(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	syslog := &c.config.Global().Syslog
	syslog.Endpoint = "127.0.0.1:1514"
	syslog.Format = "rfc3164"
	syslog.Length = 2048
	syslog.Tag = "ingress"

	c.Update()
	c.checkConfig(`
global
    daemon
    unix-bind user haproxy group haproxy mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    log 127.0.0.1:1514 len 2048 format rfc3164 local0
    log-tag ingress
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
    ssl-default-bind-options no-sslv3
    ssl-default-server-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    option httplog
    <<https-redirect>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    option httplog
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestDNS(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	c.config.Global().DNS = hatypes.DNSConfig{
		ClusterDomain: "cluster.local",
		Resolvers: []*hatypes.DNSResolver{
			{
				Name: "k8s",
				Nameservers: []*hatypes.DNSNameserver{
					{
						Name:     "coredns1",
						Endpoint: "10.0.1.11",
					},
					{
						Name:     "coredns2",
						Endpoint: "10.0.1.12",
					},
					{
						Name:     "coredns3",
						Endpoint: "10.0.1.13",
					},
				},
				AcceptedPayloadSize: 8192,
				HoldObsolete:        "0s",
				HoldValid:           "1s",
				TimeoutRetry:        "2s",
			},
		},
	}

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21, endpointS22}
	b.Resolver = "k8s"
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	b = c.config.Backends().AcquireBackend("d2", "app", "http")
	b.Endpoints = []*hatypes.Endpoint{endpointS21, endpointS22}
	b.Resolver = "k8s"
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
resolvers k8s
    nameserver coredns1 10.0.1.11
    nameserver coredns2 10.0.1.12
    nameserver coredns3 10.0.1.13
    accepted_payload_size 8192
    hold obsolete         0s
    hold valid            1s
    timeout retry         2s
backend d1_app_8080
    mode http
    server-template srv 2 app.d1.svc.cluster.local:8080 resolvers k8s resolve-prefer ipv4 init-addr none weight 1
backend d2_app_http
    mode http
    server-template srv 2 _http._tcp.app.d2.svc.cluster.local resolvers k8s resolve-prefer ipv4 init-addr none weight 1
<<backends-default>>
<<frontends-default>>
<<support>>
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

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		h.AddPath(b, "/", hatypes.MatchBegin)
		h.AddPath(b, "/admin", hatypes.MatchBegin)

		for _, list := range test.lists {
			c.config.Userlists().Replace(list.name, list.users)
		}
		b.AuthHTTP = []*hatypes.BackendConfigAuth{
			{
				Paths: createBackendPaths(b, "d1.local/"),
			},
			{
				Paths:        createBackendPaths(b, "d1.local/admin"),
				UserlistName: test.listname,
				Realm:        test.realm,
			},
		}

		var realm string
		if test.realm != "" {
			realm = fmt.Sprintf(` realm "%s"`, test.realm)
		}

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>` + test.config + `
backend d1_app_8080
    mode http
    # path01 = d1.local/
    # path02 = d1.local/admin
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request auth` + realm + ` if { var(txn.pathID) path02 } !{ http_auth(` + test.listname + `) }
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>
`)
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestAcme(t *testing.T) {
	testCases := []struct {
		shared   bool
		expected string
	}{
		{
			shared: false,
			expected: `
frontend _front_http
    mode http
    bind :80
    acl acme-challenge path_beg /.acme
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map)
    http-request redirect scheme https if !acme-challenge { var(req.redir) yes }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend _acme_challenge if acme-challenge
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404`,
		},
		{
			shared: true,
			expected: `
frontend _front_http
    mode http
    bind :80
    acl acme-challenge path_beg /.acme
    <<https-redirect>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    use_backend _acme_challenge if acme-challenge
    default_backend _error404`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		h.AddPath(b, "/", hatypes.MatchBegin)

		acme := &c.config.Global().Acme
		acme.Enabled = true
		acme.Prefix = "/.acme"
		acme.Socket = "/run/acme.sock"
		acme.Shared = test.shared

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend _acme_challenge
    mode http
    server _acme_server unix@/run/acme.sock
<<backends-default>>` + test.expected + `
<<frontend-https>>
    default_backend _error404
<<support>>
`)
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestStats(t *testing.T) {
	testCases := []struct {
		stats          hatypes.StatsConfig
		prom           hatypes.PromConfig
		healtz         hatypes.HealthzConfig
		expectedStats  string
		expectedProm   string
		expectedHealtz string
	}{
		// 0
		{},
		// 1
		{
			stats: hatypes.StatsConfig{
				Port:        1936,
				AcceptProxy: true,
			},
			expectedStats: `
    bind :1936 accept-proxy`,
		},
		// 2
		{
			stats: hatypes.StatsConfig{
				Port: 1936,
				Auth: "usr:pwd",
			},
			expectedStats: `
    bind :1936
    stats realm HAProxy\ Statistics
    stats auth usr:pwd`,
		},
		// 3
		{
			stats: hatypes.StatsConfig{
				Port:        1936,
				TLSFilename: "/var/haproxy/ssl/stats.pem",
				TLSHash:     "1",
			},
			expectedStats: `
    bind :1936 ssl crt /var/haproxy/ssl/stats.pem`,
		},
		// 4
		{
			healtz: hatypes.HealthzConfig{
				BindIP: "127.0.0.1",
				Port:   10253,
			},
			expectedHealtz: "127.0.0.1:10253",
		},
		// 5
		{
			prom: hatypes.PromConfig{
				Port: 9100,
			},
			expectedProm: `
frontend prometheus
    mode http
    bind :9100
    http-request use-service prometheus-exporter if { path /metrics }
    http-request use-service lua.send-prometheus-root if { path / }
    http-request use-service lua.send-404
    no log`,
		},
	}
	for _, test := range testCases {
		c := setup(t)
		c.config.Global().Stats = test.stats
		c.config.Global().Prometheus = test.prom
		c.config.Global().Healthz = test.healtz
		if test.expectedStats == "" {
			test.expectedStats = "\n    bind :0"
		}
		if test.expectedHealtz == "" {
			test.expectedHealtz = ":0"
		}
		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend _error404
    mode http
    http-request use-service lua.send-404
<<frontend-http-clean>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
listen stats
    mode http` + test.expectedStats + `
    stats enable
    stats uri /
    no log
    option httpclose
    stats show-legends` + test.expectedProm + `
frontend healthz
    mode http
    bind ` + test.expectedHealtz + `
    monitor-uri /healthz
    http-request use-service lua.send-404
    no log
`)
		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestModSecurity(t *testing.T) {
	testCases := []struct {
		waf        string
		wafmode    string
		path       string
		endpoints  []string
		backendExp string
		modsecExp  string
	}{
		{
			waf:        "modsecurity",
			wafmode:    "On",
			endpoints:  []string{},
			backendExp: ``,
			modsecExp:  ``,
		},
		{
			waf:        "",
			wafmode:    "",
			endpoints:  []string{"10.0.0.101:12345"},
			backendExp: ``,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345`,
		},
		{
			waf:       "modsecurity",
			wafmode:   "deny",
			endpoints: []string{"10.0.0.101:12345"},
			backendExp: `
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request deny if { var(txn.modsec.code) -m int gt 0 }`,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345`,
		},
		{
			waf:       "modsecurity",
			wafmode:   "detect",
			endpoints: []string{"10.0.0.101:12345"},
			backendExp: `
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf`,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345`,
		},
		{
			waf:       "modsecurity",
			wafmode:   "deny",
			endpoints: []string{"10.0.0.101:12345", "10.0.0.102:12345"},
			backendExp: `
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request deny if { var(txn.modsec.code) -m int gt 0 }`,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345
    server modsec-spoa1 10.0.0.102:12345`,
		},
		{
			waf:       "modsecurity",
			wafmode:   "deny",
			endpoints: []string{"10.0.0.101:12345"},
			path:      "/sub",
			backendExp: `
    # path02 = d1.local/
    # path01 = d1.local/sub
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request deny if { var(txn.modsec.code) -m int gt 0 } { var(txn.pathID) path01 }`,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b *hatypes.Backend

		b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		if test.path == "" {
			test.path = "/"
		}
		h.AddPath(b, test.path, hatypes.MatchBegin)
		b.WAF = []*hatypes.BackendConfigWAF{
			{
				Paths: createBackendPaths(b, "d1.local"+test.path),
				Config: hatypes.WAF{
					Module: test.waf,
					Mode:   test.wafmode,
				},
			},
		}
		if test.path != "/" {
			h.AddPath(b, "/", hatypes.MatchBegin)
			b.WAF = append(b.WAF, &hatypes.BackendConfigWAF{
				Paths: createBackendPaths(b, "d1.local/"),
			})
		}

		globalModsec := &c.config.Global().ModSecurity
		globalModsec.Endpoints = test.endpoints
		globalModsec.Timeout.Connect = "1s"
		globalModsec.Timeout.Server = "2s"

		c.Update()

		var modsec string
		if test.modsecExp != "" {
			modsec = `
backend spoe-modsecurity
    mode tcp` + test.modsecExp
		}
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http` + test.backendExp + `
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>` + modsec)

		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceWildcardHostname(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	h = c.config.Hosts().AcquireHost("d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	h = c.config.Hosts().AcquireHost("*.app.d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	h = c.config.Hosts().AcquireHost("*.sub.d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d1.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAVerifyOptional = true
	h.TLS.CAErrorPage = "http://sub.d1.local/error.html"
	b.SSLRedirect = b.CreateConfigBool(true)
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("*.d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.RootRedirect = "/app"
	b.SSLRedirect = b.CreateConfigBool(false)
	b.Endpoints = []*hatypes.Endpoint{endpointS21}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl local-offload ssl_fc
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map)
    http-request set-var(req.redir) var(req.base),map_reg(/etc/haproxy/maps/_front_redir_tohttps__regex.map) if !{ var(req.redir) -m found }
    http-request redirect scheme https if { var(req.redir) yes }
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map)
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map)
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
    <<https-headers>>
    acl tls-has-crt ssl_c_used
    acl tls-has-invalid-crt ssl_c_ca_err gt 0
    acl tls-has-invalid-crt ssl_c_err gt 0
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list
    http-request set-var(req.snibase) ssl_fc_sni,lower,concat(,req.path)
    http-request set-var(req.snibackend) var(req.snibase),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map)
    http-request set-var(req.snibackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_sni__regex.map) if !{ var(req.snibackend) -m found } !tls-has-crt
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front_tls_invalidcrt_pages__regex.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) _internal }
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_http_host__regex.map", `
^[^.]+\.d2\.local/ d2_app_8080
`)
	c.checkMap("_front_redir_tohttps__begin.map", `
d1.local/ yes
`)
	c.checkMap("_front_redir_tohttps__regex.map", `
^[^.]+\.app\.d1\.local/ yes
^[^.]+\.sub\.d1\.local/ yes
^[^.]+\.d2\.local/ no
`)
	c.checkMap("_front_redir_fromroot__regex.map", `
^[^.]+\.d2\.local$ /app
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local/ d1_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[^.]+\.app\.d1\.local/ d1_app_8080
^[^.]+\.d2\.local/ d2_app_8080
`)
	c.checkMap("_front_redir_fromroot__regex.map", `
^[^.]+\.d2\.local$ /app
`)
	c.checkMap("_front_https_sni__regex.map", `
^[^.]+\.sub\.d1\.local/ d1_app_8080
`)
	c.checkMap("_front_tls_auth__regex.list", `
^[^.]+\.sub\.d1\.local$
`)
	c.checkMap("_front_tls_invalidcrt_pages__regex.map", `
^[^.]+\.sub\.d1\.local$ http://sub.d1.local/error.html
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestShards(t *testing.T) {
	c := setupOptions(testOptions{
		t:          t,
		shardCount: 3,
	})
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	b = c.config.Backends().AcquireBackend("d3", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS31}
	h = c.config.Hosts().AcquireHost("d3.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
<<backends-default>>
<<frontends-default>>
<<support>>
`)

	c.checkConfigFile(`
backend d2_app_8080
    mode http
    server s21 172.17.0.121:8080 weight 100
`, "haproxy5-backend000.cfg")

	c.checkConfigFile(`
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
backend d3_app_8080
    mode http
    server s31 172.17.0.131:8080 weight 100
`, "haproxy5-backend002.cfg")

	c.logger.CompareLogging(`
INFO-V(2) updated main cfg and 2 backend file(s): [000 002]` + defaultLogging)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  BUILDERS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

type testConfig struct {
	t        *testing.T
	logger   *helper_test.LoggerMock
	instance *instance
	config   *config
	tempdir  string
}

type testOptions struct {
	t          *testing.T
	shardCount int
}

func setup(t *testing.T) *testConfig {
	return setupOptions(testOptions{t: t})
}

func setupOptions(options testOptions) *testConfig {
	t := options.t
	logger := &helper_test.LoggerMock{T: t}
	tempdir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("error creating tempdir: %v", err)
	}
	instance := CreateInstance(logger, InstanceOptions{
		HAProxyCfgDir:  tempdir,
		HAProxyMapsDir: tempdir,
		Metrics:        helper_test.NewMetricsMock(),
		BackendShards:  options.shardCount,
	}).(*instance)
	if err := instance.haproxyTmpl.NewTemplate(
		"haproxy.tmpl",
		"../../rootfs/etc/templates/haproxy/haproxy.tmpl",
		filepath.Join(tempdir, "haproxy.cfg"),
		0,
		2048,
	); err != nil {
		t.Errorf("error parsing haproxy.tmpl: %v", err)
	}
	if err := instance.mapsTmpl.NewTemplate(
		"map.tmpl",
		"../../rootfs/etc/templates/map/map.tmpl",
		"",
		0,
		2048,
	); err != nil {
		t.Errorf("error parsing map.tmpl: %v", err)
	}
	config := instance.Config().(*config)
	config.frontend.DefaultCrtFile = "/var/haproxy/ssl/certs/default.pem"
	c := &testConfig{
		t:        t,
		logger:   logger,
		instance: instance,
		config:   config,
		tempdir:  tempdir,
	}
	c.configGlobal(c.config.Global())
	return c
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
	if err := os.RemoveAll(c.tempdir); err != nil {
		c.t.Errorf("error removing tempdir: %v", err)
	}
}

func (c *testConfig) configGlobal(global *hatypes.Global) {
	global.AdminSocket = "/var/run/haproxy.sock"
	global.Bind.HTTPBind = ":80"
	global.Bind.HTTPSBind = ":443"
	global.Cookie.Key = "Ingress"
	global.Healthz.Port = 10253
	global.MaxConn = 2000
	global.SSL.ALPN = "h2,http/1.1"
	global.SSL.BackendCiphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
	global.SSL.BackendCipherSuites = "TLS_AES_128_GCM_SHA256"
	global.SSL.Ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
	global.SSL.CipherSuites = "TLS_AES_128_GCM_SHA256"
	global.SSL.DHParam.Filename = "/var/haproxy/tls/dhparam.pem"
	global.SSL.HeadersPrefix = "X-SSL"
	global.SSL.Options = "no-sslv3"
	global.Stats.Port = 1936
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
	global.UseHTX = true
}

var endpointS0 = &hatypes.Endpoint{
	Name:    "s0",
	IP:      "172.17.0.99",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS1 = &hatypes.Endpoint{
	Name:    "s1",
	IP:      "172.17.0.11",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS21 = &hatypes.Endpoint{
	Name:    "s21",
	IP:      "172.17.0.121",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS22 = &hatypes.Endpoint{
	Name:    "s22",
	IP:      "172.17.0.122",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS31 = &hatypes.Endpoint{
	Name:    "s31",
	IP:      "172.17.0.131",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS32 = &hatypes.Endpoint{
	Name:    "s32",
	IP:      "172.17.0.132",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS33 = &hatypes.Endpoint{
	Name:    "s33",
	IP:      "172.17.0.133",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}
var endpointS41s = &hatypes.Endpoint{
	Name:    "s41s",
	IP:      "172.17.0.141",
	Enabled: true,
	Port:    8443,
	Weight:  100,
}
var endpointS41h = &hatypes.Endpoint{
	Name:    "s41h",
	IP:      "172.17.0.141",
	Enabled: true,
	Port:    8080,
	Weight:  100,
}

var defaultLogging = `
INFO (test) reload was skipped
INFO HAProxy successfully reloaded`

func _yamlMarshal(in interface{}) string {
	out, _ := yaml.Marshal(in)
	return string(out)
}

func (c *testConfig) Update() {
	timer := utils.NewTimer(nil)
	c.instance.Update(timer)
}

func (c *testConfig) checkConfig(expected string) {
	c.checkConfigFile(expected, "haproxy.cfg")
}

func (c *testConfig) checkConfigFile(expected, fileName string) {
	actual := strings.Replace(c.readConfig(filepath.Join(c.tempdir, fileName)), c.tempdir, "/etc/haproxy/maps", -1)
	replace := map[string]string{
		"<<global>>": `global
    daemon
    unix-bind user haproxy group haproxy mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
    ssl-default-bind-options no-sslv3
    ssl-default-server-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256`,
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
		"<<backends-default>>": `backend _error404
    mode http
    http-request use-service lua.send-404`,
		"    <<set-req-base>>": `    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),regsub(:[0-9]+$,),lower
    http-request set-var(req.base) var(req.host),concat(,req.path)`,
		"    <<https-redirect>>": `    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map)
    http-request redirect scheme https if { var(req.redir) yes }`,
		"    <<https-redirect-match-4>>": `    <<set-req-base>>
    http-request set-var(req.redir) var(req.base),map_str(/etc/haproxy/maps/_front_redir_tohttps__exact.map)
    http-request set-var(req.redir) var(req.base),map_dir(/etc/haproxy/maps/_front_redir_tohttps__prefix.map) if !{ var(req.redir) -m found }
    http-request set-var(req.redir) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_tohttps__begin.map) if !{ var(req.redir) -m found }
    http-request set-var(req.redir) var(req.base),map_reg(/etc/haproxy/maps/_front_redir_tohttps__regex.map) if !{ var(req.redir) -m found }
    http-request redirect scheme https if { var(req.redir) yes }`,
		"    <<http-headers>>": `    http-request set-header X-Forwarded-Proto http
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert`,
		"    <<https-headers>>": `    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-Cert`,
		"<<frontend-http>>": `frontend _front_http
    mode http
    bind :80
    <<https-redirect>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
		"<<frontend-http-match-4>>": `frontend _front_http
    mode http
    bind :80
    <<https-redirect-match-4>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_str(/etc/haproxy/maps/_front_http_host__exact.map)
    http-request set-var(req.backend) var(req.base),map_dir(/etc/haproxy/maps/_front_http_host__prefix.map) if !{ var(req.backend) -m found }
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map) if !{ var(req.backend) -m found }
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map) if !{ var(req.backend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
		"<<frontend-http-clean>>": `frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
		"<<frontend-https>>": `frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),regsub(:[0-9]+$,),lower
    http-request set-var(req.base) var(req.host),concat(,req.path)
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }`,
		"<<frontend-https-match-4>>": `frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),map_str(/etc/haproxy/maps/_front_https_host__exact.map)
    http-request set-var(req.hostbackend) var(req.base),map_dir(/etc/haproxy/maps/_front_https_host__prefix.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }`,
		"<<frontend-https-clean>>": `frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }`,
		"<<frontends-default>>": `<<frontend-http>>
    default_backend _error404
<<frontend-https>>
    default_backend _error404`,
		"<<frontends-default-match-4>>": `<<frontend-http-match-4>>
    default_backend _error404
<<frontend-https-match-4>>
    default_backend _error404`,
		"<<support>>": `listen stats
    mode http
    bind :1936
    stats enable
    stats uri /
    no log
    option httpclose
    stats show-legends
frontend healthz
    mode http
    bind :10253
    monitor-uri /healthz
    http-request use-service lua.send-404
    no log`,
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
	c.compareText(fileName, actual, expected)
}

func (c *testConfig) checkMap(mapName, expected string) {
	actual := c.readConfig(c.tempdir + "/" + mapName)
	c.compareText(mapName, actual, expected)
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

func createBackendPaths(backend *hatypes.Backend, uris ...string) hatypes.BackendPaths {
	paths := make([]*hatypes.BackendPath, len(uris))
	for i, uri := range uris {
		j := strings.IndexAny(uri, "^/")
		hostname := uri[:j]
		path := uri[j:]
		paths[i] = backend.FindBackendPath(hatypes.CreatePathLink(hostname, path))
	}
	return hatypes.NewBackendPaths(paths...)
}
