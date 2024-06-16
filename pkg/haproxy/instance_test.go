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
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"

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
		doconfig  func(c *config, h *hatypes.Host, b *hatypes.Backend)
		path      []string
		match     []hatypes.MatchType
		skipSrv   bool
		srvsuffix string
		expected  string
		expFronts string
		expCheck  map[string]string
	}{
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "ingress-controller"
				b.Cookie.Strategy = "insert"
				b.Cookie.Keywords = "indirect nocache httponly"
				e1 := *endpointS1
				b.Endpoints = []*hatypes.Endpoint{&e1}
				b.Endpoints[0].CookieValue = "s1"
			},
			srvsuffix: "cookie s1",
			expected: `
    cookie ingress-controller insert indirect nocache httponly`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "Ingress"
				b.Cookie.Strategy = "prefix"
				b.Cookie.Dynamic = true
			},
			expected: `
    cookie Ingress prefix dynamic
    dynamic-cookie-key "Ingress"`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "ingress-controller"
				b.Cookie.Domain = "example.com"
				b.Cookie.Strategy = "insert"
				b.Cookie.Keywords = "indirect nocache httponly"
			},
			expected: `
    cookie ingress-controller insert indirect nocache httponly domain example.com`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "Ingress"
				b.Cookie.Strategy = "insert"
				b.Cookie.Keywords = "indirect nocache httponly"
				b.Cookie.SameSite = true
			},
			expected: `
    cookie Ingress insert attr SameSite=None secure indirect nocache httponly`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config1 := hatypes.Cors{
					Enabled:      true,
					AllowOrigin:  []string{"http://d11.local", "https://d12.local"},
					AllowHeaders: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:       86400,
				}
				config2 := config1
				config2.AllowOrigin = []string{"https://d21.local", "https://d22.local", "https://d23.local", "https://d24.local", "https://d25.local", "https://d26.local"}
				config2.AllowOriginRegex = []string{`^http://d10\.local$`, `^https?://d1[23]\.local`, `https://([a-z]*\.){0,3}d13\.local$`, `^https?://d1[45]\.local`, `^https?://d1[67]\.local`, `^https?://d1[89]\.local`}
				config3 := config1
				config3.AllowOrigin = []string{"https://d31.local"}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config1
				b.FindBackendPath(h.FindPath("/api")[0].Link).Cors = config1
				b.FindBackendPath(h.FindPath("/app")[0].Link).Cors = config2
				b.FindBackendPath(h.FindPath("/sub")[0].Link).Cors = config3
			},
			path: []string{"/", "/api", "/app", "/sub"},
			expected: `
    # path01 = d1.local/
    # path02 = d1.local/api
    # path03 = d1.local/app
    # path04 = d1.local/sub
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request set-var(txn.hdr_origin0) req.hdr(Origin)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS { var(txn.pathID) -m str path01 path02 }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) -m str path01 path02 }
    http-request set-var(txn.hdr_origin1) req.hdr(Origin)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS { var(txn.pathID) -m str path03 }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) -m str path03 }
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS { var(txn.pathID) -m str path04 }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) -m str path04 }
    acl cors_allow_origin0 var(txn.hdr_origin0) -m str http://d11.local https://d12.local
    http-response set-header Access-Control-Allow-Origin  "%[var(txn.hdr_origin0)]" if { var(txn.pathID) -m str path01 path02 } cors_allow_origin0
    http-response set-header Access-Control-Allow-Origin  "http://d11.local" if { var(txn.pathID) -m str path01 path02 } !cors_allow_origin0
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) -m str path01 path02 }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization" if { var(txn.pathID) -m str path01 path02 }
    http-response set-header Vary %[res.fhdr(Vary)],Origin if { res.hdr(Vary) -m found } { var(txn.pathID) -m str path01 path02 }
    http-response set-header Vary Origin if ! { res.hdr(Vary) -m found } { var(txn.pathID) -m str path01 path02 }
    acl cors_allow_origin1 var(txn.hdr_origin1) -m str https://d21.local https://d22.local https://d23.local https://d24.local https://d25.local
    acl cors_allow_origin1 var(txn.hdr_origin1) -m str https://d26.local
    acl cors_allow_origin1 var(txn.hdr_origin1) -m reg '^http://d10\.local$' '^https?://d1[23]\.local' 'https://([a-z]*\.){0,3}d13\.local$' '^https?://d1[45]\.local' '^https?://d1[67]\.local'
    acl cors_allow_origin1 var(txn.hdr_origin1) -m reg '^https?://d1[89]\.local'
    http-response set-header Access-Control-Allow-Origin  "%[var(txn.hdr_origin1)]" if { var(txn.pathID) -m str path03 } cors_allow_origin1
    http-response set-header Access-Control-Allow-Origin  "https://d21.local" if { var(txn.pathID) -m str path03 } !cors_allow_origin1
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) -m str path03 }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization" if { var(txn.pathID) -m str path03 }
    http-response set-header Vary %[res.fhdr(Vary)],Origin if { res.hdr(Vary) -m found } { var(txn.pathID) -m str path03 }
    http-response set-header Vary Origin if ! { res.hdr(Vary) -m found } { var(txn.pathID) -m str path03 }
    http-response set-header Access-Control-Allow-Origin  "https://d31.local" if { var(txn.pathID) -m str path04 }
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) -m str path04 }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization" if { var(txn.pathID) -m str path04 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:      true,
					AllowOrigin:  []string{"https://d11.local", "https://d12.local"},
					AllowHeaders: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:       86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path: []string{"/"},
			expected: `
    http-request set-var(txn.hdr_origin0) req.hdr(Origin)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS
    http-request use-service lua.send-cors-preflight if METH_OPTIONS
    acl cors_allow_origin0 var(txn.hdr_origin0) -m str https://d11.local https://d12.local
    http-response set-header Access-Control-Allow-Origin  "%[var(txn.hdr_origin0)]" if cors_allow_origin0
    http-response set-header Access-Control-Allow-Origin  "https://d11.local" if !cors_allow_origin0
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
    http-response set-header Vary %[res.fhdr(Vary)],Origin if { res.hdr(Vary) -m found }
    http-response set-header Vary Origin if ! { res.hdr(Vary) -m found }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:          true,
					AllowOrigin:      []string{"https://d11.local", "https://d12.local"},
					AllowOriginRegex: []string{`^http://d10\.local$`, `^https?://d1[23]\.local`, `https://([a-z]*\.){0,3}d13\.local$`},
					AllowHeaders:     "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods:     "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:           86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path: []string{"/"},
			expected: `
    http-request set-var(txn.hdr_origin0) req.hdr(Origin)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS
    http-request use-service lua.send-cors-preflight if METH_OPTIONS
    acl cors_allow_origin0 var(txn.hdr_origin0) -m str https://d11.local https://d12.local
    acl cors_allow_origin0 var(txn.hdr_origin0) -m reg '^http://d10\.local$' '^https?://d1[23]\.local' 'https://([a-z]*\.){0,3}d13\.local$'
    http-response set-header Access-Control-Allow-Origin  "%[var(txn.hdr_origin0)]" if cors_allow_origin0
    http-response set-header Access-Control-Allow-Origin  "https://d11.local" if !cors_allow_origin0
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
    http-response set-header Vary %[res.fhdr(Vary)],Origin if { res.hdr(Vary) -m found }
    http-response set-header Vary Origin if ! { res.hdr(Vary) -m found }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:          true,
					AllowOrigin:      []string{"https://d11.local"},
					AllowOriginRegex: []string{`^http://d12\.local$`},
					AllowHeaders:     "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods:     "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:           86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path: []string{"/"},
			expected: `
    http-request set-var(txn.hdr_origin0) req.hdr(Origin)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS
    http-request use-service lua.send-cors-preflight if METH_OPTIONS
    acl cors_allow_origin0 var(txn.hdr_origin0) -m str https://d11.local
    acl cors_allow_origin0 var(txn.hdr_origin0) -m reg '^http://d12\.local$'
    http-response set-header Access-Control-Allow-Origin  "%[var(txn.hdr_origin0)]" if cors_allow_origin0
    http-response set-header Access-Control-Allow-Origin  "https://d11.local" if !cors_allow_origin0
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
    http-response set-header Vary %[res.fhdr(Vary)],Origin if { res.hdr(Vary) -m found }
    http-response set-header Vary Origin if ! { res.hdr(Vary) -m found }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:          true,
					AllowOrigin:      []string{"https://d11.local"},
					AllowOriginRegex: []string{`^http://d1'2\.local$`},
					AllowHeaders:     "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods:     "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:           86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path: []string{"/"},
			expected: `
    http-request set-var(txn.hdr_origin0) req.hdr(Origin)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS
    http-request use-service lua.send-cors-preflight if METH_OPTIONS
    acl cors_allow_origin0 var(txn.hdr_origin0) -m str https://d11.local
    acl cors_allow_origin0 var(txn.hdr_origin0) -m reg '^http://d1'"'"'2\.local$'
    http-response set-header Access-Control-Allow-Origin  "%[var(txn.hdr_origin0)]" if cors_allow_origin0
    http-response set-header Access-Control-Allow-Origin  "https://d11.local" if !cors_allow_origin0
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
    http-response set-header Vary %[res.fhdr(Vary)],Origin if { res.hdr(Vary) -m found }
    http-response set-header Vary Origin if ! { res.hdr(Vary) -m found }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:      true,
					AllowOrigin:  []string{"https://d11.local"},
					AllowHeaders: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:       86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path: []string{"/"},
			expected: `
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS
    http-request use-service lua.send-cors-preflight if METH_OPTIONS
    http-response set-header Access-Control-Allow-Origin  "https://d11.local"
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"`,
		},
		// ignore AllowOriginRegex if we don't have at least one AllowOrigin
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:          true,
					AllowOrigin:      []string{},
					AllowOriginRegex: []string{`^http://d10\.local$`, `^https?://d1[23]\.local`, `https://([a-z]*\.){0,3}d13\.local$`},
					AllowHeaders:     "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods:     "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:           86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path:     []string{"/"},
			expected: ``,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:      true,
					AllowOrigin:  []string{},
					AllowHeaders: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:       86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path:     []string{"/"},
			expected: ``,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:      true,
					AllowOrigin:  []string{"*"},
					AllowHeaders: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:       86400,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
				b.FindBackendPath(h.FindPath("/sub")[0].Link).Cors = config
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				config := hatypes.Cors{
					Enabled:          true,
					AllowOrigin:      []string{"*"},
					AllowHeaders:     "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
					AllowMethods:     "GET, PUT, POST, DELETE, PATCH, OPTIONS",
					MaxAge:           86400,
					AllowCredentials: true,
				}
				b.FindBackendPath(h.FindPath("/")[0].Link).Cors = config
			},
			path: []string{"/", "/sub"},
			expected: `
    # path01 = d1.local/
    # path02 = d1.local/sub
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request set-var(txn.cors_max_age) str(86400) if METH_OPTIONS { var(txn.pathID) -m str path01 }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) -m str path01 }
    http-response set-header Access-Control-Allow-Origin  "*" if { var(txn.pathID) -m str path01 }
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) -m str path01 }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization" if { var(txn.pathID) -m str path01 }
    http-response set-header Access-Control-Allow-Credentials "true" if { var(txn.pathID) -m str path01 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/sub path02
d1.local#/ path01`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/")[0].Link).HSTS = hatypes.HSTS{
					Enabled:    true,
					MaxAge:     15768000,
					Preload:    true,
					Subdomains: true,
				}
				b.FindBackendPath(h.FindPath("/path")[0].Link).HSTS = hatypes.HSTS{
					Enabled:    true,
					MaxAge:     15768000,
					Preload:    false,
					Subdomains: false,
				}
				b.FindBackendPath(h.FindPath("/uri")[0].Link).HSTS = hatypes.HSTS{
					Enabled:    true,
					MaxAge:     15768000,
					Preload:    false,
					Subdomains: false,
				}
			},
			path: []string{"/", "/path", "/uri"},
			expected: `
    acl https-request ssl_fc
    # path01 = d1.local/
    # path02 = d1.local/path
    # path03 = d1.local/uri
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" if https-request { var(txn.pathID) -m str path01 }
    http-response set-header Strict-Transport-Security "max-age=15768000" if https-request { var(txn.pathID) -m str path02 path03 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/uri path03
d1.local#/path path02
d1.local#/ path01`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).RewriteURL = "/"
			},
			path: []string{"/app"},
			expected: `
    http-request replace-path ^/app/?(.*)$     /\1`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).RewriteURL = "/other"
			},
			path: []string{"/app"},
			expected: `
    http-request replace-path ^/app(.*)$       /other\1`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).RewriteURL = "/other/"
				b.FindBackendPath(h.FindPath("/app/sub")[0].Link).RewriteURL = "/other/"
			},
			path: []string{"/app", "/app/sub"},
			expected: `
    http-request replace-path ^/app(.*)$       /other/\1
    http-request replace-path ^/app/sub(.*)$       /other/\1`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/path1")[0].Link).RewriteURL = "/sub1"
				b.FindBackendPath(h.FindPath("/path2")[0].Link).RewriteURL = "/sub2"
				b.FindBackendPath(h.FindPath("/path3")[0].Link).RewriteURL = "/sub2"
			},
			path: []string{"/path1", "/path2", "/path3"},
			expected: `
    # path01 = d1.local/path1
    # path02 = d1.local/path2
    # path03 = d1.local/path3
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request replace-path ^/path1(.*)$       /sub1\1     if { var(txn.pathID) -m str path01 }
    http-request replace-path ^/path2(.*)$       /sub2\1     if { var(txn.pathID) -m str path02 }
    http-request replace-path ^/path3(.*)$       /sub2\1     if { var(txn.pathID) -m str path03 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/path3 path03
d1.local#/path2 path02
d1.local#/path1 path01`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).SSLRedirect = true
			},
			path: []string{"/app", "/path"},
			expected: `
    acl https-request ssl_fc
    # path01 = d1.local/app
    # path02 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request redirect scheme https if !https-request { var(txn.pathID) -m str path01 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).SSLRedirect = true
				c.global.SSL.RedirectCode = 301
			},
			path: []string{"/app", "/path"},
			expected: `
    acl https-request ssl_fc
    # path01 = d1.local/app
    # path02 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request redirect scheme https code 301 if !https-request { var(txn.pathID) -m str path01 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.FindBackendPath(h.FindPath("/api")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.FindBackendPath(h.FindPath("/path")[0].Link).AllowedIPHTTP.Rule = []string{"192.168.95.0/24"}
				b.FindBackendPath(h.FindPath("/path")[0].Link).AllowedIPHTTP.Exception = []string{"192.168.95.11"}
			},
			path: []string{"/app", "/api", "/path"},
			expected: `
    # path02 = d1.local/api
    # path01 = d1.local/app
    # path03 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    acl allow_rule_src0 src 10.0.0.0/8 192.168.0.0/16
    http-request deny if { var(txn.pathID) -m str path01 path02 } !allow_rule_src0
    acl allow_rule_src1 src 192.168.95.0/24
    acl allow_exception_src1 src 192.168.95.11
    http-request deny if { var(txn.pathID) -m str path03 } allow_exception_src1
    http-request deny if { var(txn.pathID) -m str path03 } !allow_rule_src1`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/path path03
d1.local#/app path01
d1.local#/api path02`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.FindBackendPath(h.FindPath("/api")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.FindBackendPath(h.FindPath("/path")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.FindBackendPath(h.FindPath("/api/v[0-9]+/")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.FindBackendPath(h.FindPath("/")[0].Link).AllowedIPHTTP.Rule = []string{"172.17.0.0/16"}
			},
			path:  []string{"/", "/app", "/api", "/path", "/api/v[0-9]+/"},
			match: []hatypes.MatchType{hatypes.MatchBegin, hatypes.MatchExact, hatypes.MatchBegin, hatypes.MatchPrefix, hatypes.MatchRegex},
			expected: `
    # path01 = d1.local/
    # path03 = d1.local/api
    # path05 = d1.local/api/v[0-9]+/
    # path02 = d1.local/app
    # path04 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),map_str(/etc/haproxy/maps/_back_d1_app_8080_idpath__exact.map)
    http-request set-var(txn.pathID) var(req.base),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpath__prefix_02.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) var(req.base),map_reg(/etc/haproxy/maps/_back_d1_app_8080_idpath__regex.map) if !{ var(txn.pathID) -m found }
    acl allow_rule_src0 src 172.17.0.0/16
    http-request deny if { var(txn.pathID) -m str path01 } !allow_rule_src0
    acl allow_rule_src1 src 10.0.0.0/8 192.168.0.0/16
    http-request deny if { var(txn.pathID) -m str path02 path03 path04 path05 } !allow_rule_src1`,
			expFronts: "<<frontends-default-match-4>>",
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__exact.map": `
d1.local#/app path02`,
				"_back_d1_app_8080_idpath__prefix_02.map": `
d1.local#/path path04`,
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/api path03
d1.local#/ path01`,
				"_back_d1_app_8080_idpath__regex.map": `
^d1\.local#/api/v[0-9]+/ path05`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app1")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8"}
				b.FindBackendPath(h.FindPath("/app1")[0].Link).AllowedIPHTTP.Exception = []string{"10.0.110.0/24"}
				b.FindBackendPath(h.FindPath("/app2")[0].Link).DeniedIPHTTP.Rule = []string{"192.168.95.0/24"}
				b.FindBackendPath(h.FindPath("/app2")[0].Link).DeniedIPHTTP.Exception = []string{"192.168.95.128/28"}
			},
			path: []string{"/app1", "/app2", "/app3"},
			expected: `
    # path01 = d1.local/app1
    # path02 = d1.local/app2
    # path03 = d1.local/app3
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    acl allow_rule_src0 src 10.0.0.0/8
    acl allow_exception_src0 src 10.0.110.0/24
    http-request deny if { var(txn.pathID) -m str path01 } allow_exception_src0
    http-request deny if { var(txn.pathID) -m str path01 } !allow_rule_src0
    acl deny_rule_src1 src 192.168.95.0/24
    acl deny_exception_src1 src 192.168.95.128/28
    http-request deny if { var(txn.pathID) -m str path02 } deny_rule_src1 !deny_exception_src1`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/app3 path03
d1.local#/app2 path02
d1.local#/app1 path01`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app1")[0].Link).AllowedIPHTTP.Rule = []string{"10.0.0.0/8"}
				b.FindBackendPath(h.FindPath("/app2")[0].Link).AllowedIPHTTP.Exception = []string{"10.0.110.0/24"}
				b.FindBackendPath(h.FindPath("/app3")[0].Link).DeniedIPHTTP.Rule = []string{"192.168.95.0/24"}
				b.FindBackendPath(h.FindPath("/app4")[0].Link).DeniedIPHTTP.Exception = []string{"192.168.95.128/28"}
			},
			path: []string{"/app1", "/app2", "/app3", "/app4"},
			expected: `
    # path01 = d1.local/app1
    # path02 = d1.local/app2
    # path03 = d1.local/app3
    # path04 = d1.local/app4
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    acl allow_rule_src0 src 10.0.0.0/8
    http-request deny if { var(txn.pathID) -m str path01 } !allow_rule_src0
    acl allow_exception_src1 src 10.0.110.0/24
    http-request deny if { var(txn.pathID) -m str path02 } allow_exception_src1
    acl deny_rule_src1 src 192.168.95.0/24
    http-request deny if { var(txn.pathID) -m str path03 } deny_rule_src1
    acl deny_exception_src2 src 192.168.95.128/28
    http-request deny if { var(txn.pathID) -m str path04 } !deny_exception_src2`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/app4 path04
d1.local#/app3 path03
d1.local#/app2 path02
d1.local#/app1 path01`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/path")[0].Link).AllowedIPHTTP.Rule = []string{
					"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5",
					"1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10",
					"1.1.1.11",
				}
			},
			path: []string{"/app", "/api", "/path"},
			expected: `
    # path02 = d1.local/api
    # path01 = d1.local/app
    # path03 = d1.local/path
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    acl allow_rule_src1 src 1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 1.1.1.8 1.1.1.9 1.1.1.10
    acl allow_rule_src1 src 1.1.1.11
    http-request deny if { var(txn.pathID) -m str path03 } !allow_rule_src1`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/path path03
d1.local#/app path01
d1.local#/api path02`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.AllowedIPTCP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.AllowedIPTCP.Exception = []string{"192.168.95.0/24"}
				b.ModeTCP = true
			},
			expected: `
    acl allow_rule_tcp src 10.0.0.0/8 192.168.0.0/16
    acl allow_exception_tcp src 192.168.95.0/24
    tcp-request content reject if allow_exception_tcp
    tcp-request content reject if !allow_rule_tcp`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.DeniedIPTCP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.ModeTCP = true
			},
			expected: `
    acl deny_rule_tcp src 10.0.0.0/8 192.168.0.0/16
    tcp-request content reject if deny_rule_tcp`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.DeniedIPTCP.Rule = []string{"10.0.0.0/8", "192.168.0.0/16"}
				b.DeniedIPTCP.Exception = []string{"192.168.95.0/24"}
				b.ModeTCP = true
			},
			expected: `
    acl deny_rule_tcp src 10.0.0.0/8 192.168.0.0/16
    acl deny_exception_tcp src 192.168.95.0/24
    tcp-request content reject if deny_rule_tcp !deny_exception_tcp`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/")[0].Link).MaxBodySize = 1024
				b.FindBackendPath(h.FindPath("/app")[0].Link).MaxBodySize = 1024
			},
			path: []string{"/", "/app"},
			expected: `
    http-request use-service lua.send-413 if { req.body_size,sub(1024) gt 0 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.FindBackendPath(h.FindPath("/app")[0].Link).MaxBodySize = 2048
			},
			path: []string{"/", "/app"},
			expected: `
    # path01 = d1.local/
    # path02 = d1.local/app
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request use-service lua.send-413 if { var(txn.pathID) -m str path02 } { req.body_size,sub(2048) gt 0 }`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__begin.map": `
d1.local#/app path02
d1.local#/ path01`,
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Headers = []*hatypes.BackendHeader{
					{Name: "Name", Value: "Value"},
				}
			},
			expected: `
    http-request set-header Name Value`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				auth := &b.FindBackendPath(h.FindPath("/app1")[0].Link).AuthExternal
				auth.AuthBackendName = "_auth_4001"
				auth.AuthPath = "/oauth2/auth"
				auth.HeadersRequest = []string{"*"}
				auth.HeadersSucceed = []string{"*"}
				auth.HeadersFail = []string{"*"}
				auth.Method = "GET"
			},
			path: []string{"/app1", "/app2"},
			expected: `
    # path01 = d1.local/app1
    # path02 = d1.local/app2
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request lua.auth-intercept _auth_4001 /oauth2/auth GET '*' '*' '*' if { var(txn.pathID) -m str path01 }
    http-request deny if !{ var(txn.auth_response_successful) -m bool } { var(txn.pathID) -m str path01 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				auth := &b.FindBackendPath(h.FindPath("/app1")[0].Link).AuthExternal
				auth.AuthBackendName = "_auth_4001"
				auth.AuthPath = "/oauth2/auth"
				auth.HeadersRequest = []string{"X-UserID1", "X-Token1"}
				auth.HeadersSucceed = []string{"X-UserID2", "X-Token2"}
				auth.HeadersFail = []string{"X-UserID3", "X-Token3"}
				auth.Method = "GET"
				auth.RedirectOnFail = "http://auth.local/auth1"
			},
			path: []string{"/app1", "/app2"},
			expected: `
    # path01 = d1.local/app1
    # path02 = d1.local/app2
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request lua.auth-intercept _auth_4001 /oauth2/auth GET 'X-UserID1,X-Token1' 'X-UserID2,X-Token2' 'X-UserID3,X-Token3' if { var(txn.pathID) -m str path01 }
    http-request redirect location http://auth.local/auth1 if !{ var(txn.auth_response_successful) -m bool } { var(txn.pathID) -m str path01 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				auth := &b.FindBackendPath(h.FindPath("/app1")[0].Link).AuthExternal
				auth.AuthBackendName = "_auth_4001"
				auth.AuthPath = "/oauth2/auth"
				auth.HeadersRequest = []string{"*"}
				auth.HeadersSucceed = []string{"-"}
				auth.HeadersFail = []string{"-"}
				auth.HeadersVars = map[string]string{"X-Auth-Request-Email": "req.auth_response_header.x_auth_request_email"}
				auth.Method = "HEAD"
				auth.RedirectOnFail = "http://auth.local/login"
			},
			path: []string{"/app1", "/app2"},
			expected: `
    # path01 = d1.local/app1
    # path02 = d1.local/app2
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request lua.auth-intercept _auth_4001 /oauth2/auth HEAD '*' '-' '-' if { var(txn.pathID) -m str path01 }
    http-request redirect location http://auth.local/login if !{ var(txn.auth_response_successful) -m bool } { var(txn.pathID) -m str path01 }
    http-request set-header X-Auth-Request-Email %[var(req.auth_response_header.x_auth_request_email)] if { var(req.auth_response_header.x_auth_request_email) -m found } { var(txn.pathID) -m str path01 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				auth := &b.FindBackendPath(h.FindPath("/app1")[0].Link).AuthExternal
				auth.AlwaysDeny = true
			},
			path: []string{"/app1", "/app2"},
			expected: `
    # path01 = d1.local/app1
    # path02 = d1.local/app2
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request deny if { var(txn.pathID) -m str path01 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.SourceIPs = []net.IP{net.ParseIP("192.168.0.2"), net.ParseIP("192.168.0.3")}
			},
			// IP distribution starts based on the hash of the backend name.
			// Here it's starting from the second item, but this should change if
			// the number of IPs or the name of the backend change.
			srvsuffix: "source 192.168.0.3",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.HealthCheck.Interval = "2s"
			},
			srvsuffix: "check inter 2s",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.HealthCheck.URI = "/check"
				b.HealthCheck.Port = 4000
			},
			expected: `
    option httpchk /check`,
			srvsuffix: "check port 4000",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.AgentCheck.Port = 8000
				b.AgentCheck.Interval = "2s"
			},
			srvsuffix: "agent-check agent-port 8000 agent-inter 2s",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
			},
			srvsuffix: "ssl verify none",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.Ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256"
				b.Server.CipherSuites = "TLS_AES_128_GCM_SHA256"
			},
			srvsuffix: "ssl ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ciphersuites TLS_AES_128_GCM_SHA256 verify none",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CrtFilename = "/var/haproxy/ssl/client.pem"
				b.Server.CipherSuites = "TLS_AES_128_GCM_SHA256"
				b.Server.Options = "no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets"
			},
			srvsuffix: "ssl ciphersuites TLS_AES_128_GCM_SHA256 no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets crt /var/haproxy/ssl/client.pem verify none",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CrtFilename = "/var/haproxy/ssl/client.pem"
			},
			srvsuffix: "ssl crt /var/haproxy/ssl/client.pem verify none",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
			},
			srvsuffix: "ssl verify required ca-file /var/haproxy/ssl/ca.pem",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
				b.Server.CRLFilename = "/var/haproxy/ssl/crl.pem"
			},
			srvsuffix: "ssl verify required ca-file /var/haproxy/ssl/ca.pem crl-file /var/haproxy/ssl/crl.pem",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.SNI = "var(req.host)"
			},
			srvsuffix: "ssl sni var(req.host) verify none",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
				b.Server.SNI = "ssl_fc_sni"
			},
			srvsuffix: "ssl sni ssl_fc_sni verify required ca-file /var/haproxy/ssl/ca.pem",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
				b.Server.VerifyHost = "domain.tld"
			},
			srvsuffix: "ssl verify required ca-file /var/haproxy/ssl/ca.pem verifyhost domain.tld",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Protocol = "h2"
			},
			srvsuffix: "proto h2",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Protocol = "h2"
				b.Server.Secure = true
			},
			srvsuffix: "proto h2 alpn h2 ssl verify none",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.Protocol = "h2"
				b.Server.Secure = true
				b.Server.CAFilename = "/var/haproxy/ssl/ca.pem"
			},
			srvsuffix: "proto h2 alpn h2 ssl verify required ca-file /var/haproxy/ssl/ca.pem",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Limit.RPS = 20
			},
			expected: `
    stick-table type ip size 200k expire 5m store conn_cur,conn_rate(1s)
    http-request track-sc1 src
    http-request deny deny_status 429 if { sc1_conn_rate gt 20 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Limit.Connections = 200
			},
			expected: `
    stick-table type ip size 200k expire 5m store conn_cur,conn_rate(1s)
    http-request track-sc1 src
    http-request deny deny_status 429 if { sc1_conn_cur gt 200 }`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Server.SendProxy = "send-proxy-v2"
			},
			srvsuffix: "send-proxy-v2",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
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
		// simulates a config where the cookie value is a pod id
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "serverId"
				b.Cookie.Strategy = "insert"
				b.Cookie.Keywords = "nocache"
				b.EpCookieStrategy = hatypes.EpCookiePodUID
				ep1 := *endpointS1
				b.Endpoints = []*hatypes.Endpoint{&ep1}
				b.Endpoints[0].CookieValue = "9d344d6c-6069-4aee-85e6-9348e70c71e6"
			},
			srvsuffix: "cookie 9d344d6c-6069-4aee-85e6-9348e70c71e6",
			expected: `
    cookie serverId insert nocache`,
		},
		// simulates a config where the cookie "preserve" option is used
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Cookie.Name = "serverId"
				b.Cookie.Strategy = "insert"
				b.Cookie.Preserve = true
				b.Cookie.Keywords = "nocache"
				ep1 := *endpointS1
				b.Endpoints = []*hatypes.Endpoint{&ep1}
				b.Endpoints[0].CookieValue = "web-abcde"
			},
			srvsuffix: "cookie web-abcde",
			expected: `
    cookie serverId insert preserve nocache`,
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.Endpoints[0].PUID = 1234567
			},
			srvsuffix: "id 1234567",
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				link1 := hatypes.CreatePathLink("/app1", hatypes.MatchPrefix).
					WithHeadersMatch(hatypes.HTTPHeaderMatch{{Name: "x-user", Value: "myusr1"}})
				link2 := hatypes.CreatePathLink("/app2", hatypes.MatchPrefix).
					WithHeadersMatch(hatypes.HTTPHeaderMatch{{Name: "x-user", Value: "myusr2"}})

				hdef := c.hosts.AcquireHost(hatypes.DefaultHost)
				b.FindBackendPath(hdef.AddLink(b, link1)).MaxBodySize = 1048576
				b.FindBackendPath(hdef.AddLink(b, link2)).MaxBodySize = 2097152

				b.FindBackendPath(h.AddLink(b, link1)).MaxBodySize = 1048576
				b.FindBackendPath(h.AddLink(b, link2)).MaxBodySize = 2097152
			},
			expected: `
    # path02 = <default>/app1
    # path03 = <default>/app2
    # path01 = d1.local/
    # path04 = d1.local/app1
    # path05 = d1.local/app2
    http-request set-var(txn.pathID) var(req.base),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpath__prefix_01.map) if { hdr(x-user) -- 'myusr2' }
    http-request set-var(txn.pathID) var(req.base),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpath__prefix_02.map) if !{ var(txn.pathID) -m found } { hdr(x-user) -- 'myusr1' }
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpathdef__prefix_01.map) if !{ var(txn.pathID) -m found } { hdr(x-user) -- 'myusr2' }
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpathdef__prefix_02.map) if !{ var(txn.pathID) -m found } { hdr(x-user) -- 'myusr1' }
    http-request use-service lua.send-413 if { var(txn.pathID) -m str path02 path04 } { req.body_size,sub(1048576) gt 0 }
    http-request use-service lua.send-413 if { var(txn.pathID) -m str path03 path05 } { req.body_size,sub(2097152) gt 0 }`,
			expFronts: `frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_dir(/etc/haproxy/maps/_front_http_host__prefix_01.map) if { hdr(x-user) -- 'myusr1' }
    http-request set-var(req.backend) var(req.base),map_dir(/etc/haproxy/maps/_front_http_host__prefix_02.map) if !{ var(req.backend) -m found } { hdr(x-user) -- 'myusr2' }
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map) if !{ var(req.backend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_front_defaulthost__prefix_01.map) if !{ var(req.backend) -m found } { hdr(x-user) -- 'myusr1' }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_front_defaulthost__prefix_02.map) if !{ var(req.backend) -m found } !{ var(req.defaultbackend) -m found } { hdr(x-user) -- 'myusr2' }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),map_dir(/etc/haproxy/maps/_front_https_host__prefix_01.map) if { hdr(x-user) -- 'myusr1' }
    http-request set-var(req.hostbackend) var(req.base),map_dir(/etc/haproxy/maps/_front_https_host__prefix_02.map) if !{ var(req.hostbackend) -m found } { hdr(x-user) -- 'myusr2' }
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_front_defaulthost__prefix_01.map) if !{ var(req.hostbackend) -m found } { hdr(x-user) -- 'myusr1' }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_front_defaulthost__prefix_02.map) if !{ var(req.hostbackend) -m found } !{ var(req.defaultbackend) -m found } { hdr(x-user) -- 'myusr2' }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend _error404`,
			expCheck: map[string]string{
				"_back_d1_app_8080_idpath__prefix_01.map":    "d1.local#/app2 path05",
				"_back_d1_app_8080_idpath__prefix_02.map":    "d1.local#/app1 path04",
				"_back_d1_app_8080_idpath__begin.map":        "d1.local#/ path01",
				"_back_d1_app_8080_idpathdef__prefix_01.map": "<default>#/app2 path03",
				"_back_d1_app_8080_idpathdef__prefix_02.map": "<default>#/app1 path02",
			},
		},
		{
			doconfig: func(c *config, h *hatypes.Host, b *hatypes.Backend) {
				b.ModeTCP = true
				b.CustomConfig = []string{"## custom for TCP backend"}
			},
			expected: `
    ## custom for TCP backend`,
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
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		ep := *endpointS1
		b.Endpoints = []*hatypes.Endpoint{&ep}
		h = c.config.Hosts().AcquireHost("d1.local")
		for j, p := range test.path {
			match := hatypes.MatchBegin
			if test.match != nil {
				match = test.match[j]
			}
			h.AddPath(b, p, match)
		}
		test.doconfig(c.config, h, b)

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

func TestInstanceClean(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
<<backends-default>>
<<frontend-http-clean>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceBare(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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

func TestInstanceBareHTTP(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.TLS.UseDefaultCrt = false
	h.AddPath(b, "/", hatypes.MatchBegin)

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontend-http>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
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
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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
    <<set-req-base>>
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
    unix-bind mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    lua-prepend-path /etc/haproxy/lua/?.lua
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    lua-load /etc/haproxy/lua/responses.lua
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
empty#/ default_empty_8080`)
	c.checkMap("_front_https_host__begin.map", `
empty#/ default_empty_8080`)

	c.logger.CompareLogging(defaultLogging)
}

func TestDefaultBackendRedir(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.Global().DefaultBackendRedir = "https://example.tld"
	c.config.Hosts().AcquireHost("empty").AddPath(c.config.Backends().AcquireBackend("default", "empty", "8080"), "/", hatypes.MatchBegin)

	c.Update()

	c.checkConfig(`
global
    daemon
    unix-bind mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    lua-prepend-path /etc/haproxy/lua/?.lua
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    lua-load /etc/haproxy/lua/responses.lua
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
    redirect location https://example.tld code 301
<<frontends-default>>
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
empty#/ default_empty_8080`)
	c.checkMap("_front_https_host__begin.map", `
empty#/ default_empty_8080`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceEmptyExternal(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.instance.options.IsExternal = true
	c.instance.options.IsMasterWorker = true
	c.config.global.External.IsExternal = true
	c.config.global.Master.IsMasterWorker = true
	c.config.global.Master.WorkerMaxReloads = 20
	c.config.global.Security.Username = "external"
	c.config.global.Security.Groupname = "external"

	c.config.Hosts().AcquireHost("empty").AddPath(c.config.Backends().AcquireBackend("default", "empty", "8080"), "/", hatypes.MatchBegin)
	c.Update()

	c.checkConfig(`
global
    master-worker
    user external
    group external
    unix-bind user external group external mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    mworker-max-reloads 20
    lua-load /etc/haproxy/lua/services.lua
    lua-load /etc/haproxy/lua/responses.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
    ssl-default-bind-options no-sslv3
    ssl-default-server-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256
<<defaults>>
backend default_empty_8080
    mode http
backend _error404
    mode http
    http-request use-service lua.send-404
<<frontends-default>>
<<support>>
`)
	c.logger.CompareLogging(`
INFO (test) reload was skipped
INFO haproxy successfully reloaded (external)`)
}

func TestPathIDsSplit(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	b := c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	max := 32
	for i := 1; i <= max; i++ {
		h := c.config.Hosts().AcquireHost(fmt.Sprintf("h%02d.local", i))
		h.AddPath(b, "/", hatypes.MatchBegin)
		path := b.FindBackendPath(h.FindPath("/")[0].Link)
		path.SSLRedirect = true
		path.AllowedIPHTTP.Rule = []string{"10.0.0.0/8"}
		if i < max {
			path.HSTS.Enabled = true
			path.Cors.Enabled = true
			path.Cors.AllowOrigin = []string{"*"}
			path.Cors.AllowMethods = "GET, PUT, POST, DELETE, PATCH, OPTIONS"
			path.Cors.AllowHeaders = "DNT,X-CustomHeader,Keep-Alive,User-Agent"
		}
	}

	c.Update()

	pathIDs01_30 := "path01 path02 path03 path04 path05 path06 path07 path08 path09 path10 path11 path12 path13 path14 path15 path16 path17 path18 path19 path20 path21 path22 path23 path24 path25 path26 path27 path28 path29 path30"
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl https-request ssl_fc
    # path01 = h01.local/
    # path02 = h02.local/
    # path03 = h03.local/
    # path04 = h04.local/
    # path05 = h05.local/
    # path06 = h06.local/
    # path07 = h07.local/
    # path08 = h08.local/
    # path09 = h09.local/
    # path10 = h10.local/
    # path11 = h11.local/
    # path12 = h12.local/
    # path13 = h13.local/
    # path14 = h14.local/
    # path15 = h15.local/
    # path16 = h16.local/
    # path17 = h17.local/
    # path18 = h18.local/
    # path19 = h19.local/
    # path20 = h20.local/
    # path21 = h21.local/
    # path22 = h22.local/
    # path23 = h23.local/
    # path24 = h24.local/
    # path25 = h25.local/
    # path26 = h26.local/
    # path27 = h27.local/
    # path28 = h28.local/
    # path29 = h29.local/
    # path30 = h30.local/
    # path31 = h31.local/
    # path32 = h32.local/
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpath__begin.map)
    http-request redirect scheme https if !https-request
    acl allow_rule_src0 src 10.0.0.0/8
    http-request deny if !allow_rule_src0
    http-request set-var(txn.cors_max_age) str(0) if METH_OPTIONS { var(txn.pathID) -m str ` + pathIDs01_30 + ` }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) -m str ` + pathIDs01_30 + ` }
    http-request set-var(txn.cors_max_age) str(0) if METH_OPTIONS { var(txn.pathID) -m str path31 }
    http-request use-service lua.send-cors-preflight if METH_OPTIONS { var(txn.pathID) -m str path31 }
    http-response set-header Strict-Transport-Security "max-age=0" if { var(txn.pathID) -m str ` + pathIDs01_30 + ` }
    http-response set-header Strict-Transport-Security "max-age=0" if { var(txn.pathID) -m str path31 }
    http-response set-header Access-Control-Allow-Origin  "*" if { var(txn.pathID) -m str ` + pathIDs01_30 + ` }
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) -m str ` + pathIDs01_30 + ` }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent" if { var(txn.pathID) -m str ` + pathIDs01_30 + ` }
    http-response set-header Access-Control-Allow-Origin  "*" if { var(txn.pathID) -m str path31 }
    http-response set-header Access-Control-Allow-Methods "GET, PUT, POST, DELETE, PATCH, OPTIONS" if { var(txn.pathID) -m str path31 }
    http-response set-header Access-Control-Allow-Headers "DNT,X-CustomHeader,Keep-Alive,User-Agent" if { var(txn.pathID) -m str path31 }
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSecurity(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.global.Security.Username = "haproxy"
	c.config.global.Security.Groupname = "haproxy"

	c.config.Hosts().AcquireHost("empty").AddPath(c.config.Backends().AcquireBackend("default", "empty", "8080"), "/", hatypes.MatchBegin)
	c.Update()

	c.checkConfig(`
global
    daemon
    user haproxy
    group haproxy
    unix-bind user haproxy group haproxy mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    lua-prepend-path /etc/haproxy/lua/?.lua
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    lua-load /etc/haproxy/lua/responses.lua
    ssl-dh-param-file /var/haproxy/tls/dhparam.pem
    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
    ssl-default-bind-options no-sslv3
    ssl-default-server-ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256
<<defaults>>
backend default_empty_8080
    mode http
backend _error404
    mode http
    http-request use-service lua.send-404
<<frontends-default>>
<<support>>
`)
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

	c.checkMap("_front_http_host__prefix.map", `
d1.local#/app default_d1_8080`)
	c.checkMap("_front_http_host__regex.map", `
^d1\.local#/api/v[0-9]+/ default_d1_8080`)
	c.checkMap("_front_https_host__prefix.map", `
d1.local#/app default_d1_8080`)
	c.checkMap("_front_https_host__regex.map", `
^d1\.local#/api/v[0-9]+/ default_d1_8080`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontingProxy(t *testing.T) {
	var (
		frontUseProto = `
    <<set-req-base>>
    http-request set-header X-Forwarded-Proto http if !fronting-proxy
    http-request del-header X-SSL-Client-CN if !fronting-proxy
    http-request del-header X-SSL-Client-DN if !fronting-proxy
    http-request del-header X-SSL-Client-SHA1 if !fronting-proxy
    http-request del-header X-SSL-Client-SHA2 if !fronting-proxy
    http-request del-header X-SSL-Client-Cert if !fronting-proxy
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`
		aclFrontExact = `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-has-invalid-crt ssl_c_verify gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list`
		aclFrontRegex = `
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-host-need-crt var(req.host) -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-has-invalid-crt ssl_c_verify gt 0
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list`
		aclBackWithSockID = `
    acl fronting-proxy so_id 11
    acl https-request ssl_fc
    acl https-request var(txn.proto) -m str https`
		aclBackWithHdr = `
    acl fronting-proxy hdr(X-Forwarded-Proto) -m found
    acl https-request ssl_fc
    acl https-request var(txn.proto) -m str https`
		setHeaderWithACL = `
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if local-offload
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if local-offload
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if local-offload
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" if https-request`
		setHeaderSSLWithACL = `
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if local-offload
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if local-offload
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if local-offload
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload"`
		setHeaderNoACL = `
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]
    http-response set-header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload"`
		setvarBegin = `
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)`
		setvarRegex = `
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map)`
	)
	testCases := []struct {
		frontingBind      string
		domain            string
		useProto          bool
		sslRedirect       bool
		expectedACLBack   string
		expectedSetHeader string
		expectedFront     string
		expectedMap       string
		expectedRegexMap  string
		expectedACLFront  string
		expectedSetvar    string
	}{
		// 0
		{
			frontingBind:    ":8000",
			domain:          "d1.local",
			useProto:        true,
			sslRedirect:     false,
			expectedACLBack: aclBackWithSockID,
			expectedSetHeader: `
    http-request set-var(txn.proto) hdr(X-Forwarded-Proto)
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }` + setHeaderWithACL,
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    acl fronting-proxy so_id 11` + frontUseProto,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 1
		{
			frontingBind:    ":8000",
			domain:          "*.d1.local",
			useProto:        true,
			sslRedirect:     false,
			expectedACLBack: aclBackWithSockID,
			expectedSetHeader: `
    http-request set-var(txn.proto) hdr(X-Forwarded-Proto)
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }` + setHeaderWithACL,
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    acl fronting-proxy so_id 11
    <<set-req-base>>
    http-request set-header X-Forwarded-Proto http if !fronting-proxy
    http-request del-header X-SSL-Client-CN if !fronting-proxy
    http-request del-header X-SSL-Client-DN if !fronting-proxy
    http-request del-header X-SSL-Client-SHA1 if !fronting-proxy
    http-request del-header X-SSL-Client-SHA2 if !fronting-proxy
    http-request del-header X-SSL-Client-Cert if !fronting-proxy
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedRegexMap: `^[^.]+\.d1\.local#/ d1_app_8080`,
			expectedACLFront: aclFrontRegex,
			expectedSetvar:   setvarRegex,
		},
		// 2
		{
			frontingBind:    ":80",
			domain:          "d1.local",
			useProto:        true,
			sslRedirect:     false,
			expectedACLBack: aclBackWithHdr,
			expectedSetHeader: `
    http-request set-var(txn.proto) hdr(X-Forwarded-Proto)
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }` + setHeaderWithACL,
			expectedFront: `
    mode http
    bind :80
    acl fronting-proxy hdr(X-Forwarded-Proto) -m found` + frontUseProto,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 3
		{
			frontingBind:      ":8000",
			domain:            "d1.local",
			useProto:          false,
			sslRedirect:       false,
			expectedACLBack:   ``,
			expectedSetHeader: setHeaderSSLWithACL,
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 4
		{
			frontingBind:      ":8000",
			domain:            "*.d1.local",
			useProto:          false,
			sslRedirect:       false,
			expectedACLBack:   ``,
			expectedSetHeader: setHeaderSSLWithACL,
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedRegexMap: `^[^.]+\.d1\.local#/ d1_app_8080`,
			expectedACLFront: aclFrontRegex,
			expectedSetvar:   setvarRegex,
		},
		// 5
		{
			frontingBind:      ":80",
			domain:            "d1.local",
			useProto:          false,
			sslRedirect:       false,
			expectedACLBack:   ``,
			expectedSetHeader: setHeaderSSLWithACL,
			expectedFront: `
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 6
		{
			frontingBind:    ":8000",
			domain:          "d1.local",
			useProto:        true,
			sslRedirect:     true,
			expectedACLBack: aclBackWithSockID,
			expectedSetHeader: `
    http-request set-var(txn.proto) hdr(X-Forwarded-Proto)
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }
    http-request redirect scheme https if !fronting-proxy !https-request` + setHeaderNoACL,
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    acl fronting-proxy so_id 11` + frontUseProto,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 7
		{
			frontingBind:    ":80",
			domain:          "d1.local",
			useProto:        true,
			sslRedirect:     true,
			expectedACLBack: aclBackWithHdr,
			expectedSetHeader: `
    http-request set-var(txn.proto) hdr(X-Forwarded-Proto)
    http-request redirect scheme https if fronting-proxy !{ hdr(X-Forwarded-Proto) https }
    http-request redirect scheme https if !fronting-proxy !https-request` + setHeaderNoACL,
			expectedFront: `
    mode http
    bind :80
    acl fronting-proxy hdr(X-Forwarded-Proto) -m found` + frontUseProto,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 8
		{
			frontingBind:      ":8000",
			domain:            "d1.local",
			useProto:          false,
			sslRedirect:       true,
			expectedACLBack:   ``,
			expectedSetHeader: setHeaderNoACL,
			expectedFront: `
    mode http
    bind :80
    bind :8000 id 11
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
		// 9
		{
			frontingBind:      ":80",
			domain:            "d1.local",
			useProto:          false,
			sslRedirect:       true,
			expectedACLBack:   ``,
			expectedSetHeader: setHeaderNoACL,
			expectedFront: `
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
			expectedMap:      "d1.local#/ d1_app_8080",
			expectedACLFront: aclFrontExact,
			expectedSetvar:   setvarBegin,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		h = c.config.Hosts().AcquireHost(test.domain)
		h.AddPath(b, "/", hatypes.MatchBegin)
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		b.FindBackendPath(h.FindPath("/")[0].Link).SSLRedirect = test.sslRedirect
		b.FindBackendPath(h.FindPath("/")[0].Link).HSTS = hatypes.HSTS{
			Enabled:    true,
			MaxAge:     15768000,
			Subdomains: true,
			Preload:    true,
		}
		h.TLS.CAHash = "1"
		h.TLS.CAFilename = "/var/haproxy/ssl/ca.pem"
		c.config.Global().Bind.FrontingBind = test.frontingBind
		c.config.Global().Bind.FrontingSockID = 11
		c.config.Global().Bind.FrontingUseProto = test.useProto

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http` + test.expectedACLBack + `
    acl local-offload ssl_fc` + test.expectedSetHeader + `
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http` + test.expectedFront + `
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>` + test.expectedSetvar + `
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert` + test.expectedACLFront + `
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-496 if { var(req.tls_nocrt_redir) -m str _internal }
    http-request use-service lua.send-421 if !tls-has-crt tls-host-need-crt
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) -m str _internal }
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

func TestInstanceTCPServices(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.ModeTCP = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	b2 := c.config.Backends().AcquireBackend("d2", "app", "8080")
	b2.ModeTCP = true
	b2.Endpoints = []*hatypes.Endpoint{endpointS21, endpointS22}
	b3 := c.config.Backends().AcquireBackend("d3", "app", "8080")
	b3.ModeTCP = true
	b3.Endpoints = []*hatypes.Endpoint{endpointS31, endpointS32}

	services := []struct {
		port      int
		hostname  string
		backend   hatypes.BackendID
		proxyProt bool
		tls       hatypes.TLSConfig
		custom    []string
	}{
		{
			port: 7000,
		},
		{
			port:    7001,
			backend: b.BackendID(),
		},
		{
			port:      7002,
			backend:   b.BackendID(),
			proxyProt: true,
		},
		{
			port:      7003,
			backend:   b.BackendID(),
			proxyProt: true,
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7003.pem",
			},
		},
		{
			port:    7004,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7004.pem",
			},
		},
		{
			port:    7005,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7005.pem",
				CAFilename:  "/ssl/ca-7005.pem",
			},
		},
		{
			port:    7006,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7006.pem",
				CAFilename:  "/ssl/ca-7006.pem",
				CRLFilename: "/ssl/crl-7006.pem",
			},
		},
		{
			port:    7007,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				ALPN:        "h2,http/1.1",
				TLSFilename: "/ssl/7007.pem",
			},
		},
		{
			port:    7008,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7008.pem",
				CAFilename:  "/ssl/ca-7008.pem",
				CAVerify:    hatypes.CAVerifySkipCheck,
			},
		},
		{
			port:    7009,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename:  "/ssl/7009.pem",
				Ciphers:      "ECDHE-ECDSA-AES128-GCM-SHA256",
				CipherSuites: "TLS_AES_128_GCM_SHA256",
			},
		},
		{
			port:    7010,
			backend: b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7010.pem",
				Options:     "force-tlsv13",
			},
		},
		{
			port:    7011,
			backend: b.BackendID(),
		},
		{
			port:     7011,
			hostname: "local2",
			backend:  b2.BackendID(),
		},
		{
			port:     7011,
			hostname: "local3",
			backend:  b3.BackendID(),
		},
		{
			port:     7011,
			hostname: "*.local4",
			backend:  b3.BackendID(),
		},
		{
			port:     7012,
			hostname: "local1",
			backend:  b.BackendID(),
			tls: hatypes.TLSConfig{
				TLSFilename: "/ssl/7012.pem",
			},
		},
		{
			port:    7013,
			backend: b.BackendID(),
			custom:  []string{"## custom for TCP 7013"},
		},
		{
			port:    7014,
			backend: b.BackendID(),
			custom:  []string{"## custom for TCP 7014", "## multi line"},
		},
	}

	for _, svc := range services {
		hostname := svc.hostname
		if hostname == "" {
			hostname = hatypes.DefaultHost
		}
		p, h := c.config.TCPServices().AcquireTCPService(fmt.Sprintf("%s:%d", hostname, svc.port))
		p.ProxyProt = svc.proxyProt
		p.TLS = svc.tls
		p.CustomConfig = svc.custom
		h.Backend = svc.backend
	}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode tcp
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode tcp
    server s21 172.17.0.121:8080 weight 100
    server s22 172.17.0.122:8080 weight 100
backend d3_app_8080
    mode tcp
    server s31 172.17.0.131:8080 weight 100
    server s32 172.17.0.132:8080 weight 100
<<backends-default>>
frontend _front_tcp_7000
    bind :7000
    mode tcp
frontend _front_tcp_7001
    bind :7001
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7002
    bind :7002 accept-proxy
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7003
    bind :7003 accept-proxy ssl crt /ssl/7003.pem
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7004
    bind :7004 ssl crt /ssl/7004.pem
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7005
    bind :7005 ssl crt /ssl/7005.pem ca-file /ssl/ca-7005.pem verify required
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7006
    bind :7006 ssl crt /ssl/7006.pem ca-file /ssl/ca-7006.pem verify required crl-file /ssl/crl-7006.pem
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7007
    bind :7007 ssl crt /ssl/7007.pem alpn h2,http/1.1
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7008
    bind :7008 ssl crt /ssl/7008.pem ca-file /ssl/ca-7008.pem verify optional ca-ignore-err all crt-ignore-err all
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7009
    bind :7009 ssl crt /ssl/7009.pem ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ciphersuites TLS_AES_128_GCM_SHA256
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7010
    bind :7010 ssl crt /ssl/7010.pem force-tlsv13
    mode tcp
    default_backend d1_app_8080
frontend _front_tcp_7011
    bind :7011
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content set-var(req.tcpback) req.ssl_sni,lower,map_str(/etc/haproxy/maps/_tcp_sni_7011__exact.map)
    tcp-request content set-var(req.tcpback) req.ssl_sni,lower,map_reg(/etc/haproxy/maps/_tcp_sni_7011__regex.map) if !{ var(req.tcpback) -m found }
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend %[var(req.tcpback)] if { var(req.tcpback) -m found }
    default_backend d1_app_8080
frontend _front_tcp_7012
    bind :7012 ssl crt /ssl/7012.pem
    mode tcp
    tcp-request content set-var(req.tcpback) ssl_fc_sni,lower,map_str(/etc/haproxy/maps/_tcp_sni_7012__exact.map)
    use_backend %[var(req.tcpback)] if { var(req.tcpback) -m found }
frontend _front_tcp_7013
    bind :7013
    mode tcp
    ## custom for TCP 7013
    default_backend d1_app_8080
frontend _front_tcp_7014
    bind :7014
    mode tcp
    ## custom for TCP 7014
    ## multi line
    default_backend d1_app_8080
<<frontends-default>>
<<support>>
`)
	c.checkMap("_tcp_sni_7011__exact.map", `
local2 d2_app_8080
local3 d3_app_8080`)
	c.checkMap("_tcp_sni_7011__regex.map", `
^[^.]+\.local4$ d3_app_8080`)
	c.checkMap("_tcp_sni_7012__exact.map", `
local1 d1_app_8080`)
	c.logger.CompareLogging(defaultLogging)
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
	c.config.Backends().DefaultBackend = def

	var h *hatypes.Host
	var b *hatypes.Backend
	hdef := c.config.Hosts().AcquireHost(hatypes.DefaultHost)

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.VarNamespace = true
	hdef.AddPath(b, "/", hatypes.MatchBegin)
	hdef.AddPath(b, "/app1", hatypes.MatchExact)
	hdef.AddPath(b, "/app2", hatypes.MatchPrefix)
	b.FindBackendPath(hdef.FindPath("/")[0].Link).SSLRedirect = true
	b.FindBackendPath(hdef.FindPath("/app1")[0].Link).RewriteURL = "/"
	b.FindBackendPath(hdef.FindPath("/app2")[0].Link).MaxBodySize = 32768

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d2.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.VarNamespace = true
	h.AddPath(b, "/app11", hatypes.MatchBegin)
	hdef.AddPath(b, "/app12", hatypes.MatchExact)
	hdef.AddPath(b, "/app13", hatypes.MatchPrefix)
	b.FindBackendPath(h.FindPath("/app11")[0].Link).SSLRedirect = true
	b.FindBackendPath(hdef.FindPath("/app12")[0].Link).RewriteURL = "/"
	b.FindBackendPath(hdef.FindPath("/app13")[0].Link).MaxBodySize = 65536

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl https-request ssl_fc
    # path01 = <default>/
    # path02 = <default>/app1
    # path03 = <default>/app2
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),map_str(/etc/haproxy/maps/_back_d1_app_8080_idpathdef__exact.map)
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_back_d1_app_8080_idpathdef__prefix_02.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_back_d1_app_8080_idpathdef__begin.map) if !{ var(txn.pathID) -m found }
    http-request redirect scheme https if !https-request { var(txn.pathID) -m str path01 }
    http-request use-service lua.send-413 if { var(txn.pathID) -m str path03 } { req.body_size,sub(32768) gt 0 }
    http-request replace-path ^/app1/?(.*)$     /\1     if { var(txn.pathID) -m str path02 }
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    acl https-request ssl_fc
    # path02 = <default>/app12
    # path03 = <default>/app13
    # path01 = d2.local/app11
    http-request set-var(txn.pathID) var(req.base),lower,map_beg(/etc/haproxy/maps/_back_d2_app_8080_idpath__begin.map)
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),map_str(/etc/haproxy/maps/_back_d2_app_8080_idpathdef__exact.map) if !{ var(txn.pathID) -m found }
    http-request set-var(txn.pathID) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_back_d2_app_8080_idpathdef__prefix.map) if !{ var(txn.pathID) -m found }
    http-request redirect scheme https if !https-request { var(txn.pathID) -m str path01 }
    http-request use-service lua.send-413 if { var(txn.pathID) -m str path03 } { req.body_size,sub(65536) gt 0 }
    http-request replace-path ^/app12/?(.*)$     /\1     if { var(txn.pathID) -m str path02 }
    server s1 172.17.0.11:8080 weight 100
backend default_default-backend_8080
    mode http
    server s0 172.17.0.99:8080 weight 100
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map)
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_str(/etc/haproxy/maps/_front_defaulthost__exact.map) if !{ var(req.backend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_front_defaulthost__prefix_02.map) if !{ var(req.backend) -m found } !{ var(req.defaultbackend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin.map) if !{ var(req.backend) -m found } !{ var(req.defaultbackend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend default_default-backend_8080
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_str(/etc/haproxy/maps/_front_defaulthost__exact.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),map_dir(/etc/haproxy/maps/_front_defaulthost__prefix_02.map) if !{ var(req.hostbackend) -m found } !{ var(req.defaultbackend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin.map) if !{ var(req.hostbackend) -m found } !{ var(req.defaultbackend) -m found }
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map)
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend default_default-backend_8080
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d2.local#/app11 d2_app_8080
`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem !*
`)
	c.checkMap("_front_namespace__begin.map", `
d2.local#/app11 d2
`)
	c.checkMap("_front_https_host__begin.map", `
d2.local#/app11 d2_app_8080
`)
	c.checkMap("_front_defaulthost__prefix_02.map", `
<default>#/app2 d1_app_8080
<default>#/app13 d2_app_8080`)
	c.checkMap("_front_defaulthost__exact.map", `
<default>#/app1 d1_app_8080
<default>#/app12 d2_app_8080`)
	c.checkMap("_front_defaulthost__begin.map", `
<default>#/ d1_app_8080`)
	c.checkMap("_back_d1_app_8080_idpathdef__exact.map", `
<default>#/app1 path02`)
	c.checkMap("_back_d1_app_8080_idpathdef__prefix_02.map", `
<default>#/app2 path03`)
	c.checkMap("_back_d1_app_8080_idpathdef__begin.map", `
<default>#/ path01`)
	c.checkMap("_back_d2_app_8080_idpathdef__exact.map", `
<default>#/app12 path02`)
	c.checkMap("_back_d2_app_8080_idpathdef__prefix.map", `
<default>#/app13 path03`)
	c.checkMap("_back_d2_app_8080_idpath__begin.map", `
d2.local#/app11 path01`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceUseDefaultCrt(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.TLS.UseDefaultCrt = false
	h.AddPath(b, "/", hatypes.MatchBegin)

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS21}
	h = c.config.Hosts().AcquireHost("d2.local")
	h.TLS.UseDefaultCrt = true
	h.AddPath(b, "/", hatypes.MatchBegin)

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
<<frontends-default>>
<<support>>
`)
	c.checkMap("_front_http_host__begin.map", `
d1.local#/ d1_app_8080
d2.local#/ d2_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d2.local#/ d2_app_8080
`)
	c.logger.CompareLogging(defaultLogging)
}
func TestInstanceStrictHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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
	c.checkMap("_front_http_host__begin.map", `
d1.local#/path d1_app_8080
d1.local#/ _error404
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local#/path d1_app_8080
d1.local#/ _error404
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
frontend _front_http
    mode http
    bind :80
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin.map) if !{ var(req.backend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin.map) if !{ var(req.hostbackend) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend _error404
<<support>>
`)
	c.checkMap("_front_http_host__begin.map", `
d1.local#/path d1_app_8080
d1.local#/ d2_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local#/path d1_app_8080
d1.local#/ d2_app_8080
`)
	c.checkMap("_front_defaulthost__begin.map", `
<default>#/ d2_app_8080`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontend(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.global.ForwardFor = "add"
	c.config.global.OriginalForwardedForHdr = "X-Original-Forwarded-For"
	c.config.global.RealIPHdr = "X-Real-IP"

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().DefaultBackend = def

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.FindBackendPath(h.FindPath("/")[0].Link).SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.VarNamespace = true
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d1.pem"
	h.TLS.TLSHash = "1"

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/app", hatypes.MatchPrefix)
	b.FindBackendPath(h.FindPath("/app")[0].Link).SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/d2.pem"
	h.TLS.TLSHash = "2"

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl https-request ssl_fc
    http-request redirect scheme https if !https-request
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode http
    acl https-request ssl_fc
    http-request redirect scheme https if !https-request
    server s1 172.17.0.11:8080 weight 100
backend default_default-backend_8080
    mode http
    server s0 172.17.0.99:8080 weight 100
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(txn.namespace) var(req.base),map_dir(/etc/haproxy/maps/_front_namespace__prefix.map)
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map) if !{ var(txn.namespace) -m found }
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_dir(/etc/haproxy/maps/_front_http_host__prefix.map)
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map) if !{ var(req.backend) -m found }
    http-request set-header X-Original-Forwarded-For %[hdr(x-forwarded-for)] if { hdr(x-forwarded-for) -m found }
    http-request del-header x-forwarded-for
    option forwardfor
    http-request set-header X-Real-IP %[src]
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend default_default-backend_8080
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
    http-request set-header X-Original-Forwarded-For %[hdr(x-forwarded-for)] if { hdr(x-forwarded-for) -m found }
    http-request del-header x-forwarded-for
    option forwardfor
    http-request set-header X-Real-IP %[src]
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend default_default-backend_8080
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d1.local#/ d1_app_8080
`)
	c.checkMap("_front_http_host__prefix.map", `
d2.local#/app d2_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local#/ d1_app_8080
`)
	c.checkMap("_front_https_host__prefix.map", `
d2.local#/app d2_app_8080
`)
	c.checkMap("_front_namespace__begin.map", `
d1.local#/ d1
`)
	c.checkMap("_front_namespace__prefix.map", `
d2.local#/app -
`)

	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem !*
/var/haproxy/ssl/certs/d1.pem d1.local
/var/haproxy/ssl/certs/d2.pem d2.local
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontendMatchHeader(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.frontend.RedirectToCode = 302

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().DefaultBackend = def

	var h1, h2, h3, h4, h5 *hatypes.Host
	var b1, b21 *hatypes.Backend
	var link1, link2, link3 *hatypes.PathLink

	// http/s
	//
	// h2/app2        +x-version         => b21
	// h4/app2        +x-version         => b21 (http)
	// h5/app2        +x-version         => b21
	//
	// h2/            +x-user +x-version => b1
	// h4/            +x-user +x-version => b1 (http)
	// h5/            +x-user +x-version => b1
	//
	// h2/                               => b1
	// h3/                               => b1
	// h4/                               => b1 (http)
	// h5/                               => b1
	//

	// default
	//
	// <default>/app2 +x-version         => b21
	//
	// <default>/     +x-user +x-version => b1
	//
	// <default>/                        => b1
	//

	// varNamespace
	//
	// h5/app2        +x-version         => b21
	//
	// h5/            +x-user +x-version => b1
	//
	// h5/                               => b1
	//

	// sni
	//
	// h4/app2        +x-version         => b21
	//
	// h4/            +x-user +x-version => b1
	//
	// h4/                               => b1
	//

	// redirects
	//
	// h3/app3        +x-version         => /login3
	// h3/app2        +x-version         => /login2
	//
	// h3/            +x-user +x-version => /login1
	//

	b1 = c.config.Backends().AcquireBackend("b1", "app", "8080")
	b21 = c.config.Backends().AcquireBackend("b21", "app", "8080")
	b1.Endpoints = []*hatypes.Endpoint{endpointS1}
	b21.Endpoints = []*hatypes.Endpoint{endpointS21}
	h1 = c.config.Hosts().AcquireHost(hatypes.DefaultHost)
	h2 = c.config.Hosts().AcquireHost("h2.local")
	h2.TLS.TLSFilename = "/var/haproxy/ssl/certs/h2.pem"
	h3 = c.config.hosts.AcquireHost("h3.local")
	h4 = c.config.hosts.AcquireHost("h4.local")
	h4.TLS.TLSFilename = "/var/haproxy/ssl/certs/h4.pem"
	h4.TLS.CAFilename = "/var/haproxy/ssl/cacerts/h4.pem"
	h4.TLS.CAHash = "1"
	h5 = c.config.hosts.AcquireHost("h5.local")
	h5.VarNamespace = true

	h1.AddPath(b1, "/", hatypes.MatchBegin)
	h2.AddPath(b1, "/", hatypes.MatchBegin)
	h3.AddPath(b1, "/", hatypes.MatchBegin)
	h4.AddPath(b1, "/", hatypes.MatchBegin)
	h5.AddPath(b1, "/", hatypes.MatchBegin)

	link1 = hatypes.CreatePathLink("/", hatypes.MatchBegin)
	link1.WithHeadersMatch(hatypes.HTTPHeaderMatch{
		{Name: "x-user", Value: "id"},
		{Name: "x-version", Value: "^[Ss]taging$", Regex: true},
	})
	link2 = hatypes.CreatePathLink("/app2", hatypes.MatchBegin)
	link2.WithHeadersMatch(hatypes.HTTPHeaderMatch{
		{Name: "x-version", Value: "^[Tt]est$", Regex: true},
	})
	link3 = hatypes.CreatePathLink("/app3", hatypes.MatchBegin)
	link3.WithHeadersMatch(hatypes.HTTPHeaderMatch{
		{Name: "x-version", Value: "^[Tt]est$", Regex: true},
	})

	h1.AddLink(b1, link1)
	h1.AddLink(b21, link2)

	h2.AddLink(b1, link1)
	h2.AddLink(b21, link2)

	h3.AddLinkRedirect(link1, "/login1")
	h3.AddLinkRedirect(link2, "/login2")
	h3.AddLinkRedirect(link3, "/login3")

	h4.AddLink(b1, link1)
	h4.AddLink(b21, link2)

	h5.AddLink(b1, link1)
	h5.AddLink(b21, link2)

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend b1_app_8080
    mode http
    acl local-offload ssl_fc
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if local-offload
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if local-offload
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if local-offload
    server s1 172.17.0.11:8080 weight 100
backend b21_app_8080
    mode http
    acl local-offload ssl_fc
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]   if local-offload
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]       if local-offload
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex]   if local-offload
    server s21 172.17.0.121:8080 weight 100
backend default_default-backend_8080
    mode http
    server s0 172.17.0.99:8080 weight 100
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin_01.map) if { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin_02.map) if !{ var(txn.namespace) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map) if !{ var(txn.namespace) -m found }
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<http-headers>>
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin_01.map) if { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin_02.map) if !{ var(req.redirto) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request redirect location %[var(req.redirto)] code 302 if { var(req.redirto) -m found }
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin_01.map) if { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin_02.map) if !{ var(req.backend) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map) if !{ var(req.backend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin_01.map) if !{ var(req.backend) -m found } { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin_02.map) if !{ var(req.backend) -m found } !{ var(req.defaultbackend) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin.map) if !{ var(req.backend) -m found } !{ var(req.defaultbackend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend default_default-backend_8080
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin_01.map) if { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin_02.map) if !{ var(req.redirto) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request redirect location %[var(req.redirto)] code 302 if { var(req.redirto) -m found }
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin_01.map) if { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin_02.map) if !{ var(req.hostbackend) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin_01.map) if !{ var(req.hostbackend) -m found } { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin_02.map) if !{ var(req.hostbackend) -m found } !{ var(req.defaultbackend) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request set-var(req.defaultbackend) str(<default>\#),concat(,req.path),lower,map_beg(/etc/haproxy/maps/_front_defaulthost__begin.map) if !{ var(req.hostbackend) -m found } !{ var(req.defaultbackend) -m found }
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin_01.map) if { hdr(x-user) -- 'id' } { hdr(x-version) -m reg -- '^[Ss]taging$' }
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin_02.map) if !{ var(txn.namespace) -m found } { hdr(x-version) -m reg -- '^[Tt]est$' }
    http-request set-var(txn.namespace) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_namespace__begin.map) if !{ var(txn.namespace) -m found }
    http-request set-var(txn.namespace) str(-) if !{ var(txn.namespace) -m found }
    <<https-headers>>
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-has-invalid-crt ssl_c_verify gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list
    http-request set-var(req.tls_nocrt_redir) str(_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_invalidcrt_redir) str(_internal) if tls-has-invalid-crt tls-check-crt
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-496 if { var(req.tls_nocrt_redir) -m str _internal }
    http-request use-service lua.send-421 if !tls-has-crt tls-host-need-crt
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) -m str _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    use_backend %[var(req.defaultbackend)]
    default_backend default_default-backend_8080
<<support>>
`)

	c.checkMap("_front_redir_to__begin_02.map", `
h3.local#/app3 /login3
h3.local#/app2 /login2
`)
	c.checkMap("_front_redir_to__begin_01.map", `
h3.local#/ /login1
`)
	c.checkMap("_front_http_host__begin_01.map", `
h2.local#/ b1_app_8080
h4.local#/ b1_app_8080
h5.local#/ b1_app_8080
`)
	c.checkMap("_front_http_host__begin_02.map", `
h2.local#/app2 b21_app_8080
h4.local#/app2 b21_app_8080
h5.local#/app2 b21_app_8080
`)
	c.checkMap("_front_http_host__begin.map", `
h2.local#/ b1_app_8080
h3.local#/ b1_app_8080
h4.local#/ b1_app_8080
h5.local#/ b1_app_8080
`)
	c.checkMap("_front_https_host__begin_01.map", `
h2.local#/ b1_app_8080
h4.local#/ b1_app_8080
h5.local#/ b1_app_8080
`)
	c.checkMap("_front_https_host__begin_02.map", `
h2.local#/app2 b21_app_8080
h4.local#/app2 b21_app_8080
h5.local#/app2 b21_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
h2.local#/ b1_app_8080
h3.local#/ b1_app_8080
h4.local#/ b1_app_8080
h5.local#/ b1_app_8080
`)
	c.checkMap("_front_namespace__begin_01.map", `
h2.local#/ -
h3.local#/ -
h4.local#/ -
h5.local#/ b1
`)
	c.checkMap("_front_namespace__begin_02.map", `
h2.local#/app2 -
h3.local#/app3 -
h3.local#/app2 -
h4.local#/app2 -
h5.local#/app2 b21
`)
	c.checkMap("_front_namespace__begin.map", `
h2.local#/ -
h3.local#/ -
h4.local#/ -
h5.local#/ b1
`)
	c.checkMap("_front_defaulthost__begin_01.map", `
<default>#/ b1_app_8080
`)
	c.checkMap("_front_defaulthost__begin_02.map", `
<default>#/app2 b21_app_8080
`)
	c.checkMap("_front_defaulthost__begin.map", `
<default>#/ b1_app_8080
`)

	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem !*
/var/haproxy/ssl/certs/h2.pem h2.local
/var/haproxy/ssl/certs/h4.pem [ca-file /var/haproxy/ssl/cacerts/h4.pem verify optional] h4.local
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceFrontendCA(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().DefaultBackend = def

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d", "app", "8080")
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

	for _, path := range b.Paths {
		path.SSLRedirect = true
	}
	b.TLS.AddCertHeader = true
	b.TLS.FingerprintLower = true
	b.TLS.Sha2Bits = 384
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d_app_8080
    mode http
    acl https-request ssl_fc
    acl local-offload ssl_fc
    http-request redirect scheme https if !https-request
    http-request set-header X-SSL-Client-CN   %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Client-DN   %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-SHA1 %{+Q}[ssl_c_sha1,hex,lower]
    http-request set-header X-SSL-Client-SHA2 %{+Q}[ssl_c_der,sha2(384),hex,lower]
    http-request set-header X-SSL-Client-Cert %{+Q}[ssl_c_der,base64]
    server s1 172.17.0.11:8080 weight 100
backend default_default-backend_8080
    mode http
    server s0 172.17.0.99:8080 weight 100
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    http-request set-var(req.backend) var(req.base),map_reg(/etc/haproxy/maps/_front_http_host__regex.map) if !{ var(req.backend) -m found }
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend default_default-backend_8080
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    <<https-headers>>
    acl tls-has-crt ssl_c_used
    acl tls-need-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-need-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-host-need-crt var(req.host) -i -m str -f /etc/haproxy/maps/_front_tls_needcrt__exact.list
    acl tls-host-need-crt var(req.host) -i -m reg -f /etc/haproxy/maps/_front_tls_needcrt__regex.list
    acl tls-has-invalid-crt ssl_c_verify gt 0
    acl tls-check-crt ssl_fc_sni -i -m str -f /etc/haproxy/maps/_front_tls_auth__exact.list
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list
    http-request set-var(req.tls_nocrt_redir) ssl_fc_sni,lower,map_str(/etc/haproxy/maps/_front_tls_missingcrt_pages__exact.map,_internal) if !tls-has-crt tls-need-crt
    http-request set-var(req.tls_nocrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front_tls_missingcrt_pages__regex.map,_internal) if { var(req.tls_nocrt_redir) -m str _internal }
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_str(/etc/haproxy/maps/_front_tls_invalidcrt_pages__exact.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front_tls_invalidcrt_pages__regex.map,_internal) if { var(req.tls_invalidcrt_redir) -m str _internal }
    http-request redirect location %[var(req.tls_nocrt_redir)] code 303 if { var(req.tls_nocrt_redir) -m found } !{ var(req.tls_nocrt_redir) -m str _internal }
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) -m str _internal }
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-496 if { var(req.tls_nocrt_redir) -m str _internal }
    http-request use-service lua.send-421 if !tls-has-crt tls-host-need-crt
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) -m str _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend default_default-backend_8080
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d2.local#/ d_app_8080
d3.local#/ d_app_8080
d4.local#/ d_app_8080
d5.local#/ d_app_8080
d6.local#/ d_app_8080
`)
	c.checkMap("_front_http_host__regex.map", `
^[^.]+\.d1\.local#/ d_app_8080
`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem !*
/var/haproxy/ssl/certs/default.pem [ca-file /var/haproxy/ssl/ca/d1.local.pem verify optional] *.d1.local
/var/haproxy/ssl/certs/default.pem [ca-file /var/haproxy/ssl/ca/d2.local.pem verify optional crl-file /var/haproxy/ssl/ca/d2.local.crl.pem] d2.local
/var/haproxy/ssl/certs/default.pem [ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384] d3.local
/var/haproxy/ssl/certs/default.pem [ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256] d4.local
/var/haproxy/ssl/certs/default.pem [alpn h2] d5.local
/var/haproxy/ssl/certs/default.pem [ssl-min-ver TLSv1.0 ssl-max-ver TLSv1.2] d6.local
`)
	c.checkMap("_front_https_host__begin.map", `
d2.local#/ d_app_8080
d3.local#/ d_app_8080
d4.local#/ d_app_8080
d5.local#/ d_app_8080
d6.local#/ d_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[^.]+\.d1\.local#/ d_app_8080
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

func TestInstanceFrontendAuth(t *testing.T) {
	type back struct {
		iplist   []string
		port     int
		hostname string
	}
	testCases := []struct {
		backs    []back
		expback  string
		expfront string
	}{
		{
			backs: []back{
				{iplist: []string{"10.0.0.1", "10.0.0.2"}, port: 8080},
			},
			expback: `
backend _auth_backend001_8080
    mode http
    server srv001 10.0.0.1:8080 weight 1
    server srv002 10.0.0.2:8080 weight 1`,
			expfront: `
backend _auth_4001
    mode http
    server _auth_4001 127.0.0.1:4001
frontend _front__auth
    mode http
    bind 127.0.0.1:4001
    use_backend _auth_backend001_8080`,
		},
		{
			backs: []back{
				{iplist: []string{"10.0.0.1", "10.0.0.2"}, port: 8080},
				{iplist: []string{"10.0.0.3"}, port: 8080},
				{iplist: []string{"10.0.0.3"}, port: 8080, hostname: "app1.local"},
			},
			expback: `
backend _auth_backend001_8080
    mode http
    server srv001 10.0.0.1:8080 weight 1
    server srv002 10.0.0.2:8080 weight 1
backend _auth_backend002_8080
    mode http
    server srv001 10.0.0.3:8080 weight 1
backend _auth_backend003_8080
    mode http
    http-request set-header Host app1.local
    server srv001 10.0.0.3:8080 weight 1`,
			expfront: `
backend _auth_4001
    mode http
    server _auth_4001 127.0.0.1:4001
backend _auth_4002
    mode http
    server _auth_4002 127.0.0.1:4002
backend _auth_4003
    mode http
    server _auth_4003 127.0.0.1:4003
frontend _front__auth
    mode http
    bind 127.0.0.1:4001 id 14001
    bind 127.0.0.1:4002 id 14002
    bind 127.0.0.1:4003 id 14003
    use_backend _auth_backend001_8080 if { so_id 14001 }
    use_backend _auth_backend002_8080 if { so_id 14002 }
    use_backend _auth_backend003_8080 if { so_id 14003 }`,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		h.AddPath(b, "/", hatypes.MatchBegin)

		auth := &c.config.Frontend().AuthProxy
		auth.Name = "_front__auth"
		auth.RangeStart = 4001
		auth.RangeEnd = 4010

		for _, back := range test.backs {
			backend := c.config.Backends().AcquireAuthBackend(back.iplist, back.port, back.hostname)
			_, _ = c.config.Frontend().AcquireAuthBackendName(backend.BackendID())
		}

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>` + test.expback + `
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>` + test.expfront + `
<<frontends-default>>
<<support>>
`)

		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceFrontendAuthExternal(t *testing.T) {
	backend1ID := "d_app1_8080"
	allHeaders := []string{"*"}
	testCases := []struct {
		authext   *hatypes.AuthExternal
		expconfig string
		logging   string
	}{
		// 0
		{},
		// 1
		{
			authext: &hatypes.AuthExternal{},
		},
		// 2
		{
			authext: &hatypes.AuthExternal{
				AuthBackendName: backend1ID,
				AuthPath:        "/auth",
				Method:          "GET",
				HeadersFail:     allHeaders,
				HeadersRequest:  allHeaders,
				HeadersSucceed:  allHeaders,
			},
			expconfig: `
    http-request lua.auth-intercept d_app1_8080 /auth GET '*' '*' '*' if { var(req.base) -m str beg 'd.local#/' }
    http-request deny if !{ var(txn.auth_response_successful) -m bool } { var(req.base) -m str beg 'd.local#/' }`,
		},
		// 3
		{
			authext: &hatypes.AuthExternal{
				AuthBackendName: backend1ID,
				AuthPath:        "/auth",
				Method:          "POST",
				HeadersFail:     []string{"X-Reason"},
				HeadersRequest:  allHeaders,
				HeadersSucceed:  allHeaders,
				HeadersVars:     map[string]string{"X-UserID": "req.auth_response_header.x_user_id"},
			},
			expconfig: `
    http-request lua.auth-intercept d_app1_8080 /auth POST '*' '*' 'X-Reason' if { var(req.base) -m str beg 'd.local#/' }
    http-request deny if !{ var(txn.auth_response_successful) -m bool } { var(req.base) -m str beg 'd.local#/' }
    http-request set-header X-UserID %[var(req.auth_response_header.x_user_id)] if { var(req.auth_response_header.x_user_id) -m found } { var(req.base) -m str beg 'd.local#/' }`,
		},
		// 4
		{
			authext: &hatypes.AuthExternal{
				AuthBackendName: backend1ID,
				AuthPath:        "/auth",
				Method:          "POST",
				HeadersFail:     allHeaders,
				HeadersRequest:  []string{"X-UserID", "X-GroupID"},
				HeadersSucceed:  allHeaders,
				RedirectOnFail:  "/login",
			},
			expconfig: `
    http-request lua.auth-intercept d_app1_8080 /auth POST 'X-UserID,X-GroupID' '*' '*' if { var(req.base) -m str beg 'd.local#/' }
    http-request redirect location /login if !{ var(txn.auth_response_successful) -m bool } { var(req.base) -m str beg 'd.local#/' }`,
		},
		// 5
		{
			authext: &hatypes.AuthExternal{
				AuthBackendName: backend1ID,
				AuthPath:        "/login",
				Method:          "POST",
				HeadersFail:     allHeaders,
				HeadersRequest:  allHeaders,
				HeadersSucceed:  []string{"X-Region", "X-Tenant"},
				RedirectOnFail:  "/login",
				AllowedPath:     "/login",
			},
			expconfig: `
    http-request lua.auth-intercept d_app1_8080 /login POST '*' 'X-Region,X-Tenant' '*' if !{ path_beg /login } { var(req.base) -m str beg 'd.local#/' }
    http-request redirect location /login if !{ var(txn.auth_response_successful) -m bool } !{ path_beg /login } { var(req.base) -m str beg 'd.local#/' }`,
		},
		// 6
		{
			authext: &hatypes.AuthExternal{
				AlwaysDeny: true,
			},
			expconfig: `
    http-request deny if { var(req.base) -m str beg 'd.local#/' }`,
		},
	}

	for _, test := range testCases {
		c := setup(t)
		defer c.teardown()

		h := c.config.Hosts().AcquireHost("d.local")
		b := c.config.Backends().AcquireBackend("d", "app1", "8080")

		path := h.AddPath(b, "/", hatypes.MatchBegin)
		path.AuthExt = test.authext

		c.Update()
		c.checkConfig(`
<<global>>
<<defaults>>
backend d_app1_8080
    mode http
backend _error404
    mode http
    http-request use-service lua.send-404
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>` + test.expconfig + `
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>` + test.expconfig + `
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
		if test.logging == "" {
			test.logging = defaultLogging
		}
		c.logger.CompareLogging(test.logging)
	}
}

func TestInstanceSomePaths(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	def := c.config.Backends().AcquireBackend("default", "default-backend", "8080")
	def.Endpoints = []*hatypes.Endpoint{endpointS0}
	c.config.Backends().DefaultBackend = def

	var h *hatypes.Host
	var b *hatypes.Backend

	b = c.config.Backends().AcquireBackend("d", "app0", "8080")
	h = c.config.Hosts().AcquireHost("d.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.FindBackendPath(h.FindPath("/")[0].Link).SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d", "app1", "8080")
	h.AddPath(b, "/app", hatypes.MatchBegin)
	b.FindBackendPath(h.FindPath("/app")[0].Link).SSLRedirect = true
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
    acl https-request ssl_fc
    http-request redirect scheme https if !https-request
    server s1 172.17.0.11:8080 weight 100
backend d_app1_8080
    mode http
    acl https-request ssl_fc
    http-request redirect scheme https if !https-request
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
backend default_default-backend_8080
    mode http
    server s0 172.17.0.99:8080 weight 100
<<frontend-http>>
    default_backend default_default-backend_8080
<<frontend-https>>
    default_backend default_default-backend_8080
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d.local#/sub d_app3_8080
d.local#/app/sub d_app2_8080
d.local#/app d_app1_8080
d.local#/ d_app0_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d.local#/sub d_app3_8080
d.local#/app/sub d_app2_8080
d.local#/app d_app1_8080
d.local#/ d_app0_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceCustomFrontend(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	c.config.Global().CustomFrontendEarly = []string{
		"# dummy tcp-request",
		"tcp-request connection accept",
	}
	c.config.Global().CustomFrontendLate = []string{
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
    # dummy tcp-request
    tcp-request connection accept
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    # new header
    http-response set-header X-Server HAProxy
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    # dummy tcp-request
    tcp-request connection accept
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert
    # new header
    http-response set-header X-Server HAProxy
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceCustomSections(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	c.config.Global().CustomSections = []string{
		"cache icons",
		"	total-max-size 4",
		"	max-age 240",
	}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
cache icons
	total-max-size 4
	max-age 240
backend d1_app_8080
    mode http
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceCustomTCP(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	tcp := c.config.TCPBackends().Acquire("default_postgresql", 5432)
	tcp.AddEndpoint("172.17.0.11", 5432)

	c.config.global.CustomTCP = []string{"## custom for TCP", "## multi line"}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
listen _tcp_default_postgresql_5432
    bind :5432
    mode tcp
    ## custom for TCP
    ## multi line
    server srv001 172.17.0.11:5432
<<backends-default>>
<<frontend-http-clean>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
<<support>>
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceCustomProxy(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.SetSSLPassthrough(true)

	var h2 *hatypes.Host
	var b2 = c.config.Backends().AcquireBackend("d2", "app", "8080")
	b2.Endpoints = []*hatypes.Endpoint{endpointS21}
	b2.ModeTCP = true
	h2 = c.config.Hosts().AcquireHost("d2.local")
	h2.AddPath(b, "/", hatypes.MatchBegin)
	h2.SetSSLPassthrough(true)

	auth := &c.config.Frontend().AuthProxy
	auth.Name = "_front__auth"
	auth.RangeStart = 4001
	auth.RangeEnd = 4010
	authBackend := c.config.Backends().AcquireAuthBackend([]string{"172.17.100.11"}, 5000, "")
	_, _ = c.config.Frontend().AcquireAuthBackendName(authBackend.BackendID())

	tcp := c.config.tcpbackends.Acquire("default_pgsql", 5432)
	tcp.AddEndpoint("172.17.0.21", 5432)

	_, tcpHost := c.config.tcpservices.AcquireTCPService(hatypes.DefaultHost + ":7001")
	tcpHost.Backend = b.BackendID()

	c.config.Global().CustomProxy = map[string][]string{
		"missing":                 {"## comment"},
		"_tcp_default_pgsql_5432": {"## custom for _tcp_default_pgsql_5432"},
		"_auth_backend001_5000":   {"## custom for _auth_backend001_5000"},
		"d1_app_8080":             {"## custom for d1_app_8080"},
		"d2_app_8080":             {"## custom for d2_app_8080"},
		"_redirect_https":         {"## custom for _redirect_https"},
		"_error404":               {"## custom for _error404", "## line 2"},
		"_auth_4001":              {"## custom for _auth_4001"},
		"_front__auth":            {"## custom for _front__auth"},
		"_front_tcp_7001":         {"## custom for _front_tcp_7001"},
		"_front__tls":             {"## custom for _front__tls"},
		"_front_http":             {"## custom for _front_http"},
		"_front_https__local":     {"## custom for _front_https__local"},
		"stats":                   {"## custom for stats"},
		"healthz":                 {"## custom for healthz"},
	}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
listen _tcp_default_pgsql_5432
    bind :5432
    mode tcp
    ## custom for _tcp_default_pgsql_5432
    server srv001 172.17.0.21:5432
backend _auth_backend001_5000
    mode http
    ## custom for _auth_backend001_5000
    server srv001 172.17.100.11:5000 weight 1
backend d1_app_8080
    mode http
    ## custom for d1_app_8080
    server s1 172.17.0.11:8080 weight 100
backend d2_app_8080
    mode tcp
    ## custom for d2_app_8080
    server s21 172.17.0.121:8080 weight 100
backend _redirect_https
    mode http
    ## custom for _redirect_https
    http-request redirect scheme https
backend _error404
    mode http
    ## custom for _error404
    ## line 2
    http-request use-service lua.send-404
backend _auth_4001
    mode http
    ## custom for _auth_4001
    server _auth_4001 127.0.0.1:4001
frontend _front__auth
    mode http
    bind 127.0.0.1:4001
    ## custom for _front__auth
    use_backend _auth_backend001_5000
frontend _front_tcp_7001
    bind :7001
    mode tcp
    ## custom for _front_tcp_7001
    default_backend d1_app_8080
listen _front__tls
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content set-var(req.sslpassback) req.ssl_sni,lower,map_str(/etc/haproxy/maps/_front_sslpassthrough__exact.map)
    ## custom for _front__tls
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend %[var(req.sslpassback)] if { var(req.sslpassback) -m found }
    server _default_server_https_socket unix@/var/run/haproxy/_https_socket.sock send-proxy-v2
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    ## custom for _front_http
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https__local
    mode http
    bind unix@/var/run/haproxy/_https_socket.sock accept-proxy ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    <<https-headers>>
    ## custom for _front_https__local
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
listen stats
    mode http
    bind :1936
    stats enable
    stats uri /
    no log
    option httpclose
    stats show-legends
    ## custom for stats
frontend healthz
    mode http
    bind :10253
    monitor-uri /healthz
    http-request use-service lua.send-404
    no log
    ## custom for healthz
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestCustomResponseLua(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.global.CustomHTTPLuaResponses = []hatypes.HTTPResponse{
		{
			Name: "send-404",
			Headers: []hatypes.HTTPHeader{
				{Name: "content-length", Value: "25"},
				{Name: "server", Value: "haproxy"},
			},
			Body:         []string{"<p>", "  404 Not Found", "</p>"},
			StatusCode:   404,
			StatusReason: "Not Found",
		},
		{
			Name: "send-496",
			Headers: []hatypes.HTTPHeader{
				{Name: "content-length", Value: "40"},
				{Name: "server", Value: "haproxy"},
			},
			Body:         []string{"<p>", "  496 SSL Certificate Required", "</p>"},
			StatusCode:   496,
			StatusReason: "SSL Certificate Required",
		},
	}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
<<backends-default>>
<<frontend-http-clean>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
<<support>>
`)

	c.compareText("responses.lua", c.readConfig(c.tempdir+"/responses.lua"), `
core.register_service("send-404", "http", function(applet)
    response = [==[
<p>
  404 Not Found
</p>
]==]
    applet:set_status(404, "Not Found")
    applet:add_header("content-length", "25")
    applet:add_header("server", "haproxy")
    applet:start_response()
    applet:send(response)
end)
core.register_service("send-496", "http", function(applet)
    response = [==[
<p>
  496 SSL Certificate Required
</p>
]==]
    applet:set_status(496, "SSL Certificate Required")
    applet:add_header("content-length", "40")
    applet:add_header("server", "haproxy")
    applet:start_response()
    applet:send(response)
end)
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestCustomResponseHAProxy(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.global.CustomHTTPHAResponses = []hatypes.HTTPResponse{
		{
			Name: "403",
			Headers: []hatypes.HTTPHeader{
				{Name: "content-length", Value: "25"},
				{Name: "server", Value: "haproxy"},
			},
			Body:         []string{"<p>", "  403 Forbidden", "</p>"},
			StatusCode:   403,
			StatusReason: "Forbidden",
		},
		{
			Name: "503",
			Headers: []hatypes.HTTPHeader{
				{Name: "content-length", Value: "35"},
				{Name: "server", Value: "haproxy"},
			},
			Body:         []string{"<p>", "  503 Service Unavailable", "</p>"},
			StatusCode:   503,
			StatusReason: "Service Unavailable",
		},
		{
			Name: "504",
			Headers: []hatypes.HTTPHeader{
				{Name: "content-length", Value: "0"},
				{Name: "location", Value: "https://other.local"},
			},
			StatusCode:   302,
			StatusReason: "Found",
		},
	}

	c.Update()
	c.checkConfig(`
<<global>>
defaults
    log global
    maxconn 2000
    option redispatch
    option dontlognull
    option http-server-close
    option http-keep-alive
    errorfile 403 /etc/haproxy/errorfiles/403.http
    errorfile 503 /etc/haproxy/errorfiles/503.http
    errorfile 504 /etc/haproxy/errorfiles/504.http
    timeout client          50s
    timeout client-fin      50s
    timeout connect         5s
    timeout http-keep-alive 1m
    timeout http-request    5s
    timeout queue           5s
    timeout server          50s
    timeout server-fin      50s
    timeout tunnel          1h
<<backends-default>>
<<frontend-http-clean>>
    default_backend _error404
<<frontend-https-clean>>
    default_backend _error404
<<support>>
`)

	c.compareRawText("haproxy-403.http", c.readRawConfig(c.tempdir+"/errorfiles/403.http"),
		`HTTP/1.1 403 Forbidden
content-length: 25
server: haproxy

<p>
  403 Forbidden
</p>
`)
	c.compareRawText("haproxy-503.http", c.readRawConfig(c.tempdir+"/errorfiles/503.http"),
		`HTTP/1.1 503 Service Unavailable
content-length: 35
server: haproxy

<p>
  503 Service Unavailable
</p>
`)
	c.compareRawText("haproxy-504.http", c.readRawConfig(c.tempdir+"/errorfiles/504.http"),
		`HTTP/1.1 302 Found
content-length: 0
location: https://other.local

`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceSSLPassthrough(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.FindBackendPath(h.FindPath("/")[0].Link).SSLRedirect = true
	b.Endpoints = []*hatypes.Endpoint{endpointS31}
	// TODO should ingress converter configure mode tcp?
	b.ModeTCP = true
	h.SetSSLPassthrough(true)

	b = c.config.Backends().AcquireBackend("d3", "app-ssl", "8443")
	h = c.config.Hosts().AcquireHost("d3.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.Endpoints = []*hatypes.Endpoint{endpointS41s}
	b.ModeTCP = true
	h.SetSSLPassthrough(true)

	b = c.config.Backends().AcquireBackend("d3", "app1-http", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS41h}
	h.HTTPPassthroughBackend = b.ID

	b = c.config.Backends().AcquireBackend("d3", "app2-http", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS41h}
	h.AddPath(b, "/app", hatypes.MatchBegin)

	b = c.config.Backends().AcquireBackend("d4", "app4-ssl", "8443")
	h = c.config.Hosts().AcquireHost(hatypes.DefaultHost)
	h.AddPath(b, "/", hatypes.MatchBegin)
	b.Endpoints = []*hatypes.Endpoint{endpointS41s}
	b.ModeTCP = true
	h.SetSSLPassthrough(true)

	b = c.config.Backends().AcquireBackend("d4", "app4-http", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS41h}
	h.HTTPPassthroughBackend = b.ID

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d2_app_8080
    mode tcp
    server s31 172.17.0.131:8080 weight 100
backend d3_app-ssl_8443
    mode tcp
    server s41s 172.17.0.141:8443 weight 100
backend d3_app1-http_8080
    mode http
    server s41h 172.17.0.141:8080 weight 100
backend d3_app2-http_8080
    mode http
    server s41h 172.17.0.141:8080 weight 100
backend d4_app4-http_8080
    mode http
    server s41h 172.17.0.141:8080 weight 100
backend d4_app4-ssl_8443
    mode tcp
    server s41s 172.17.0.141:8443 weight 100
backend _redirect_https
    mode http
    http-request redirect scheme https
<<backends-default>>
listen _front__tls
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content set-var(req.sslpassback) req.ssl_sni,lower,map_str(/etc/haproxy/maps/_front_sslpassthrough__exact.map)
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend %[var(req.sslpassback)] if { var(req.sslpassback) -m found }
    use_backend d4_app4-ssl_8443
    server _default_server_https_socket unix@/var/run/haproxy/_https_socket.sock send-proxy-v2
<<frontend-http>>
    use_backend d4_app4-http_8080
    default_backend _error404
frontend _front_https__local
    mode http
    bind unix@/var/run/haproxy/_https_socket.sock accept-proxy ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_sslpassthrough__exact.map", `
d2.local d2_app_8080
d3.local d3_app-ssl_8443
`)
	c.checkMap("_front_http_host__begin.map", `
d2.local#/ _redirect_https
d3.local#/app d3_app2-http_8080
d3.local#/ d3_app1-http_8080
`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem !*
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceRootRedirect(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.config.global.SSL.SSLRedirect = true

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	h = c.config.Hosts().AcquireHost("*.d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.RootRedirect = "/app"
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("d2.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/app1", hatypes.MatchBegin)
	h.AddPath(b, "/app2", hatypes.MatchBegin)
	h.RootRedirect = "/app1"
	for _, path := range b.Paths {
		path.SSLRedirect = true
	}
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
    acl https-request ssl_fc
    http-request redirect scheme https if !https-request
    server s21 172.17.0.121:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    http-request redirect scheme https if { path / } { var(req.host) -i -m str -f /etc/haproxy/maps/_front_redir_root_ssl__exact.map }
    http-request set-var(req.rootredir) var(req.host),map_str(/etc/haproxy/maps/_front_redir_fromroot__exact.map)
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map) if !{ var(req.rootredir) -m found }
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
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
    http-request set-var(req.rootredir) var(req.host),map_str(/etc/haproxy/maps/_front_redir_fromroot__exact.map)
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map) if !{ var(req.rootredir) -m found }
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_http_host__regex.map", `
^[^.]+\.d1\.local#/ d1_app_8080
`)
	c.checkMap("_front_http_host__begin.map", `
d2.local#/app2 d2_app_8080
d2.local#/app1 d2_app_8080
`)
	c.checkMap("_front_http_host__regex.map", `
^[^.]+\.d1\.local#/ d1_app_8080
`)
	c.checkMap("_front_redir_fromroot__exact.map", `
d2.local /app1
`)
	c.checkMap("_front_redir_root_ssl__exact.map", `
d2.local
`)
	c.checkMap("_front_redir_fromroot__regex.map", `
^[^.]+\.d1\.local$ /app
`)
	c.checkMap("_front_https_host__begin.map", `
d2.local#/app2 d2_app_8080
d2.local#/app1 d2_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[^.]+\.d1\.local#/ d1_app_8080
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceAlias(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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
    <<set-req-base>>
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

	c.checkMap("_front_http_host__begin.map", `
d1.local#/ d1_app_8080
d2.local#/ d2_app_8080
d3.local#/ d3_app_8080
sub.d2.local#/ d2_app_8080
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local#/ d1_app_8080
d2.local#/ d2_app_8080
d3.local#/ d3_app_8080
sub.d2.local#/ d2_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[a-z]+\.d2\.local#/ d2_app_8080
^[^.]+\.d1\.local#/ d1_app_8080
d3\.local#/ d3_app_8080
`)
	c.logger.CompareLogging(defaultLogging)
}

func TestInstanceRedirectFrom(t *testing.T) {
	testCases := []struct {
		data     [3]hatypes.HostRedirectConfig
		code     int
		noredirs []string
		expHTTP  string
		expHTTPS string
		expMaps  map[string]string
	}{
		// 0
		{
			data: [3]hatypes.HostRedirectConfig{
				{RedirectHost: "*.d1.local"},
			},
			code: 301,
			expHTTP: `
    http-request set-var(req.redirdest) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_from__regex.map) if !{ var(req.backend) -m found }
    http-request redirect prefix //%[var(req.redirdest)] code 301 if { var(req.redirdest) -m found }`,
			expHTTPS: `
    http-request set-var(req.redirdest) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_from__regex.map) if !{ var(req.hostbackend) -m found }
    http-request redirect prefix //%[var(req.redirdest)] code 301 if { var(req.redirdest) -m found }`,
			expMaps: map[string]string{
				"_front_redir_from__regex.map": `
^[^.]+\.d1\.local$ d1.local
`,
			},
		},
		// 1
		{
			data: [3]hatypes.HostRedirectConfig{
				{RedirectHost: "*.d1.local"},
				{RedirectHost: "sub.d2.local", RedirectHostRegex: "^[a-z]+\\.d2\\.local$"},
				{RedirectHostRegex: "\\.d3\\.local$"},
			},
			expHTTP: `
    http-request set-var(req.redirdest) var(req.host),map_str(/etc/haproxy/maps/_front_redir_from__exact.map) if !{ var(req.backend) -m found }
    http-request set-var(req.redirdest) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_from__regex.map) if !{ var(req.backend) -m found } !{ var(req.redirdest) -m found }
    http-request redirect prefix //%[var(req.redirdest)] code 302 if { var(req.redirdest) -m found }`,
			expHTTPS: `
    http-request set-var(req.redirdest) var(req.host),map_str(/etc/haproxy/maps/_front_redir_from__exact.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.redirdest) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_from__regex.map) if !{ var(req.hostbackend) -m found } !{ var(req.redirdest) -m found }
    http-request redirect prefix //%[var(req.redirdest)] code 302 if { var(req.redirdest) -m found }`,
			expMaps: map[string]string{
				"_front_redir_from__exact.map": `
sub.d2.local d2.local
`,
				"_front_redir_from__regex.map": `
^[a-z]+\.d2\.local$ d2.local
^[^.]+\.d1\.local$ d1.local
\.d3\.local$ d3.local
`,
			},
		},
		// 2
		{
			data: [3]hatypes.HostRedirectConfig{
				{RedirectHost: "*.d1.local"},
			},
			code:     301,
			noredirs: []string{"/.well-known/acme-challenge"},
			expHTTP: `
    http-request set-var(req.redirdest) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_from__regex.map) if !{ path_beg "/.well-known/acme-challenge" } !{ var(req.backend) -m found }
    http-request redirect prefix //%[var(req.redirdest)] code 301 if !{ path_beg "/.well-known/acme-challenge" } { var(req.redirdest) -m found }`,
			expHTTPS: `
    http-request set-var(req.redirdest) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_from__regex.map) if !{ path_beg "/.well-known/acme-challenge" } !{ var(req.hostbackend) -m found }
    http-request redirect prefix //%[var(req.redirdest)] code 301 if !{ path_beg "/.well-known/acme-challenge" } { var(req.redirdest) -m found }`,
			expMaps: map[string]string{
				"_front_redir_from__regex.map": `
^[^.]+\.d1\.local$ d1.local
`,
			},
		},
	}

	for _, test := range testCases {
		c := setup(t)
		defer c.teardown()

		c.config.global.NoRedirects = test.noredirs

		var h *hatypes.Host
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		h.AddPath(b, "/", hatypes.MatchBegin)
		h.Redirect = test.data[0]

		b = c.config.Backends().AcquireBackend("d2", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS21}
		h = c.config.Hosts().AcquireHost("d2.local")
		h.AddPath(b, "/", hatypes.MatchBegin)
		h.Redirect = test.data[1]

		b = c.config.Backends().AcquireBackend("d3", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS31}
		h = c.config.Hosts().AcquireHost("d3.local")
		h.AddPath(b, "/", hatypes.MatchBegin)
		h.Redirect = test.data[2]

		if test.code != 0 {
			c.config.frontend.RedirectFromCode = test.code
		} else {
			c.config.frontend.RedirectFromCode = 302
		}

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
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)
    http-request set-header X-Forwarded-Proto http
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)` + test.expHTTP + `
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)` + test.expHTTPS + `
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
		for file, content := range test.expMaps {
			c.checkMap(file, content)
		}
		c.logger.CompareLogging(defaultLogging)
	}
}

func TestInstanceRedirectTo(t *testing.T) {
	testCases := []struct {
		to       [3]string
		code     int
		noredirs []string
		expected string
		expMaps  map[string]string
	}{
		// 0
		{
			to: [3]string{
				"https://app.local",
			},
			expected: `
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin.map)
    http-request redirect location %[var(req.redirto)] code 302 if { var(req.redirto) -m found }`,
			expMaps: map[string]string{
				"_front_redir_to__begin.map": `
d1.local#/ https://app.local
`,
			},
		},
		// 1
		{
			to: [3]string{
				"https://app.local/login",
				"https://app.local/app2",
			},
			expected: `
    http-request set-var(req.redirto) var(req.base),map_dir(/etc/haproxy/maps/_front_redir_to__prefix_01.map)
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin.map) if !{ var(req.redirto) -m found }
    http-request redirect location %[var(req.redirto)] code 302 if { var(req.redirto) -m found }`,
			expMaps: map[string]string{
				"_front_redir_to__prefix_01.map": `
d1.local#/app2 https://app.local/app2
`,
				"_front_redir_to__begin.map": `
d1.local#/ https://app.local/login
`,
			},
		},
		// 2
		{
			to: [3]string{
				"",
				"https://app.local/app2",
				"https://app.local/app3",
			},
			expected: `
    http-request set-var(req.redirto) var(req.base),map_dir(/etc/haproxy/maps/_front_redir_to__prefix.map)
    http-request redirect location %[var(req.redirto)] code 302 if { var(req.redirto) -m found }`,
			expMaps: map[string]string{
				"_front_redir_to__prefix.map": `
d1.local#/app3 https://app.local/app3
d1.local#/app2 https://app.local/app2
`,
			},
		},
		// 3
		{
			to: [3]string{
				"https://app.local",
			},
			noredirs: []string{"/.well-known/acme-challenge"},
			expected: `
    http-request set-var(req.redirto) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_redir_to__begin.map) if !{ path_beg "/.well-known/acme-challenge" }
    http-request redirect location %[var(req.redirto)] code 302 if !{ path_beg "/.well-known/acme-challenge" } { var(req.redirto) -m found }`,
			expMaps: map[string]string{
				"_front_redir_to__begin.map": `
d1.local#/ https://app.local
`,
			},
		},
	}

	for _, test := range testCases {
		c := setup(t)
		defer c.teardown()

		c.config.global.NoRedirects = test.noredirs

		var h = c.config.Hosts().AcquireHost("d1.local")
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		if test.to[0] != "" {
			h.AddRedirect("/", hatypes.MatchBegin, test.to[0])
		} else {
			h.AddPath(b, "/", hatypes.MatchBegin)
		}

		b = c.config.Backends().AcquireBackend("d2", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS21}
		if test.to[1] != "" {
			h.AddRedirect("/app2", hatypes.MatchPrefix, test.to[1])
		} else {
			h.AddPath(b, "/app2", hatypes.MatchBegin)
		}

		b = c.config.Backends().AcquireBackend("d3", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS31}
		if test.to[2] != "" {
			h.AddRedirect("/app3", hatypes.MatchPrefix, test.to[2])
		} else {
			h.AddPath(b, "/app3", hatypes.MatchBegin)
		}

		if test.code != 0 {
			c.config.frontend.RedirectToCode = test.code
		} else {
			c.config.frontend.RedirectToCode = 302
		}

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
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)
    http-request set-header X-Forwarded-Proto http
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert` + test.expected + `
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    http-request set-var(req.path) path
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)` + test.expected + `
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    default_backend _error404
<<support>>
`)
		for file, content := range test.expMaps {
			c.checkMap(file, content)
		}
		c.logger.CompareLogging(defaultLogging)
	}
}

func TestInstanceSyslog(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host
	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}
	h = c.config.Hosts().AcquireHost("d1.local")
	h.AddPath(b, "/", hatypes.MatchBegin)

	tcpPort1, tcpHost1 := c.config.tcpservices.AcquireTCPService("<default>:7001")
	tcpPort1.LogFormat = "default"
	tcpHost1.Backend = b.BackendID()

	tcpPort2, tcpHost2 := c.config.tcpservices.AcquireTCPService("<default>:7002")
	tcpPort2.LogFormat = "%[src]"
	tcpHost2.Backend = b.BackendID()

	syslog := &c.config.Global().Syslog
	syslog.Endpoint = "127.0.0.1:1514"
	syslog.Format = "rfc3164"
	syslog.Length = 2048
	syslog.Tag = "ingress"

	c.Update()
	c.checkConfig(`
global
    daemon
    unix-bind mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    log 127.0.0.1:1514 len 2048 format rfc3164 local0
    log-tag ingress
    lua-prepend-path /etc/haproxy/lua/?.lua
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    lua-load /etc/haproxy/lua/responses.lua
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
frontend _front_tcp_7001
    bind :7001
    mode tcp
    option tcplog
    default_backend d1_app_8080
frontend _front_tcp_7002
    bind :7002
    mode tcp
    log-format %[src]
    default_backend d1_app_8080
frontend _front_http
    mode http
    bind :80
    option httplog
    <<set-req-base>>
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

	b = c.config.Backends().AcquireBackend("d3", "app", "http")
	b.DNSPort = "named"
	b.Endpoints = []*hatypes.Endpoint{endpointS21, endpointS22}
	b.Resolver = "k8s"
	h = c.config.Hosts().AcquireHost("d3.local")
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
backend d3_app_http
    mode http
    server-template srv 2 _named._tcp.app.d3.svc.cluster.local resolvers k8s resolve-prefer ipv4 init-addr none weight 1
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
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		h.AddPath(b, "/", hatypes.MatchBegin)
		h.AddPath(b, "/admin", hatypes.MatchBegin)

		for _, list := range test.lists {
			c.config.Userlists().Replace(list.name, list.users)
		}
		b.FindBackendPath(h.FindPath("/admin")[0].Link).AuthHTTP = hatypes.AuthHTTP{
			UserlistName: test.listname,
			Realm:        test.realm,
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
    http-request auth` + realm + ` if { var(txn.pathID) -m str path02 } !{ http_auth(` + test.listname + `) }
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
    <<set-req-base>>
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
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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

// TestModSecurity ensures that ModSecurity-related config eventually lands in the templated HAProxy config files
func TestModSecurity(t *testing.T) {
	testCases := []struct {
		waf             string
		wafmode         string
		path            string
		endpoints       []string
		backendExp      string
		modsecExp       string
		modsecAgentArgs []string
		modsecAgentExp  string
		modsecUseCoraza bool
		modsecOtherExp  string
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
    http-request deny if { var(txn.modsec.code) -m int gt 0 } { var(txn.pathID) -m str path01 }`,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345`,
		},
		// Test setting custom args
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
			modsecOtherExp: `
    messages     check-request
    option       var-prefix  modsec`,

			modsecAgentArgs: []string{"unique-id", "method", "path", "query", "req.ver", "req.hdrs_bin"},
			modsecAgentExp: `
spoe-message check-request
    args   unique-id method path query req.ver req.hdrs_bin
    event  on-backend-http-request`,
		},
		// Test modsecurity-use-coraza
		{
			waf:       "modsecurity",
			wafmode:   "deny",
			endpoints: []string{"10.0.0.101:12345"},
			backendExp: `
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request redirect code 302 location %[var(txn.coraza.data)] if { var(txn.coraza.action) -m str redirect }
    http-response redirect code 302 location %[var(txn.coraza.data)] if { var(txn.coraza.action) -m str redirect }
    http-request deny deny_status 403 hdr waf-block "request"  if { var(txn.coraza.action) -m str deny }
    http-response deny deny_status 403 hdr waf-block "response" if { var(txn.coraza.action) -m str deny }
    http-request silent-drop if { var(txn.coraza.action) -m str drop }
    http-response silent-drop if { var(txn.coraza.action) -m str drop }
    http-request deny deny_status 504 if { var(txn.coraza.error) -m int gt 0 }
    http-response deny deny_status 504 if { var(txn.coraza.error) -m int gt 0 }`,
			modsecExp: `
    timeout connect 1s
    timeout server  2s
    server modsec-spoa0 10.0.0.101:12345`,
			modsecAgentArgs: []string{"app=hdr(host)", "id=unique-id", "src-ip=src", "src-port=src_port", "dst-ip=dst", "dst-port=dst_port", "method=method", "path=path", "query=query", "version=req.ver", "headers=req.hdrs", "body=req.body"},
			modsecAgentExp: `
spoe-message coraza-req
    args   app=hdr(host) id=unique-id src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body
    event  on-backend-http-request`,
			modsecOtherExp: `
    messages     coraza-req
    option       var-prefix  coraza`,
			modsecUseCoraza: true,
		},
	}
	for _, test := range testCases {
		c := setup(t)

		var h *hatypes.Host
		var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
		b.Endpoints = []*hatypes.Endpoint{endpointS1}
		h = c.config.Hosts().AcquireHost("d1.local")
		if test.path == "" {
			test.path = "/"
		}
		h.AddPath(b, test.path, hatypes.MatchBegin)
		b.FindBackendPath(h.FindPath(test.path)[0].Link).WAF = hatypes.WAF{
			Module: test.waf,
			Mode:   test.wafmode,
		}
		if test.path != "/" {
			h.AddPath(b, "/", hatypes.MatchBegin)
		}

		globalModsec := &c.config.Global().ModSecurity
		globalModsec.Endpoints = test.endpoints
		globalModsec.Timeout.Connect = "1s"
		globalModsec.Timeout.Server = "2s"
		globalModsec.Args = test.modsecAgentArgs
		globalModsec.UseCoraza = test.modsecUseCoraza
		c.Update()

		var modsec string
		if test.modsecExp != "" {
			modsec = `
backend spoe-modsecurity
    mode tcp` + test.modsecExp
		}
		// unique-id-format must be set when using Coraza
		if test.modsecUseCoraza {
			c.checkConfig(`
<<global>>
<<defaults>>
    unique-id-format        %[uuid()]
backend d1_app_8080
    mode http` + test.backendExp + `
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>` + modsec)
		} else {
			c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http` + test.backendExp + `
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
<<frontends-default>>
<<support>>` + modsec)
		}
		if test.modsecAgentExp != "" {
			c.containsText("spoe-modsecurity.conf", c.readConfig(c.tempdir+"/spoe-modsecurity.conf"), test.modsecAgentExp)
		}
		if test.modsecOtherExp != "" {
			c.containsText("spoe-modsecurity.conf", c.readConfig(c.tempdir+"/spoe-modsecurity.conf"), test.modsecOtherExp)
		}

		c.logger.CompareLogging(defaultLogging)
		c.teardown()
	}
}

func TestInstanceWildcardHostname(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host

	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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
	h.TLS.CAVerify = hatypes.CAVerifyOptional
	h.TLS.CAErrorPage = "http://sub.d1.local/error.html"
	for _, path := range b.Paths {
		path.SSLRedirect = true
	}
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	b = c.config.Backends().AcquireBackend("d2", "app", "8080")
	h = c.config.Hosts().AcquireHost("*.d2.local")
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.RootRedirect = "/app"
	b.Endpoints = []*hatypes.Endpoint{endpointS21}

	c.Update()
	c.checkConfig(`
<<global>>
<<defaults>>
backend d1_app_8080
    mode http
    acl https-request ssl_fc
    acl local-offload ssl_fc
    http-request redirect scheme https if !https-request
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
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map)
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
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
    http-request set-var(req.rootredir) var(req.host),map_reg(/etc/haproxy/maps/_front_redir_fromroot__regex.map)
    http-request redirect location %[var(req.rootredir)] if { path / } { var(req.rootredir) -m found }
    <<https-headers>>
    acl tls-has-crt ssl_c_used
    acl tls-has-invalid-crt ssl_c_verify gt 0
    acl tls-check-crt ssl_fc_sni -i -m reg -f /etc/haproxy/maps/_front_tls_auth__regex.list
    http-request set-var(req.tls_invalidcrt_redir) ssl_fc_sni,lower,map_reg(/etc/haproxy/maps/_front_tls_invalidcrt_pages__regex.map,_internal) if tls-has-invalid-crt tls-check-crt
    http-request redirect location %[var(req.tls_invalidcrt_redir)] code 303 if { var(req.tls_invalidcrt_redir) -m found } !{ var(req.tls_invalidcrt_redir) -m str _internal }
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    http-request use-service lua.send-495 if { var(req.tls_invalidcrt_redir) -m str _internal }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d1.local#/ d1_app_8080
`)
	c.checkMap("_front_http_host__regex.map", `
^[^.]+\.app\.d1\.local#/ d1_app_8080
^[^.]+\.sub\.d1\.local#/ d1_app_8080
^[^.]+\.d2\.local#/ d2_app_8080
`)
	c.checkMap("_front_redir_fromroot__regex.map", `
^[^.]+\.d2\.local$ /app
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local#/ d1_app_8080
`)
	c.checkMap("_front_https_host__regex.map", `
^[^.]+\.app\.d1\.local#/ d1_app_8080
^[^.]+\.sub\.d1\.local#/ d1_app_8080
^[^.]+\.d2\.local#/ d2_app_8080
`)
	c.checkMap("_front_redir_fromroot__regex.map", `
^[^.]+\.d2\.local$ /app
`)
	c.checkMap("_front_tls_auth__regex.list", `
^[^.]+\.sub\.d1\.local$
`)
	c.checkMap("_front_tls_invalidcrt_pages__regex.map", `
^[^.]+\.sub\.d1\.local$ http://sub.d1.local/error.html
`)

	c.logger.CompareLogging(defaultLogging)
}

func TestCAVerifySkip(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	var h *hatypes.Host

	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
	b.Endpoints = []*hatypes.Endpoint{endpointS1}

	h = c.config.Hosts().AcquireHost("d1.local")
	h.TLS.TLSFilename = "/var/haproxy/ssl/certs/default.pem"
	h.TLS.TLSHash = "0"
	h.AddPath(b, "/", hatypes.MatchBegin)
	h.TLS.CAFilename = "/var/haproxy/ssl/ca/d1.local.pem"
	h.TLS.CAHash = "1"
	h.TLS.CAVerify = hatypes.CAVerifySkipCheck

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
    server s1 172.17.0.11:8080 weight 100
<<backends-default>>
frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }
    default_backend _error404
frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    acl tls-has-crt ssl_c_used
    acl tls-has-invalid-crt ssl_c_verify gt 0
    http-request use-service lua.send-421 if tls-has-crt { ssl_fc_has_sni } !{ ssl_fc_sni,strcmp(req.host) eq 0 }
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }
    use_backend %[var(req.snibackend)] if { var(req.snibackend) -m found }
    default_backend _error404
<<support>>
`)

	c.checkMap("_front_http_host__begin.map", `
d1.local#/ d1_app_8080
`)
	c.checkMap("_front_bind_crt.list", `
/var/haproxy/ssl/certs/default.pem !*
/var/haproxy/ssl/certs/default.pem [ca-file /var/haproxy/ssl/ca/d1.local.pem verify optional] d1.local
`)
	c.checkMap("_front_https_host__begin.map", `
d1.local#/ d1_app_8080
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

	var b = c.config.Backends().AcquireBackend("d1", "app", "8080")
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
	tempdir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Errorf("error creating tempdir: %v", err)
	}
	err = os.Mkdir(filepath.Join(tempdir, "errorfiles"), 0755)
	if err != nil {
		t.Errorf("error creating temp subdir: %v", err)
	}
	instance := CreateInstance(logger, InstanceOptions{
		HAProxyCfgDir:  tempdir,
		HAProxyMapsDir: tempdir,
		Metrics:        helper_test.NewMetricsMock(),
		BackendShards:  options.shardCount,
		//
		fake: true,
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
	if err := instance.haResponseTmpl.NewTemplate(
		"response.http.tmpl",
		"../../rootfs/etc/templates/responses/response.http.tmpl",
		"",
		0,
		2048,
	); err != nil {
		t.Errorf("error parsing responses.http.tmpl: %v", err)
	}
	if err := instance.luaResponseTmpl.NewTemplate(
		"responses.lua.tmpl",
		"../../rootfs/etc/templates/responses/responses.lua.tmpl",
		filepath.Join(tempdir, "responses.lua"),
		0,
		2048,
	); err != nil {
		t.Errorf("error parsing responses.lua.tmpl: %v", err)
	}
	if err := instance.modsecTmpl.NewTemplate(
		"modsecurity.tmpl",
		"../../rootfs/etc/templates/modsecurity/modsecurity.tmpl",
		filepath.Join(tempdir, "spoe-modsecurity.conf"),
		0,
		1024,
	); err != nil {
		t.Errorf("error parsing modsecurity.tmpl: %v", err)
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
	global.DefaultBackendRedirCode = 301
	global.Healthz.Port = 10253
	global.Master.ExitOnFailure = true
	global.MatchOrder = hatypes.DefaultMatchOrder
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
INFO haproxy successfully reloaded (embedded daemon)`

func (c *testConfig) Update() {
	timer := utils.NewTimer(nil)
	c.instance.AcmeUpdate()
	c.instance.HAProxyUpdate(timer)
}

func (c *testConfig) checkConfig(expected string) {
	c.checkConfigFile(expected, "haproxy.cfg")
}

func (c *testConfig) checkConfigFile(expected, fileName string) {
	actual := strings.Replace(c.readConfig(filepath.Join(c.tempdir, fileName)), c.tempdir, "/etc/haproxy/maps", -1)
	replace := map[string]string{
		"<<global>>": `global
    daemon
    unix-bind mode 0600
    stats socket /var/run/haproxy.sock level admin expose-fd listeners mode 600
    maxconn 2000
    hard-stop-after 15m
    lua-prepend-path /etc/haproxy/lua/?.lua
    lua-load /etc/haproxy/lua/auth-request.lua
    lua-load /etc/haproxy/lua/services.lua
    lua-load /etc/haproxy/lua/responses.lua
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
    http-request set-var(req.host) hdr(host),field(1,:),lower
    http-request set-var(req.base) var(req.host),concat(\#,req.path)`,
		"    <<http-headers>>": `    http-request set-header X-Forwarded-Proto http
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert`,
		"    <<https-headers>>": `    http-request set-header X-Forwarded-Proto https
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-SHA1
    http-request del-header X-SSL-Client-SHA2
    http-request del-header X-SSL-Client-Cert`,
		"<<frontend-http>>": `frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_http_host__begin.map)
    use_backend %[var(req.backend)] if { var(req.backend) -m found }`,
		"<<frontend-http-match-4>>": `frontend _front_http
    mode http
    bind :80
    <<set-req-base>>
    <<http-headers>>
    http-request set-var(req.backend) var(req.base),map_str(/etc/haproxy/maps/_front_http_host__exact.map)
    http-request set-var(req.backend) var(req.base),map_dir(/etc/haproxy/maps/_front_http_host__prefix_02.map) if !{ var(req.backend) -m found }
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
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map)
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }`,
		"<<frontend-https-match-4>>": `frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
    http-request set-var(req.hostbackend) var(req.base),map_str(/etc/haproxy/maps/_front_https_host__exact.map)
    http-request set-var(req.hostbackend) var(req.base),map_dir(/etc/haproxy/maps/_front_https_host__prefix_02.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.hostbackend) var(req.base),lower,map_beg(/etc/haproxy/maps/_front_https_host__begin.map) if !{ var(req.hostbackend) -m found }
    http-request set-var(req.hostbackend) var(req.base),map_reg(/etc/haproxy/maps/_front_https_host__regex.map) if !{ var(req.hostbackend) -m found }
    <<https-headers>>
    use_backend %[var(req.hostbackend)] if { var(req.hostbackend) -m found }`,
		"<<frontend-https-clean>>": `frontend _front_https
    mode http
    bind :443 ssl alpn h2,http/1.1 crt-list /etc/haproxy/maps/_front_bind_crt.list ca-ignore-err all crt-ignore-err all
    <<set-req-base>>
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

var replaceComments = regexp.MustCompile(`(?m)^[ \t]{0,2}(--.*|#.*)?[\r\n]+`)

func (c *testConfig) readConfig(fileName string) string {
	return replaceComments.ReplaceAllString(c.readRawConfig(fileName), ``)
}

func (c *testConfig) readRawConfig(fileName string) string {
	config, err := os.ReadFile(fileName)
	if err != nil {
		c.t.Errorf("error reading config file: %v", err)
		return ""
	}
	return string(config)
}

func (c *testConfig) compareText(name, actual, expected string) {
	txtActual := "\n" + strings.Trim(actual, "\n")
	txtExpected := "\n" + strings.Trim(expected, "\n")
	c.compareRawText(name, txtActual, txtExpected)
}

func (c *testConfig) containsText(name, s string, substr string) {
	if !strings.Contains(s, substr) {
		c.t.Error("\nFile " + name + " did not contain the expected substring.\nsubstring: " + substr + "\nfile contents:\n" + s)
	}
}

func (c *testConfig) compareRawText(name, actual, expected string) {
	if actual != expected {
		c.t.Error("\ndiff of " + name + ":" + diff.Diff(expected, actual))
	}
}
