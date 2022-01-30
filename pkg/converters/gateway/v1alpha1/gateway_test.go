/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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

package v1alpha1

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gateway "sigs.k8s.io/gateway-api/apis/v1alpha1"
	gwapischeme "sigs.k8s.io/gateway-api/pkg/client/clientset/networking/versioned/scheme"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

type testCaseSync struct {
	id             string
	resConfig      []string
	config         func(c *testConfig)
	configTrack    func(c *testConfig)
	expFullSync    bool
	expDefaultHost string
	expHosts       string
	expBackends    string
	expLogging     string
}

func TestSyncHTTPRouteCore(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "minimum",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "match-group-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				group := g.GroupVersionKind().Group
				g.Spec.Listeners[0].Routes.Group = &group
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "match-group-2",
			resConfig: []string{`
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: web
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - protocol: HTTPS
    port: 443
    routes:
      kind: HTTPRoute
      selector:
        matchLabels:
          gateway: web1
  - protocol: HTTP
    port: 80
    routes:
      kind: HTTPRoute
      selector:
        matchLabels:
          gateway: web2
    tls:
      mode: Passthrough
`},
			config: func(c *testConfig) {
				c.createHTTPRoute1("default/web1", "gateway=web1", "echoserver1:8080")
				c.createHTTPRoute1("default/web2", "gateway=web2", "echoserver2:8443")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web2__rule0
passthrough: true
httppassback: default_web1__rule0
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
- id: default_web2__rule0
  endpoints:
  - ip: 172.17.0.12
    port: 8443
    weight: 128
  modetcp: true
`,
		},
		{
			id: "missing-service-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
			},
			expLogging: `
WARN skipping service 'echoserver' on HTTPRoute 'default/web': service not found: 'default/echoserver'
`,
		},
		{
			id: "missing-port-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8081")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
WARN skipping service 'echoserver' on HTTPRoute 'default/web': port '8081' not found
`,
		},
		{
			id: "missing-service-ref-1",
			resConfig: []string{`
apiVersion: networking.x-k8s.io/v1alpha1
kind: HTTPRoute
metadata:
  labels:
    gateway: web
  name: web
  namespace: default
spec:
  rules:
  - forwardTo:
    - weight: 128
`},
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
		},
		{
			id: "invalid-kind-1",
			resConfig: []string{`
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: web
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - protocol: HTTP
    port: 80
    routes:
      kind: AcmeRoute
`},
			expLogging: `WARN ignoring unsupported listener type 'networking.x-k8s.io/AcmeRoute' on Gateway 'default/web'`,
		},
		{
			id: "another-group-1",
			resConfig: []string{`
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: web
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - protocol: HTTP
    port: 80
    routes:
      group: acme.io
      kind: AcmeRoute
`},
		},
		{
			id: "find-labels-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web3")
				c.createHTTPRoute1("default/web1", "gateway=web1", "echoserver1:8080")
				c.createHTTPRoute1("default/web2", "gateway=web2", "echoserver2:8080")
				c.createHTTPRoute1("default/web3", "gateway=web3", "echoserver3:8080")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				c.createService1("default/echoserver3", "8080", "172.17.0.13")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web3__rule0
`,
			expBackends: `
- id: default_web3__rule0
  endpoints:
  - ip: 172.17.0.13
    port: 8080
    weight: 128
`,
		},
		{
			id: "find-labels-2",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web1", "gateway=web", "echoserver1:8080")
				c.createHTTPRoute1("default/web2", "gateway=web", "echoserver2:8080")
				c.createHTTPRoute1("default/web3", "gateway=web3", "echoserver3:8080")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				c.createService1("default/echoserver3", "8080", "172.17.0.13")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web1__rule0
- path: /
  match: prefix
  backend: default_web2__rule0
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
- id: default_web2__rule0
  endpoints:
  - ip: 172.17.0.12
    port: 8080
    weight: 128
`,
		},
		{
			id: "custom-host-and-path-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				route := c.createHTTPRoute2("default/web", "gateway=web", "echoserver:8080", "/app")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				route.Spec.Hostnames = append(route.Spec.Hostnames, "domain1.local")
			},
			expHosts: `
- hostname: domain1.local
  paths:
  - path: /app
    match: prefix
    backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "match-path-types-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				route := c.createHTTPRoute2("default/web", "gateway=web", "echoserver:8080", "/app0,/app1,/app2,/app3,/app4")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				g1 := gateway.PathMatchExact
				g2 := gateway.PathMatchPrefix
				g3 := gateway.PathMatchRegularExpression
				g4 := gateway.PathMatchImplementationSpecific
				route.Spec.Rules[0].Matches[1].Path.Type = &g1
				route.Spec.Rules[0].Matches[2].Path.Type = &g2
				route.Spec.Rules[0].Matches[3].Path.Type = &g3
				route.Spec.Rules[0].Matches[4].Path.Type = &g4
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /app4
  backend: default_web__rule0
- path: /app3
  match: regex
  backend: default_web__rule0
- path: /app2
  match: prefix
  backend: default_web__rule0
- path: /app1
  match: exact
  backend: default_web__rule0
- path: /app0
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "match-path-mode-tcp-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				passthrough := gateway.TLSModePassthrough
				g.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{Mode: &passthrough}
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
passthrough: true
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
  modetcp: true
`,
		},
		{
			id: "multi-path-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute2("default/web", "gateway=web", "echoserver:8080", "/app1,/app2")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /app2
  match: prefix
  backend: default_web__rule0
- path: /app1
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "listener-hostname-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "gateway=web")
				r := c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				hostname := gateway.Hostname("domain.local")
				g.Spec.Listeners[0].Hostname = &hostname
				r.Spec.Hostnames = append(r.Spec.Hostnames, "other.local")
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "reouse-httproute-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web1", "gateway=web")
				c.createGateway1("default/web2", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
	})
}

func TestSyncHTTPRouteNamespaceFilter(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "filter-1",
			config: func(c *testConfig) {
				c.createGateway1("ns1/gwweb", "gateway=web")
				c.createHTTPRoute1("ns2/routeweb", "gateway=web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
			},
		},
		{
			id: "filter-2",
			config: func(c *testConfig) {
				g := c.createGateway1("ns1/gwweb", "gateway=web")
				c.createHTTPRoute1("ns2/routeweb", "gateway=web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
				same := gateway.RouteSelectSame
				g.Spec.Listeners[0].Routes.Namespaces = &gateway.RouteNamespaces{From: &same}
			},
		},
		{
			id: "filter-3",
			config: func(c *testConfig) {
				g := c.createGateway1("ns1/gwweb", "gateway=web")
				c.createHTTPRoute1("ns2/routeweb", "gateway=web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
				all := gateway.RouteSelectAll
				g.Spec.Listeners[0].Routes.Namespaces = &gateway.RouteNamespaces{From: &all}
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: ns2_routeweb__rule0
`,
			expBackends: `
- id: ns2_routeweb__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
	})
}

func TestSyncHTTPRouteTracked(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "remove-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsDel = append(c.cache.Changed.SecretsDel, c.createSecret1("default/crt1"))
			},
			expFullSync: false,
		},
		{
			id: "remove-secret-2",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsDel = append(c.cache.Changed.SecretsDel, c.createSecret1("default/crt"))
			},
			expFullSync: true,
		},
		{
			id: "add-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsAdd = append(c.cache.Changed.SecretsDel, c.createSecret1("default/crt1"))
			},
			expFullSync: false,
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web': secret not found: 'default/crt'
`,
		},
		{
			id: "add-secret-2",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsAdd = append(c.cache.Changed.SecretsDel, c.createSecret1("default/crt"))
			},
			expFullSync: true,
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web': secret not found: 'default/crt'
`,
		},
		{
			id: "update-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsUpd = append(c.cache.Changed.SecretsUpd, c.createSecret1("default/crt"))
			},
			expFullSync: true,
		},
		{
			id: "remove-service-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				svc, _ := c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.cache.Changed.ServicesDel = append(c.cache.Changed.ServicesDel, svc)
			},
			expFullSync: false,
		},
		{
			id: "remove-service-2",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				svc, _ := c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.Changed.ServicesDel = append(c.cache.Changed.ServicesDel, svc)
			},
			expFullSync: true,
		},
		{
			id: "add-service-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
			},
			configTrack: func(c *testConfig) {
				svc, _ := c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.Changed.ServicesDel = append(c.cache.Changed.ServicesDel, svc)
			},
			expFullSync: true,
			expLogging: `
WARN skipping service 'echoserver' on HTTPRoute 'default/web': service not found: 'default/echoserver'
`,
		},
		{
			id: "change-endpoint-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				_, ep := c.createService1("default/echoserver", "8080", "172.17.0.12")
				c.cache.Changed.EndpointsNew = append(c.cache.Changed.EndpointsNew, ep)
			},
			expFullSync: true,
		},
	})
}

func TestSyncHTTPRouteWeight(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "multi-backend-weight-1",
			resConfig: []string{`
apiVersion: networking.x-k8s.io/v1alpha1
kind: HTTPRoute
metadata:
  labels:
    gateway: web
  name: web
  namespace: default
spec:
  rules:
  - forwardTo:
    - serviceName: echoserver1
      port: 8080
      weight: 4
    - serviceName: echoserver2
      port: 8080
      weight: 1
`},
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 256
  - ip: 172.17.0.12
    port: 8080
    weight: 64
`,
		},
		{
			id: "multi-backend-weight-2",
			resConfig: []string{`
apiVersion: networking.x-k8s.io/v1alpha1
kind: HTTPRoute
metadata:
  labels:
    gateway: web
  name: web
  namespace: default
spec:
  rules:
  - forwardTo:
    - serviceName: echoserver1
      port: 8080
      weight: 4
    - serviceName: echoserver2
      port: 8080
      weight: 1
`},
			config: func(c *testConfig) {
				c.createGateway1("default/web", "gateway=web")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12,172.17.0.13,172.17.0.14,172.17.0.15")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 256
  - ip: 172.17.0.12
    port: 8080
    weight: 16
  - ip: 172.17.0.13
    port: 8080
    weight: 16
  - ip: 172.17.0.14
    port: 8080
    weight: 16
  - ip: 172.17.0.15
    port: 8080
    weight: 16
`,
		},
	})
}

func TestSyncHTTPRouteTLS(t *testing.T) {
	allow := gateway.TLSROuteOVerrideAllow
	deny := gateway.TLSRouteOverrideDeny
	runTestSync(t, []testCaseSync{
		{
			id: "tls-listener-err-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `WARN skipping certificate reference on Gateway 'default/web': secret not found: 'default/crt'`,
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-listener-err-2",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.CertificateRef.Group = "acme.io"
			},
			expLogging: `WARN skipping certificate reference on Gateway 'default/web': unsupported Group 'acme.io', supported groups are 'core' and ''`,
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-listener-err-3",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.CertificateRef.Kind = "ConfigMap"
			},
			expLogging: `WARN skipping certificate reference on Gateway 'default/web': unsupported Kind 'ConfigMap', the only supported kind is 'Secret'`,
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-listener-1",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/web", "gateway=web", "crt")
				c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.CertificateRef.Kind = "Secret"
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
tls:
  tlsfilename: /tls/crt.pem
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-listener-override-1",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/web", "gateway=web", "crt1")
				r := c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.RouteOverride = &gateway.TLSOverridePolicy{Certificate: &deny}
				r.Spec.TLS = &gateway.RouteTLSConfig{}
				r.Spec.TLS.CertificateRef.Name = "crt2"
				c.cache.SecretTLSPath["default/crt1"] = "/tls/crt1.pem"
				c.cache.SecretTLSPath["default/crt2"] = "/tls/crt2.pem"
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
tls:
  tlsfilename: /tls/crt1.pem
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-listener-override-2",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/web", "gateway=web", "crt1")
				r := c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.RouteOverride = &gateway.TLSOverridePolicy{Certificate: &allow}
				r.Spec.TLS = &gateway.RouteTLSConfig{}
				r.Spec.TLS.CertificateRef.Name = "crt2"
				c.cache.SecretTLSPath["default/crt1"] = "/tls/crt1.pem"
				c.cache.SecretTLSPath["default/crt2"] = "/tls/crt2.pem"
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
tls:
  tlsfilename: /tls/crt2.pem
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-route-err-1",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/web", "gateway=web", "crt0")
				r1 := c.createHTTPRoute2("default/web1", "gateway=web", "echoserver1:8080", "/app1")
				r2 := c.createHTTPRoute2("default/web2", "gateway=web", "echoserver2:8080", "/app2")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				gw.Spec.Listeners[0].TLS.RouteOverride = &gateway.TLSOverridePolicy{Certificate: &allow}
				r1.Spec.Hostnames = append(r1.Spec.Hostnames, "domain1.local")
				r1.Spec.Hostnames = append(r1.Spec.Hostnames, "domain2.local")
				r2.Spec.Hostnames = append(r2.Spec.Hostnames, "domain1.local")
				r2.Spec.Hostnames = append(r2.Spec.Hostnames, "domain2.local")
				r1.Spec.TLS = &gateway.RouteTLSConfig{}
				r1.Spec.TLS.CertificateRef.Name = "crt1"
				r2.Spec.TLS = &gateway.RouteTLSConfig{}
				r2.Spec.TLS.CertificateRef.Name = "crt2"
				c.cache.SecretTLSPath["default/crt0"] = "/tls/crt0.pem"
				c.cache.SecretTLSPath["default/crt1"] = "/tls/crt1.pem"
				c.cache.SecretTLSPath["default/crt2"] = "/tls/crt2.pem"
			},
			expLogging: `
WARN skipping certificate reference on HTTPRoute 'default/web2' for hostname domain1.local: a TLS certificate was already assigned
WARN skipping certificate reference on HTTPRoute 'default/web2' for hostname domain2.local: a TLS certificate was already assigned
`,
			expHosts: `
- hostname: domain1.local
  paths:
  - path: /app2
    match: prefix
    backend: default_web2__rule0
  - path: /app1
    match: prefix
    backend: default_web1__rule0
  tls:
    tlsfilename: /tls/crt1.pem
- hostname: domain2.local
  paths:
  - path: /app2
    match: prefix
    backend: default_web2__rule0
  - path: /app1
    match: prefix
    backend: default_web1__rule0
  tls:
    tlsfilename: /tls/crt1.pem
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
- id: default_web2__rule0
  endpoints:
  - ip: 172.17.0.12
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-route-fallback-err-1",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/webgw", "gateway=web", "crt-listener")
				r := c.createHTTPRoute1("default/webroute", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.RouteOverride = &gateway.TLSOverridePolicy{Certificate: &allow}
				r.Spec.TLS = &gateway.RouteTLSConfig{}
				r.Spec.TLS.CertificateRef.Name = "crt-route"
				c.cache.SecretTLSPath["default/crt-listener"] = "/tls/crt-listener.pem"
			},
			expLogging: `
WARN falling back to the listener configured certificate due to an error reading on HTTPRoute 'default/webroute': secret not found: 'default/crt-route'
`,
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_webroute__rule0
tls:
  tlsfilename: /tls/crt-listener.pem
`,
			expBackends: `
- id: default_webroute__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "tls-route-fallback-err-2",
			config: func(c *testConfig) {
				gw := c.createGateway2("default/webgw", "gateway=web", "crt-listener")
				r := c.createHTTPRoute1("default/webroute", "gateway=web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				gw.Spec.Listeners[0].TLS.RouteOverride = &gateway.TLSOverridePolicy{Certificate: &allow}
				r.Spec.TLS = &gateway.RouteTLSConfig{}
				r.Spec.TLS.CertificateRef.Name = "crt-route"
			},
			expLogging: `
WARN skipping listener certificate reference on Gateway 'default/webgw': secret not found: 'default/crt-listener'
WARN skipping route certificate reference on HTTPRoute 'default/webroute': secret not found: 'default/crt-route'
`,
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_webroute__rule0
`,
			expBackends: `
- id: default_webroute__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
	})
}

func TestSyncHTTPRouteTLSPassthrough(t *testing.T) {
	passthrough := gateway.TLSModePassthrough
	runTestSync(t, []testCaseSync{
		{
			id: "https-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "gateway=web")
				r := c.createHTTPRoute1("default/web", "gateway=web", "echoserver:8443")
				c.createService1("default/echoserver", "8443", "172.17.0.11")
				g.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{Mode: &passthrough}
				r.Spec.Hostnames = append(r.Spec.Hostnames, "domain.local")
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web__rule0
  passthrough: true
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8443
    weight: 128
  modetcp: true
`,
		},
		{
			id: "http-than-https-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web1", "gateway=web1")
				g := c.createGateway1("default/web2", "gateway=web2")
				r1 := c.createHTTPRoute1("default/web1", "gateway=web1", "echoserver1:8080")
				r2 := c.createHTTPRoute1("default/web2", "gateway=web2", "echoserver2:8443")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				g.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = append(r1.Spec.Hostnames, "domain.local")
				r2.Spec.Hostnames = append(r2.Spec.Hostnames, "domain.local")
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web2__rule0
  passthrough: true
  httppassback: default_web1__rule0
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
- id: default_web2__rule0
  endpoints:
  - ip: 172.17.0.12
    port: 8443
    weight: 128
  modetcp: true
`,
		},
		{
			id: "https-than-http-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web1", "gateway=web1")
				c.createGateway1("default/web2", "gateway=web2")
				r1 := c.createHTTPRoute1("default/web1", "gateway=web1", "echoserver1:8443")
				r2 := c.createHTTPRoute1("default/web2", "gateway=web2", "echoserver2:8080")
				c.createService1("default/echoserver1", "8443", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				g.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = append(r1.Spec.Hostnames, "domain.local")
				r2.Spec.Hostnames = append(r2.Spec.Hostnames, "domain.local")
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web1__rule0
  passthrough: true
  httppassback: default_web2__rule0
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8443
    weight: 128
  modetcp: true
- id: default_web2__rule0
  endpoints:
  - ip: 172.17.0.12
    port: 8080
    weight: 128
`,
		},
		{
			id: "http-than-https-than-http-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web1", "gateway=web1")
				g := c.createGateway1("default/web2", "gateway=web2")
				c.createGateway1("default/web3", "gateway=web3")
				r1 := c.createHTTPRoute2("default/web1", "gateway=web1", "echoserver1:8080", "/,/app1")
				r2 := c.createHTTPRoute1("default/web2", "gateway=web2", "echoserver2:8443")
				r3 := c.createHTTPRoute2("default/web3", "gateway=web3", "echoserver3:8080", "/app2")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				c.createService1("default/echoserver3", "8080", "172.17.0.13")
				g.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = append(r1.Spec.Hostnames, "domain.local")
				r2.Spec.Hostnames = append(r2.Spec.Hostnames, "domain.local")
				r3.Spec.Hostnames = append(r3.Spec.Hostnames, "domain.local")
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /app2
    match: prefix
    backend: default_web3__rule0
  - path: /app1
    match: prefix
    backend: default_web1__rule0
  - path: /
    match: prefix
    backend: default_web2__rule0
  passthrough: true
  httppassback: default_web1__rule0
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
- id: default_web2__rule0
  endpoints:
  - ip: 172.17.0.12
    port: 8443
    weight: 128
  modetcp: true
- id: default_web3__rule0
  endpoints:
  - ip: 172.17.0.13
    port: 8080
    weight: 128
`,
		},
		{
			id: "https-with-match-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "gateway=web")
				r1 := c.createHTTPRoute2("default/web", "gateway=web", "echoserver:8443", "/app")
				c.createService1("default/echoserver", "8443", "172.17.0.11")
				g.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = append(r1.Spec.Hostnames, "domain.local")
			},
			expLogging: `
WARN ignoring match from HTTPRoute 'default/web': backend is configured as TCP mode
`,
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web__rule0
  passthrough: true
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8443
    weight: 128
  modetcp: true
`,
		},
	})
}

func runTestSync(t *testing.T, testCases []testCaseSync) {
	for _, test := range testCases {
		c := setup(t)

		c.createGatewayResources(test.resConfig)
		if test.config != nil {
			test.config(c)
		}
		c.sync()

		if test.configTrack != nil {
			c.hconfig.Commit()
			test.configTrack(c)
			conv := c.createConverter()
			fullSync := conv.NeedFullSync()
			if fullSync != test.expFullSync {
				t.Errorf("%s: full sync differ, expected %t, actual: %t", test.id, test.expFullSync, fullSync)
			}
		} else {
			if test.expDefaultHost == "" {
				test.expDefaultHost = "[]"
			}
			if test.expHosts == "" {
				test.expHosts = "[]"
			}
			if test.expBackends == "" {
				test.expBackends = "[]"
			}
			c.compareConfigDefaultHost(test.id, test.expDefaultHost)
			c.compareConfigHosts(test.id, test.expHosts)
			c.compareConfigBacks(test.id, test.expBackends)
		}

		c.logger.CompareLoggingID(test.id, test.expLogging)

		c.teardown()
	}
}

type testConfig struct {
	t       *testing.T
	cache   *conv_helper.CacheMock
	logger  *types_helper.LoggerMock
	tracker convtypes.Tracker
	hconfig haproxy.Config
}

func setup(t *testing.T) *testConfig {
	logger := types_helper.NewLoggerMock(t)
	tracker := tracker.NewTracker()
	c := &testConfig{
		t:       t,
		hconfig: haproxy.CreateInstance(logger, haproxy.InstanceOptions{}).Config(),
		cache:   conv_helper.NewCacheMock(tracker),
		logger:  logger,
		tracker: tracker,
	}
	return c
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
}

func (c *testConfig) sync() {
	conv := c.createConverter()
	conv.Sync(true)
}

func (c *testConfig) createConverter() Config {
	return NewGatewayConverter(
		&convtypes.ConverterOptions{
			Cache:   c.cache,
			Logger:  c.logger,
			Tracker: c.tracker,
		},
		c.hconfig,
		c.cache.SwapChangedObjects(),
		nil,
	)
}

func (c *testConfig) createSecret1(secretName string) *api.Secret {
	return conv_helper.CreateSecret(secretName)
}

func (c *testConfig) createService1(name, port, ip string) (*api.Service, *api.Endpoints) {
	svc, ep := conv_helper.CreateService(name, port, ip)
	c.cache.SvcList = append(c.cache.SvcList, svc)
	c.cache.EpList[name] = ep
	return svc, ep
}

func (c *testConfig) createGatewayClass1() *gateway.GatewayClass {
	gc := CreateObject(`
apiVersion: networking.x-k8s.io/v1alpha1
kind: GatewayClass
metadata:
  name: haproxy
spec:
  controller: haproxy-ingress.github.io/controller`).(*gateway.GatewayClass)
	c.cache.GatewayA1ClassList = append(c.cache.GatewayA1ClassList, gc)
	return gc
}

func (c *testConfig) createGateway1(name, matchLabels string) *gateway.Gateway {
	n := strings.Split(name, "/")
	gw := CreateObject(`
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: ` + n[1] + `
  namespace: ` + n[0] + `
spec:
  gatewayClassName: haproxy
  listeners:
  - protocol: HTTP
    port: 80
    routes:
      kind: HTTPRoute
      selector:
        matchLabels: {}`).(*gateway.Gateway)
	for _, label := range strings.Split(matchLabels, ",") {
		l := strings.Split(label, "=")
		gw.Spec.Listeners[0].Routes.Selector.MatchLabels[l[0]] = l[1]
	}
	c.cache.GatewayA1List = append(c.cache.GatewayA1List, gw)
	return gw
}

func (c *testConfig) createGateway2(name, matchLabel, secretName string) *gateway.Gateway {
	gw := c.createGateway1(name, matchLabel)
	gw.Spec.Listeners[0].TLS = &gateway.GatewayTLSConfig{
		CertificateRef: &gateway.LocalObjectReference{
			Name: secretName,
		},
	}
	return gw
}

func (c *testConfig) createHTTPRoute1(name, labels, service string) *gateway.HTTPRoute {
	n := strings.Split(name, "/")
	svc := strings.Split(service, ":")
	r := CreateObject(`
kind: HTTPRoute
apiVersion: networking.x-k8s.io/v1alpha1
metadata:
  labels: {}
  name: ` + n[1] + `
  namespace: ` + n[0] + `
spec:
  rules:
  - forwardTo:
    - serviceName: ` + svc[0] + `
      port: ` + svc[1] + `
      weight: 1`).(*gateway.HTTPRoute)
	for _, label := range strings.Split(labels, ",") {
		l := strings.Split(label, "=")
		r.ObjectMeta.Labels[l[0]] = l[1]
	}
	c.cache.HTTPRouteA1List = append(c.cache.HTTPRouteA1List, r)
	return r
}

func (c *testConfig) createHTTPRoute2(name, labels, service, paths string) *gateway.HTTPRoute {
	r := c.createHTTPRoute1(name, labels, service)
	prefix := gateway.PathMatchPrefix
	for _, path := range strings.Split(paths, ",") {
		p := path
		match := gateway.HTTPRouteMatch{
			Path: &gateway.HTTPPathMatch{
				Type:  &prefix,
				Value: &p,
			},
		}
		r.Spec.Rules[0].Matches = append(r.Spec.Rules[0].Matches, match)
	}
	return r
}

func (c *testConfig) createGatewayResources(res []string) {
	for _, cfg := range res {
		obj := CreateObject(cfg)
		switch obj := obj.(type) {
		case *gateway.Gateway:
			c.cache.GatewayA1List = append(c.cache.GatewayA1List, obj)
		case *gateway.HTTPRoute:
			c.cache.HTTPRouteA1List = append(c.cache.HTTPRouteA1List, obj)
		default:
			panic(fmt.Errorf("unknown object type: %s", obj.GetObjectKind().GroupVersionKind().String()))
		}
	}
}

func CreateObject(cfg string) runtime.Object {
	decode := gwapischeme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode([]byte(cfg), nil, nil)
	if err != nil {
		return nil
	}
	return obj
}

func (c *testConfig) compareText(id string, actual, expected string) {
	txt1 := "\n" + strings.Trim(expected, "\n")
	txt2 := "\n" + strings.Trim(actual, "\n")
	if txt1 != txt2 {
		c.t.Errorf("diff on %s:%s", id, diff.Diff(txt1, txt2))
	}
}

func (c *testConfig) compareConfigDefaultHost(id string, expected string) {
	host := c.hconfig.Hosts().DefaultHost()
	if host != nil {
		c.compareText(id, conv_helper.MarshalHost(host), expected)
	} else {
		c.compareText(id, "[]", expected)
	}
}

func (c *testConfig) compareConfigHosts(id string, expected string) {
	c.compareText(id, conv_helper.MarshalHosts(c.hconfig.Hosts().BuildSortedItems()...), expected)
}

func (c *testConfig) compareConfigBacks(id string, expected string) {
	c.compareText(id, conv_helper.MarshalBackendsWeight(c.hconfig.Backends().BuildSortedItems()...), expected)
}
