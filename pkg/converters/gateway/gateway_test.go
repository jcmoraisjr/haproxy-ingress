/*
Copyright 2024 The HAProxy Ingress Controller Authors.

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

package gateway_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
	api "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapischeme "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/scheme"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/gateway"
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
	expTCPServices string
	expBackends    string
	expLogging     string
}

func TestSyncHTTPRouteCore(t *testing.T) {
	gatewayGroup := gatewayv1.Group(gatewayv1.GroupName)
	otherGroup := gatewayv1.Group("other.k8s.io")
	runTestSync(t, []testCaseSync{
		{
			id: "minimum",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
			id: "cross-namespace-1",
			config: func(c *testConfig) {
				c.createGateway1("ns1/web", "l1")
				c.createHTTPRoute1("ns2/web", "ns1/web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
WARN skipping attachment of HTTPRoute 'ns2/web' to Gateway 'ns1/web' listener 'l1': listener does not allow the route
`,
		},
		{
			id: "cross-namespace-2",
			config: func(c *testConfig) {
				g := c.createGateway1("ns1/web", "l1")
				c.createHTTPRoute1("ns2/web", "ns1/web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
				all := gatewayv1.NamespacesFromAll
				g.Spec.Listeners[0].AllowedRoutes.Namespaces.From = &all
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: ns2_web__rule0
`,
			expBackends: `
- id: ns2_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "cross-namespace-3",
			config: func(c *testConfig) {
				c.createNamespace("ns2", "name=ns2")
				c.createGateway1("ns1/web", "l1::name=ns1")
				c.createHTTPRoute1("ns2/web", "ns1/web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
WARN skipping attachment of HTTPRoute 'ns2/web' to Gateway 'ns1/web' listener 'l1': listener does not allow the route
`,
		},
		{
			id: "cross-namespace-4",
			config: func(c *testConfig) {
				c.createNamespace("ns2", "name=ns2")
				c.createGateway1("ns1/web", "l1::name=ns2")
				c.createHTTPRoute1("ns2/web", "ns1/web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: ns2_web__rule0
`,
			expBackends: `
- id: ns2_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`,
		},
		{
			id: "cross-namespace-5",
			config: func(c *testConfig) {
				c.createGateway1("ns2/web", "l1")
				c.createHTTPRoute1("ns2/web", "ns1/web", "echoserver:8080")
				c.createService1("ns2/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
ERROR error reading gateway: gateway not found: ns1/web`,
		},
		{
			id: "allowed-kind-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1,l2")
				c.createHTTPRoute2("default/web1", "web:l1", "echoserver1:8080", "/app1")
				c.createHTTPRoute2("default/web2", "web:l2", "echoserver2:8080", "/app2")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				g.Spec.Listeners[0].AllowedRoutes.Kinds = []gatewayv1.RouteGroupKind{
					{Kind: "HTTPRoute"},
					{Group: &otherGroup, Kind: "HTTPRoute"},
				}
				g.Spec.Listeners[1].AllowedRoutes.Kinds = []gatewayv1.RouteGroupKind{
					{Group: &gatewayGroup, Kind: "HTTPRoute"},
					{Group: &gatewayGroup, Kind: "OtherRoute"},
				}
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /app2
  match: prefix
  backend: default_web2__rule0
- path: /app1
  match: prefix
  backend: default_web1__rule0
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
			id: "allowed-kind-2",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				g.Spec.Listeners[0].AllowedRoutes.Kinds = []gatewayv1.RouteGroupKind{
					{Kind: "OtherRoute"},
					{Group: &gatewayGroup, Kind: "OtherRoute"},
					{Group: &otherGroup, Kind: "HTTPRoute"},
				}
			},
			expLogging: `
WARN skipping attachment of HTTPRoute 'default/web' to Gateway 'default/web' listener 'l1': listener does not allow route of Kind 'HTTPRoute'
`,
		},
		{
			id: "multi-listener-1",
			resConfig: []string{`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: web
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - name: h1
    allowedRoutes:
      namespaces:
        from: Same
  - name: h2
    allowedRoutes:
      namespaces:
        from: Same
`},
			config: func(c *testConfig) {
				c.createHTTPRoute2("default/web1", "web:h1", "echoserver1:8080", "/app1")
				c.createHTTPRoute2("default/web2", "web:h2", "echoserver2:8080", "/app2")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /app2
  match: prefix
  backend: default_web2__rule0
- path: /app1
  match: prefix
  backend: default_web1__rule0
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
			id: "tls-listener-no-refs-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1,l2")
				r1 := c.createHTTPRoute2("default/web1", "web:l1", "echoserver1:8080", "/")
				r2 := c.createHTTPRoute2("default/web2", "web:l2", "echoserver2:8080", "/")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				r1.Spec.Hostnames = []gatewayv1.Hostname{"host1.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"host1.local"}
			},
			expLogging: `
WARN skipping redeclared path '/' type 'prefix' on HTTPRoute 'default/web2'
`,
			expHosts: `
- hostname: host1.local
  paths:
  - path: /
    match: prefix
    backend: default_web1__rule0
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
			id: "duplicate-endpoint",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1,l2")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.11")
				r := c.createHTTPRoute1("default/web1", "web:l1", "echoserver1:8080,echoserver2:8080")
				r.Spec.Rules[0].BackendRefs[0].Weight = ptr.To[int32](1)
				r.Spec.Rules[0].BackendRefs[1].Weight = ptr.To[int32](0)
			},
			expDefaultHost: `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web1__rule0
`,
			expBackends: `
- id: default_web1__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
  - ip: 172.17.0.11
    port: 8080
    drain: true
`,
		},
	})
}

func TestSyncHTTPRouteTracking(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "remove-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsAdd = append(c.cache.Changed.SecretsDel, c.createSecret1("default/crt1"))
			},
			expFullSync: false,
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': secret not found: 'default/crt'
`,
		},
		{
			id: "add-secret-2",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			configTrack: func(c *testConfig) {
				c.cache.Changed.SecretsAdd = append(c.cache.Changed.SecretsDel, c.createSecret1("default/crt"))
			},
			expFullSync: true,
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': secret not found: 'default/crt'
`,
		},
		{
			id: "update-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
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
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
  namespace: default
spec:
  parentRefs:
  - name: web
  rules:
  - backendRefs:
    - name: echoserver1
      port: 8080
      weight: 4
    - name: echoserver2
      port: 8080
      weight: 1
`},
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1")
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
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  labels:
    gateway: web
  name: web
  namespace: default
spec:
  parentRefs:
  - name: web
  rules:
  - backendRefs:
    - name: echoserver1
      port: 8080
      weight: 4
    - name: echoserver2
      port: 8080
      weight: 1
`},
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1")
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

func TestSyncTCPRouteCore(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "minimum",
			config: func(c *testConfig) {
				c.createGateway1("default/pg", "l1:5432")
				c.createTCPRoute1("default/pg", "pg", "postgres:15432")
				c.createService1("default/postgres", "15432", "172.17.0.11")
			},
			expTCPServices: `
- backends: []
  defaultbackend: default_pg__tcprule0
  port: 5432
  proxyprot: false
  tls: []
`,
			expBackends: `
- id: default_pg__tcprule0
  endpoints:
  - ip: 172.17.0.11
    port: 15432
    weight: 128
  modetcp: true
`,
		},
	})
}

func TestSyncGateway(t *testing.T) {
	runTestSync(t, []testCaseSync{
		{
			id: "ignore-missing-gateway-class",
			config: func(c *testConfig) {
				c.createGateway0("default/web")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expLogging:     "",
			expDefaultHost: "",
			expBackends:    "",
		},
	})
}

func TestSyncGatewayTLS(t *testing.T) {
	defaultBackend := `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
`
	defaultHTTPHost := `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
`
	defaultHTTPSHost := `
hostname: <default>
paths:
- path: /
  match: prefix
  backend: default_web__rule0
tls:
  tlsfilename: /tls/default/crt.pem
`
	runTestSync(t, []testCaseSync{
		{
			id: "tls-listener-missing-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': secret not found: 'default/crt'
`,
			expDefaultHost: defaultHTTPHost,
			expBackends:    defaultBackend,
		},
		{
			id: "tls-listener-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt")
				c.createGateway2("default/web", "l1", "crt")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expDefaultHost: defaultHTTPSHost,
			expBackends:    defaultBackend,
		},
		{
			id: "tls-listener-more-refs-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt")
				c.createSecret1("default/crt2")
				c.createGateway2("default/web", "l1", "crt,crt2")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
WARN skipping one or more certificate references on Gateway 'default/web' listener 'l1': listener currently supports only the first referenced certificate
`,
			expDefaultHost: defaultHTTPSHost,
			expBackends:    defaultBackend,
		},
		{
			id: "tls-listener-no-refs-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt1")
				g := c.createGateway2("default/web", "l1", "crt1")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				g.Spec.Listeners[0].TLS.CertificateRefs = nil
			},
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': listener has no certificate reference
`,
			expDefaultHost: defaultHTTPHost,
			expBackends:    defaultBackend,
		},
		{
			id: "tls-listener-reassign-crt-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt1")
				c.createSecret1("default/crt2")
				c.createGateway2("default/web", "l1,l2", "crt1").Spec.Listeners[1].TLS.CertificateRefs[0].Name = "crt2"
				r1 := c.createHTTPRoute1("default/web1", "web:l1", "echoserver1:8080")
				r2 := c.createHTTPRoute1("default/web2", "web:l2", "echoserver2:8080")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				r1.Spec.Hostnames = []gatewayv1.Hostname{"host1.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"host1.local"}
			},
			expLogging: `
WARN skipping redeclared path '/' type 'prefix' on HTTPRoute 'default/web2'
`,
			expHosts: `
- hostname: host1.local
  paths:
  - path: /
    match: prefix
    backend: default_web1__rule0
  tls:
    tlsfilename: /tls/default/crt1.pem
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
	})
}

func TestSyncGatewayTLSPassthrough(t *testing.T) {
	passthrough := gatewayv1.TLSModePassthrough
	runTestSync(t, []testCaseSync{
		{
			id: "passthrough-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1")
				r := c.createHTTPRoute1("default/web", "web", "echoserver:8443")
				c.createService1("default/echoserver", "8443", "172.17.0.11")
				g.Spec.Listeners[0].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
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
			id: "passthrough-and-http-first-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1,l2")
				r1 := c.createHTTPRoute2("default/web1", "web:l1", "echoserver1:8080", "/")
				r2 := c.createHTTPRoute1("default/web2", "web:l2", "echoserver2:8443")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				g.Spec.Listeners[1].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
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
			id: "passthrough-and-http-last-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1,l2")
				r1 := c.createHTTPRoute1("default/web1", "web:l1", "echoserver1:8443")
				r2 := c.createHTTPRoute2("default/web2", "web:l2", "echoserver2:8080", "/")
				c.createService1("default/echoserver1", "8443", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				g.Spec.Listeners[0].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
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
			id: "passthrough-and-http-dup-passthrough-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1,l2,l3")
				r1 := c.createHTTPRoute1("default/web1", "web:l1", "echoserver1:8443")
				r2 := c.createHTTPRoute1("default/web2", "web:l2", "echoserver2:8443")
				r3 := c.createHTTPRoute2("default/web3", "web:l3", "echoserver3:8080", "/")
				c.createService1("default/echoserver1", "8443", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				c.createService1("default/echoserver3", "8080", "172.17.0.13")
				g.Spec.Listeners[0].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				g.Spec.Listeners[1].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r3.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
			},
			expLogging: `
WARN skipping redeclared ssl-passthrough root path on HTTPRoute 'default/web2'
`,
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web1__rule0
  passthrough: true
  httppassback: default_web3__rule0
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
			id: "passthrough-and-http-dup-http-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1,l2,l3")
				r1 := c.createHTTPRoute1("default/web1", "web:l1", "echoserver1:8443")
				r2 := c.createHTTPRoute2("default/web2", "web:l2", "echoserver2:8080", "/")
				r3 := c.createHTTPRoute2("default/web3", "web:l3", "echoserver3:8080", "/")
				c.createService1("default/echoserver1", "8443", "172.17.0.11")
				c.createService1("default/echoserver2", "8080", "172.17.0.12")
				c.createService1("default/echoserver3", "8080", "172.17.0.13")
				g.Spec.Listeners[0].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r3.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
			},
			expLogging: `
WARN skipping redeclared http root path on HTTPRoute 'default/web3'
`,
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
- id: default_web3__rule0
  endpoints:
  - ip: 172.17.0.13
    port: 8080
    weight: 128
`,
		},
		{
			id: "passthrough-and-http-path-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1,l2")
				r1 := c.createHTTPRoute2("default/web1", "web:l1", "echoserver1:8080", "/app")
				r2 := c.createHTTPRoute1("default/web2", "web:l2", "echoserver2:8443")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				g.Spec.Listeners[1].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /app
    match: prefix
    backend: default_web1__rule0
  - path: /
    match: prefix
    backend: default_web2__rule0
  passthrough: true
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
			id: "passthrough-with-match-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1")
				r1 := c.createHTTPRoute2("default/web", "web", "echoserver:8443", "/app")
				c.createService1("default/echoserver", "8443", "172.17.0.11")
				g.Spec.Listeners[0].TLS = &gatewayv1.GatewayTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
			},
			expLogging: `
WARN ignoring match from HTTPRoute 'default/web': backend is TCP or SSL Passthrough
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
		t.Run(test.id, func(t *testing.T) {
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
				if test.expTCPServices == "" {
					test.expTCPServices = "[]"
				}
				if test.expBackends == "" {
					test.expBackends = "[]"
				}
				c.compareConfigDefaultHost(test.id, test.expDefaultHost)
				c.compareConfigHosts(test.id, test.expHosts)
				c.compareConfigTCPServices(test.id, test.expTCPServices)
				c.compareConfigBacks(test.id, test.expBackends)
			}

			c.logger.CompareLoggingID(test.id, test.expLogging)
		})
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
	t.Cleanup(func() {
		c.logger.CompareLogging("")
	})
	return c
}

func (c *testConfig) sync() {
	conv := c.createConverter()
	conv.Sync(true, &gatewayv1.Gateway{})
}

func (c *testConfig) createConverter() gateway.Config {
	return gateway.NewGatewayConverter(
		&convtypes.ConverterOptions{
			Cache:         c.cache,
			Logger:        c.logger,
			Tracker:       c.tracker,
			HasTCPRouteA2: true,
		},
		c.hconfig,
		c.cache.SwapChangedObjects(),
		nil,
	)
}

func (c *testConfig) createNamespace(name, labels string) *api.Namespace {
	ns := &api.Namespace{}
	ns.Name = name
	ns.Labels = map[string]string{}
	for _, label := range strings.Split(labels, ",") {
		l := strings.Split(label, "=")
		ns.Labels[l[0]] = l[1]
	}
	c.cache.NsList[name] = ns
	return ns
}

func (c *testConfig) createSecret1(secretName string) *api.Secret {
	s := conv_helper.CreateSecret(secretName)
	c.cache.SecretTLSPath[secretName] = "/tls/" + secretName + ".pem"
	return s
}

func (c *testConfig) createService1(name, port, ip string) (*api.Service, *api.Endpoints) {
	svc, ep, _ := conv_helper.CreateService(name, port, ip)
	c.cache.SvcList = append(c.cache.SvcList, svc)
	c.cache.EpList[name] = ep
	return svc, ep
}

func (c *testConfig) createGateway0(name string) *gatewayv1.Gateway {
	n := strings.Split(name, "/")
	gw := CreateObject(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ` + n[1] + `
  namespace: ` + n[0] + `
spec:
  gatewayClassName: missing`).(*gatewayv1.Gateway)
	c.cache.GatewayList = append(c.cache.GatewayList, gw)
	return gw
}

func (c *testConfig) createGateway1(name, listeners string) *gatewayv1.Gateway {
	n := strings.Split(name, "/")
	gw := CreateObject(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ` + n[1] + `
  namespace: ` + n[0] + `
spec:
  gatewayClassName: haproxy
  listeners: []`).(*gatewayv1.Gateway)
	for _, listener := range strings.Split(listeners, ",") {
		l := gatewayv1.Listener{}
		var lname, lselector string
		var lport gatewayv1.PortNumber
		lsplit := strings.Split(listener, ":")
		lname = lsplit[0]
		if len(lsplit) > 2 {
			lselector = lsplit[2]
		}
		if len(lsplit) > 1 && lsplit[1] != "" {
			port, err := strconv.Atoi(lsplit[1])
			if err != nil {
				panic(err)
			}
			lport = gatewayv1.PortNumber(port)
		}
		l.Name = gatewayv1.SectionName(lname)
		l.Port = lport
		from := gatewayv1.NamespacesFromSame
		var selector *v1.LabelSelector
		if lselector != "" {
			from = gatewayv1.NamespacesFromSelector
			selector = &v1.LabelSelector{
				MatchLabels: map[string]string{},
			}
			for _, sel := range strings.Split(lselector, ";") {
				s := strings.Split(sel, "=")
				selector.MatchLabels[s[0]] = s[1]
			}
		}
		l.AllowedRoutes = &gatewayv1.AllowedRoutes{
			Namespaces: &gatewayv1.RouteNamespaces{
				From:     &from,
				Selector: selector,
			},
		}
		gw.Spec.Listeners = append(gw.Spec.Listeners, l)
	}
	c.cache.GatewayList = append(c.cache.GatewayList, gw)
	return gw
}

func (c *testConfig) createGateway2(name, listeners, secretName string) *gatewayv1.Gateway {
	gw := c.createGateway1(name, listeners)
	for l := range gw.Spec.Listeners {
		tls := &gatewayv1.GatewayTLSConfig{}
		for _, s := range strings.Split(secretName, ",") {
			tls.CertificateRefs = append(tls.CertificateRefs, gatewayv1.SecretObjectReference{
				Name: gatewayv1.ObjectName(s),
			})
		}
		gw.Spec.Listeners[l].TLS = tls
	}
	return gw
}

func splitRouteInfo(name, parent, services string) (n []string, svcs [][]string, pns, pn, ps string) {
	n = strings.Split(name, "/")
	if i := strings.Index(parent, "/"); i >= 0 {
		pns = parent[:i]
		pn = parent[i+1:]
	} else {
		pn = parent
	}
	if i := strings.Index(pn, ":"); i >= 0 {
		ps = pn[i+1:]
		pn = pn[:i]
	}
	for _, svc := range strings.Split(services, ",") {
		svcs = append(svcs, strings.Split(svc, ":"))
	}
	return
}

func (c *testConfig) createRoute(kind, version, name, parent, services string) string {
	n, svcs, pns, pn, ps := splitRouteInfo(name, parent, services)
	r := `
apiVersion: gateway.networking.k8s.io/` + version + `
kind: ` + kind + `
metadata:
  name: ` + n[1] + `
  namespace: ` + n[0] + `
spec:
  parentRefs:
  - name: ` + pn + `
    namespace: ` + pns + `
    sectionName: ` + ps + `
  rules:
  - backendRefs:`

	for _, svc := range svcs {
		r += `
    - name: ` + svc[0] + `
      port: ` + svc[1]
	}

	return r
}

func (c *testConfig) createHTTPRoute1(name, parent, service string) *gatewayv1.HTTPRoute {
	r := CreateObject(c.createRoute("HTTPRoute", "v1", name, parent, service)).(*gatewayv1.HTTPRoute)
	c.cache.HTTPRouteList = append(c.cache.HTTPRouteList, r)
	return r
}

func (c *testConfig) createHTTPRoute2(name, parent, service, paths string) *gatewayv1.HTTPRoute {
	r := c.createHTTPRoute1(name, parent, service)
	prefix := gatewayv1.PathMatchPathPrefix
	for _, path := range strings.Split(paths, ",") {
		p := path
		match := gatewayv1.HTTPRouteMatch{
			Path: &gatewayv1.HTTPPathMatch{
				Type:  &prefix,
				Value: &p,
			},
		}
		r.Spec.Rules[0].Matches = append(r.Spec.Rules[0].Matches, match)
	}
	return r
}

func (c *testConfig) createTCPRoute1(name, parent, services string) *gatewayv1alpha2.TCPRoute {
	r := CreateObject(c.createRoute("TCPRoute", "v1alpha2", name, parent, services)).(*gatewayv1alpha2.TCPRoute)
	c.cache.TCPRouteList = append(c.cache.TCPRouteList, r)
	return r
}

func (c *testConfig) createGatewayResources(res []string) {
	for _, cfg := range res {
		obj := CreateObject(cfg)
		switch obj := obj.(type) {
		case *gatewayv1.Gateway:
			c.cache.GatewayList = append(c.cache.GatewayList, obj)
		case *gatewayv1.HTTPRoute:
			c.cache.HTTPRouteList = append(c.cache.HTTPRouteList, obj)
		case nil:
			panic(fmt.Errorf("object is nil, cfg is %s", cfg))
		default:
			panic(fmt.Errorf("unknown object type: %s", obj.GetObjectKind().GroupVersionKind().String()))
		}
	}
}

func CreateObject(cfg string) runtime.Object {
	decode := gwapischeme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode([]byte(cfg), nil, nil)
	if err != nil {
		panic(err)
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

func (c *testConfig) compareConfigTCPServices(id string, expected string) {
	c.compareText(id, conv_helper.MarshalTCPServices(c.hconfig.TCPServices().BuildSortedItems()...), expected)
}

func (c *testConfig) compareConfigBacks(id string, expected string) {
	c.compareText(id, conv_helper.MarshalBackendsWeight(c.hconfig.Backends().BuildSortedItems()...), expected)
}
