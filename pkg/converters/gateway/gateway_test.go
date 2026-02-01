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

package gateway

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
	"github.com/stretchr/testify/assert"
	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapischeme "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/scheme"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

type testCaseSync struct {
	id             string
	resConfig      []string
	config         func(c *testConfig)
	expFullSync    bool
	expDefaultHost string
	expHosts       string
	expTCPServices string
	expBackends    string
	expGWStatus    string
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
			expDefaultHost: ``, // route points to a missing gw; not our
			expBackends:    ``, // business, so just missing routing configs.
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
			expLogging: `
WARN Route kinds (gateway.networking.k8s.io/OtherRoute) not supported on Gateway 'default/web' listener 'l2'
`,
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
WARN Route kinds (gateway.networking.k8s.io/OtherRoute) not supported on Gateway 'default/web' listener 'l1'
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
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Same
  - name: h2
    protocol: HTTP
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
				c.createGateway2("default/web", "l1:443", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceSecret, "default/crt1")
			},
			expFullSync: false,
		},
		{
			id: "remove-secret-2",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1:443", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceSecret, "default/crt")
			},
			expFullSync: true,
		},
		{
			id: "add-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1:443", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.createSecret1("default/crt1")
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceSecret, "default/crt1")
			},
			expFullSync: false,
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': secret not found: 'default/crt'
`,
		},
		{
			id: "add-secret-2",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1:443", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceSecret, "default/crt")
			},
			expFullSync: true,
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': secret not found: 'default/crt'
`,
		},
		{
			id: "update-secret-1",
			config: func(c *testConfig) {
				c.createGateway2("default/web", "l1:443", "crt")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				c.cache.SecretTLSPath["default/crt"] = "/tls/crt.pem"
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceSecret, "default/crt")
			},
			expFullSync: true,
		},
		{
			id: "remove-service-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceService, "default/echoserver1")
			},
			expFullSync: false,
		},
		{
			id: "remove-service-2",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceService, "default/echoserver")
			},
			expFullSync: true,
		},
		{
			id: "add-service-1",
			config: func(c *testConfig) {
				c.createGateway1("default/web", "l1")
				c.createHTTPRoute1("default/web", "web", "echoserver:8080")
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceService, "default/echoserver")
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
				tracker.TrackChanges(c.cache.Changed.Links, convtypes.ResourceEndpoints, "default/echoserver")
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
	defaultBackend := `
- id: default_pg__tcprule0
  endpoints:
  - ip: 172.17.0.11
    port: 15432
    weight: 128
  modetcp: true
`
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
			expBackends: defaultBackend,
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
	defaultHost := `
hostname: <default>
defaultback: _error404
paths: []
tls:
  tlsfilename: /tls/default/crt2.pem
`
	defaultHTTPSHost := `
hostname: <default>
defaultback: _error404
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
				c.createGateway2("default/web", "l1:443", "crt")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': secret not found: 'default/crt'
`,
			expBackends: defaultBackend,
		},
		{
			id: "tls-listener-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt")
				c.createGateway2("default/web", "l1:443", "crt")
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
				c.createGateway2("default/web", "l1:443", "crt,crt2")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
			},
			expDefaultHost: defaultHTTPSHost,
			expBackends:    defaultBackend,
		},
		{
			id: "tls-listener-no-refs-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt1")
				g := c.createGateway2("default/web", "l1:443", "crt1")
				c.createHTTPRoute1("default/web", "web:l1", "echoserver:8080")
				c.createService1("default/echoserver", "8080", "172.17.0.11")
				g.Spec.Listeners[0].TLS.CertificateRefs = nil
			},
			expLogging: `
WARN skipping certificate reference on Gateway 'default/web' listener 'l1': listener has no certificate reference
`,
			expBackends: defaultBackend,
		},
		{
			id: "tls-listener-reassign-crt-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt1")
				c.createSecret1("default/crt2")
				c.createGateway2("default/web", "l1:443,l2:443", "crt1").Spec.Listeners[1].TLS.CertificateRefs[0].Name = "crt2"
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
			expDefaultHost: defaultHost,
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
				g := c.createGateway1("default/web", "l1:8443")
				r := c.createTLSRoute1("default/web", "web", "echoserver:8443")
				c.createService1("default/echoserver", "8443", "172.17.0.11")
				g.Spec.Listeners[0].TLS = &gatewayv1.ListenerTLSConfig{Mode: &passthrough}
				r.Spec.Hostnames = append(r.Spec.Hostnames, "domain.local")
			},
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web__tlsrule0
  passthrough: true
`,
			expBackends: `
- id: default_web__tlsrule0
  endpoints:
  - ip: 172.17.0.11
    port: 8443
    weight: 128
  modetcp: true
`,
		},
		{
			id: "passthrough-dup-1",
			config: func(c *testConfig) {
				g := c.createGateway1("default/web", "l1:8443,l2:8443")
				r1 := c.createTLSRoute1("default/web1", "web:l1", "echoserver1:8443")
				r2 := c.createTLSRoute1("default/web2", "web:l2", "echoserver2:8443")
				c.createService1("default/echoserver1", "8443", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				g.Spec.Listeners[0].TLS = &gatewayv1.ListenerTLSConfig{Mode: &passthrough}
				g.Spec.Listeners[1].TLS = &gatewayv1.ListenerTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
			},
			expLogging: `
WARN skipping redeclared ssl-passthrough hostname 'domain.local' on TLSRoute 'default/web2'
`,
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web1__tlsrule0
  passthrough: true
`,
			expBackends: `
- id: default_web1__tlsrule0
  endpoints:
  - ip: 172.17.0.11
    port: 8443
    weight: 128
  modetcp: true
- id: default_web2__tlsrule0
  endpoints:
  - ip: 172.17.0.12
    port: 8443
    weight: 128
  modetcp: true
`,
		},
		{
			// HTTPRoute is always processed first, so we have test on one single direction
			id: "passthrough-having-matching-http-1",
			config: func(c *testConfig) {
				c.createSecret1("default/crt")
				g := c.createGateway2("default/web", "l0:8443,l1:8443", "crt")
				r1 := c.createHTTPRoute1("default/web", "web:l0", "echoserver1:8080")
				r2 := c.createTLSRoute1("default/web", "web:l1", "echoserver2:8443")
				c.createService1("default/echoserver1", "8080", "172.17.0.11")
				c.createService1("default/echoserver2", "8443", "172.17.0.12")
				g.Spec.Listeners[0].Protocol = gatewayv1.HTTPSProtocolType
				g.Spec.Listeners[1].TLS = &gatewayv1.ListenerTLSConfig{Mode: &passthrough}
				r1.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
				r2.Spec.Hostnames = []gatewayv1.Hostname{"domain.local"}
			},
			expLogging: `
WARN skipping hostname 'domain.local' on TLSRoute 'default/web': hostname already declared as HTTP
`,
			expHosts: `
- hostname: domain.local
  paths:
  - path: /
    match: prefix
    backend: default_web__rule0
  tls:
    tlsfilename: /tls/default/crt.pem
`,
			expDefaultHost: `
hostname: <default>
defaultback: _error404
paths: []
tls:
  tlsfilename: /tls/default/crt.pem
`,
			expBackends: `
- id: default_web__rule0
  endpoints:
  - ip: 172.17.0.11
    port: 8080
    weight: 128
- id: default_web__tlsrule0
  endpoints:
  - ip: 172.17.0.12
    port: 8443
    weight: 128
  modetcp: true
`,
		},
	})
}

func TestGatewayClassStatus(t *testing.T) {
	c := setup(t)
	gwcls := c.createGatewayClass("haproxy")
	_ = c.createConverter().SyncFull()
	c.compareStatus("gatewayclass", gwcls, `
conditions:
- lastTransitionTime: "-"
  message: Class accepted by HAProxy Ingress
  reason: Accepted
  status: "True"
  type: Accepted
`)
}

func TestGatewayStatus(t *testing.T) {
	testCases := map[string]struct {
		create     func(c *testConfig) *gatewayv1.Gateway
		expLogging string
		expStatus  string
	}{
		"test01": {
			create: func(c *testConfig) *gatewayv1.Gateway {
				return c.createGateway1("default/gateway1", "")
			},
			expStatus: `
conditions:
- lastTransitionTime: "-"
  message: Gateway accepted by HAProxy Ingress
  reason: Accepted
  status: "True"
  type: Accepted
- lastTransitionTime: "-"
  message: ""
  reason: Programmed
  status: "True"
  type: Programmed
`,
		},
		"test02": {
			create: func(c *testConfig) *gatewayv1.Gateway {
				return c.createGateway1("default/gateway1", "l1")
			},
			expStatus: `
conditions:
- lastTransitionTime: "-"
  message: Gateway accepted by HAProxy Ingress
  reason: Accepted
  status: "True"
  type: Accepted
- lastTransitionTime: "-"
  message: ""
  reason: Programmed
  status: "True"
  type: Programmed
listeners:
- attachedRoutes: 0
  conditions:
  - lastTransitionTime: "-"
    message: ""
    reason: ResolvedRefs
    status: "True"
    type: ResolvedRefs
  - lastTransitionTime: "-"
    message: ""
    reason: Programmed
    status: "True"
    type: Programmed
  - lastTransitionTime: "-"
    message: ""
    reason: Accepted
    status: "True"
    type: Accepted
  - lastTransitionTime: "-"
    message: ""
    reason: NoConflicts
    status: "False"
    type: Conflicted
  name: l1
  supportedKinds:
  - kind: HTTPRoute
`,
		},
		"test03": {
			create: func(c *testConfig) *gatewayv1.Gateway {
				return c.createGateway2("default/gateway1", "l1:443", "notfound")
			},
			expLogging: `WARN skipping certificate reference on Gateway 'default/gateway1' listener 'l1': secret not found: 'default/notfound'`,
			expStatus: `
conditions:
- lastTransitionTime: "-"
  message: Gateway accepted by HAProxy Ingress
  reason: Accepted
  status: "True"
  type: Accepted
- lastTransitionTime: "-"
  message: ""
  reason: Programmed
  status: "True"
  type: Programmed
listeners:
- attachedRoutes: 0
  conditions:
  - lastTransitionTime: "-"
    message: 'secret not found: ''default/notfound'''
    reason: InvalidCertificateRef
    status: "False"
    type: ResolvedRefs
  - lastTransitionTime: "-"
    message: ResolvedRefs condition has a failure status
    reason: Pending
    status: "False"
    type: Programmed
  name: l1
  supportedKinds:
  - kind: HTTPRoute
`,
		},
		"test04": {
			create: func(c *testConfig) *gatewayv1.Gateway {
				gw := c.createGateway1("default/gateway1", "l1")
				gw.Spec.Listeners[0].AllowedRoutes.Kinds = []gatewayv1.RouteGroupKind{{Kind: "Invalid"}}
				return gw
			},
			expLogging: `
WARN None of the configured route kinds are supported on Gateway 'default/gateway1' listener 'l1': gateway.networking.k8s.io/Invalid
`,
			expStatus: `
conditions:
- lastTransitionTime: "-"
  message: Gateway accepted by HAProxy Ingress
  reason: Accepted
  status: "True"
  type: Accepted
- lastTransitionTime: "-"
  message: ""
  reason: Programmed
  status: "True"
  type: Programmed
listeners:
- attachedRoutes: 0
  conditions:
  - lastTransitionTime: "-"
    message: None of the configured route kinds are supported
    reason: InvalidRouteKinds
    status: "False"
    type: ResolvedRefs
  - lastTransitionTime: "-"
    message: ResolvedRefs condition has a failure status
    reason: Pending
    status: "False"
    type: Programmed
  name: l1
  supportedKinds: []
`,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			c := setup(t)
			_ = c.createGatewayClass("haproxy")
			gw := test.create(c)
			_ = c.createConverter().SyncFull()
			c.compareStatus("gateway", gw, test.expStatus)
			c.logger.CompareLogging(test.expLogging)
		})
	}
}

func TestMatchingHostnames(t *testing.T) {
	testCases := map[string]struct {
		listenerTCPProto bool
		listenerHostname *gatewayv1.Hostname
		routerHostnames  []gatewayv1.Hostname
		expMatch         bool
		expHostnames     []gatewayv1.Hostname
	}{
		//
		// TCP listener
		"test_TCP_01": {
			listenerTCPProto: true,
			listenerHostname: nil,
			routerHostnames:  nil,
			expMatch:         true,
			expHostnames:     nil,
		},
		//
		// HTTP and TLS listeners
		//
		// listener without restriction
		"test_TLSHTTP_any_01": {
			listenerHostname: nil,
			routerHostnames:  nil,
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"*"},
		},
		"test_TLSHTTP_any_02": {
			listenerHostname: nil,
			routerHostnames:  []gatewayv1.Hostname{"example.com", "sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"example.com", "sub.example.com"},
		},
		//
		// listener with "example.com" hostname
		"test_TLSHTTP_domain_01": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  nil,
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"example.com"},
		},
		"test_TLSHTTP_domain_02": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"example.com"},
		},
		"test_TLSHTTP_domain_03": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "*.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"example.com"},
		},
		"test_TLSHTTP_domain_04": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  []gatewayv1.Hostname{"*.example.com", "sub.example.com"},
			expMatch:         false,
			expHostnames:     nil,
		},
		"test_TLSHTTP_domain_05": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "sub.example.com", "some.sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"example.com"},
		},
		"test_TLSHTTP_domain_06": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "example.com", "*.example.com", "*.example.com", "sub.example.com", "sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"example.com"},
		},
		"test_TLSHTTP_domain_07": {
			listenerHostname: ptr.To(gatewayv1.Hostname("example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.net", "*.example.net", "sub.example.net", "some.sub.example.net"},
			expMatch:         false,
			expHostnames:     nil,
		},
		//
		// listener with "sub.example.com" hostname
		"test_TLSHTTP_subdomain_01": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  nil,
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"sub.example.com"},
		},
		"test_TLSHTTP_subdomain_02": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com"},
			expMatch:         false,
			expHostnames:     nil,
		},
		"test_TLSHTTP_subdomain_03": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "*.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"sub.example.com"},
		},
		"test_TLSHTTP_subdomain_04": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"*.example.com", "sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"sub.example.com"},
		},
		"test_TLSHTTP_subdomain_05": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "sub.example.com", "some.sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"sub.example.com"},
		},
		"test_TLSHTTP_subdomain_06": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "example.com", "*.example.com", "*.example.com", "sub.example.com", "sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"sub.example.com"},
		},
		"test_TLSHTTP_subdomain_07": {
			listenerHostname: ptr.To(gatewayv1.Hostname("sub.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.net", "*.example.net", "sub.example.net", "some.sub.example.net"},
			expMatch:         false,
			expHostnames:     nil,
		},
		//
		// listener with "*.example.com" hostname
		"test_TLSHTTP_wildcard_01": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  nil,
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"*.example.com"},
		},
		"test_TLSHTTP_wildcard_02": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com"},
			expMatch:         false,
			expHostnames:     nil,
		},
		"test_TLSHTTP_wildcard_03": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "*.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"*.example.com"},
		},
		"test_TLSHTTP_wildcard_04": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"*.example.com", "sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"*.example.com", "sub.example.com"},
		},
		"test_TLSHTTP_wildcard_05": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "sub.example.com", "some.sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"sub.example.com", "some.sub.example.com"},
		},
		"test_TLSHTTP_wildcard_06": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.com", "example.com", "*.example.com", "*.example.com", "sub.example.com", "sub.example.com"},
			expMatch:         true,
			expHostnames:     []gatewayv1.Hostname{"*.example.com", "sub.example.com"},
		},
		"test_TLSHTTP_wildcard_07": {
			listenerHostname: ptr.To(gatewayv1.Hostname("*.example.com")),
			routerHostnames:  []gatewayv1.Hostname{"example.net", "*.example.net", "sub.example.net", "some.sub.example.net"},
			expMatch:         false,
			expHostnames:     nil,
		},
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			var protocols []gatewayv1.ProtocolType
			if test.listenerTCPProto {
				protocols = []gatewayv1.ProtocolType{gatewayv1.TCPProtocolType}
			} else {
				protocols = []gatewayv1.ProtocolType{gatewayv1.TLSProtocolType, gatewayv1.HTTPProtocolType}
			}
			for _, protocol := range protocols {
				t.Run("protocol="+string(protocol), func(t *testing.T) {
					c := setup(t)
					conv := c.createConverter()
					listener := gatewayv1.Listener{}
					listener.Protocol = protocol
					listener.Hostname = test.listenerHostname
					match, hostnames := conv.checkMatchingHostnames(&listener, test.routerHostnames)
					assert.Equal(t, test.expMatch, match, "hostname match")
					assert.Equal(t, test.expHostnames, hostnames, "hostname list")
				})
			}
		})
	}
}

func runTestSync(t *testing.T, testCases []testCaseSync) {
	for _, test := range testCases {
		t.Run(test.id, func(t *testing.T) {
			c := setup(t)
			_ = c.createGatewayClass("haproxy")

			c.createGatewayResources(test.resConfig)
			if test.config != nil {
				test.config(c)
			}
			// ch.Links reflects changes made by the watcher
			hasChanges := len(c.cache.Changed.Links) > 0
			conv := c.createConverter()
			_ = conv.SyncFull()

			if hasChanges {
				c.hconfig.Commit()
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
				if test.expGWStatus != "" {
					var status []string
					for _, gw := range c.cache.GatewayList {
						status = append(status, conv_helper.MarshalStatus(gw))
					}
					c.compareText(test.id, strings.Join(status, "\n---\n"), test.expGWStatus)
				}
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

func (c *testConfig) createConverter() *converter {
	return NewGatewayConverter(
		&convtypes.ConverterOptions{
			Cache:      c.cache,
			Logger:     c.logger,
			Tracker:    c.tracker,
			HasGateway: true,
		},
		c.hconfig,
		c.cache.LegacySwapObjects(),
		nil,
	).(*converter)
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

func (c *testConfig) createService1(name, port, ip string) (*api.Service, []*discoveryv1.EndpointSlice) {
	svc, eps := conv_helper.CreateService(name, port, ip)
	c.cache.SvcList = append(c.cache.SvcList, svc)
	c.cache.EpsList[name] = eps
	return svc, eps
}

func (c *testConfig) createGatewayClass(name string) *gatewayv1.GatewayClass {
	gwcls := CreateObject(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: ` + name + `
spec:
  controllerName: haproxy-ingress.github.io/controller`).(*gatewayv1.GatewayClass)
	c.cache.GatewayClassMap[gatewayv1.ObjectName(gwcls.Name)] = gwcls
	return gwcls
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
		if listener == "" {
			continue
		}
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
		} else {
			lport = 80
		}
		l.Name = gatewayv1.SectionName(lname)
		l.Port = lport
		// TODO hardcoded for now, use integration test's framework instead in the future
		switch lport {
		case 5432:
			l.Protocol = gatewayv1.TCPProtocolType
		case 8443:
			l.Protocol = gatewayv1.TLSProtocolType
		case 443:
			l.Protocol = gatewayv1.HTTPSProtocolType
		default:
			l.Protocol = gatewayv1.HTTPProtocolType
		}
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
		listener := &gw.Spec.Listeners[l]
		if listener.Protocol != gatewayv1.HTTPSProtocolType && listener.Protocol != gatewayv1.TLSProtocolType {
			continue
		}
		tls := &gatewayv1.ListenerTLSConfig{
			Mode: ptr.To(gatewayv1.TLSModeTerminate),
		}
		for _, s := range strings.Split(secretName, ",") {
			tls.CertificateRefs = append(tls.CertificateRefs, gatewayv1.SecretObjectReference{
				Name: gatewayv1.ObjectName(s),
			})
		}
		listener.TLS = tls
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

func (c *testConfig) createTLSRoute1(name, parent, services string) *gatewayv1alpha2.TLSRoute {
	r := CreateObject(c.createRoute("TLSRoute", "v1alpha2", name, parent, services)).(*gatewayv1alpha2.TLSRoute)
	c.cache.TLSRouteList = append(c.cache.TLSRouteList, r)
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
	var host *hatypes.Host
	if f := c.hconfig.Frontends().Items(); len(f) > 0 {
		host = f[0].DefaultHost()
	}
	if host != nil {
		c.compareText(id, conv_helper.MarshalHost(host), expected)
	} else {
		c.compareText(id, "[]", expected)
	}
}

func (c *testConfig) compareConfigHosts(id string, expected string) {
	var hosts []*hatypes.Host
	if f := c.hconfig.Frontends().Items(); len(f) > 0 {
		hosts = f[0].BuildSortedHosts()
	}
	c.compareText(id, conv_helper.MarshalHosts(hosts...), expected)
}

func (c *testConfig) compareConfigTCPServices(id string, expected string) {
	c.compareText(id, conv_helper.MarshalTCPServices(c.hconfig.TCPServices().BuildSortedItems()...), expected)
}

func (c *testConfig) compareConfigBacks(id string, expected string) {
	c.compareText(id, conv_helper.MarshalBackendsWeight(c.hconfig.Backends().BuildSortedItems()...), expected)
}

func (c *testConfig) compareStatus(id string, obj client.Object, expected string) {
	c.compareText(id, conv_helper.MarshalStatus(obj), expected)
}
