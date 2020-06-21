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

package ingress

import (
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/diff"
	yaml "gopkg.in/yaml.v2"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/annotations"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/tracker"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  CORE INGRESS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

func TestSyncSvcNotFound(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "notfound:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths: []`)

	c.compareConfigBack(defaultBackendConfig)

	c.logger.CompareLogging(`
WARN skipping backend config of ingress 'default/echo': service not found: 'default/notfound'`)
}

func TestSyncDefaultSvcNotFound(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.cache.SvcList = []*api.Service{}
	c.createSvc1Auto()
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080`)

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080`)

	c.logger.CompareLogging(`
ERROR error reading default service: service not found: 'system/default'`)
}

func TestSyncSvcPortNotFound(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "echo:non"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths: []
`)

	c.compareConfigBack(`
- id: _default_backend
  endpoints:
  - ip: 172.17.0.99
    port: 8080
`)

	c.logger.CompareLogging(`
WARN skipping backend config of ingress 'default/echo': port not found: 'non'
`)
}

func TestSyncSvcNamedPort(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo", "svcport:8080:http", "172.17.1.101")
	c.Sync(
		c.createIng1("default/echo1", "echo1.example.com", "/", "echo:http"),
		c.createIng1("default/echo2", "echo2.example.com", "/", "echo:svcport"),
		c.createIng1("default/echo3", "echo3.example.com", "/", "echo:8080"),
		c.createIng1("default/echo4", "echo4.example.com", "/", "echo:9000"),
	)

	c.compareConfigFront(`
- hostname: echo1.example.com
  paths:
  - path: /
    backend: default_echo_http
- hostname: echo2.example.com
  paths:
  - path: /
    backend: default_echo_http
- hostname: echo3.example.com
  paths:
  - path: /
    backend: default_echo_http
- hostname: echo4.example.com
  paths: []
`)

	c.compareConfigBack(`
- id: default_echo_http
  endpoints:
  - ip: 172.17.1.101
    port: 8080
- id: _default_backend
  endpoints:
  - ip: 172.17.0.99
    port: 8080
`)

	c.logger.CompareLogging(`
WARN skipping backend config of ingress 'default/echo4': port not found: '9000'
`)
}

func TestSyncSvcUpstream(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	svc, _ := c.createSvc1Ann("default/echo", "8080", "172.17.1.101,172.17.1.102,172.17.1.103", map[string]string{
		"ingress.kubernetes.io/service-upstream": "true",
	})
	svc.Spec.ClusterIP = "10.0.0.2"
	c.Sync(
		c.createIng1("default/echo1", "echo1.example.com", "/", "echo:8080"),
	)

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 10.0.0.2
    port: 8080` + defaultBackendConfig)
}

func TestSyncSingle(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo", "8080", "172.17.0.11,172.17.0.28")
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080`)

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
  - ip: 172.17.0.28
    port: 8080` + defaultBackendConfig)
}

func TestSyncReuseBackend(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo", "8080", "172.17.0.10,172.17.0.11")
	c.Sync(
		c.createIng1("default/ing1", "svc1.example.com", "/", "echo:8080"),
		c.createIng1("default/ing2", "svc2.example.com", "/app", "echo:8080"),
	)

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.10
    port: 8080
  - ip: 172.17.0.11
    port: 8080` + defaultBackendConfig)
}

func TestSyncReuseHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo1", "8080", "172.17.0.21")
	c.createSvc1("default/echo2", "8080", "172.17.0.22,172.17.0.23")
	c.Sync(
		c.createIng1("default/echo1", "echo.example.com", "/path1", "echo1:8080"),
		c.createIng1("default/echo2", "echo.example.com", "/path2", "echo2:8080"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /path2
    backend: default_echo2_8080
  - path: /path1
    backend: default_echo1_8080`)
}

func TestSyncNoEndpoint(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo", "8080", "")
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080`)

	c.compareConfigBack(`
- id: default_echo_8080` + defaultBackendConfig)
}

func TestSyncInvalidEndpoint(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	delete(c.cache.EpList, "default/echo")
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080`)

	c.compareConfigBack(`
- id: default_echo_8080` + defaultBackendConfig)

	c.logger.CompareLogging(`
ERROR error adding endpoints of service 'default/echo': could not find endpoints for service 'default/echo'`)
}

func TestSyncDrainSupport(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	svc, ep := c.createSvc1("default/echo", "http:8080:http", "172.17.1.101,172.17.1.102")
	svcName := svc.Namespace + "/" + svc.Name
	ss := &ep.Subsets[0]
	addr := ss.Addresses
	ss.Addresses = []api.EndpointAddress{addr[0]}
	ss.NotReadyAddresses = []api.EndpointAddress{addr[1]}
	pod1 := c.createPod1("default/echo-xxxxx", "172.17.1.103", "http:8080")
	pod2 := c.createPod1("default/echo-yyyyy", "172.17.1.104", "none:8080")
	c.cache.TermPodList[svcName] = []*api.Pod{pod1, pod2}

	c.cache.Changed.GlobalNew = map[string]string{"drain-support": "true"}
	c.Sync(
		c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_http
`)
	c.compareConfigBack(`
- id: default_echo_http
  endpoints:
  - ip: 172.17.1.101
    port: 8080
  - ip: 172.17.1.102
    port: 8080
    drain: true
  - ip: 172.17.1.103
    port: 8080
    drain: true
- id: _default_backend
  endpoints:
  - ip: 172.17.0.99
    port: 8080
`)

	c.logger.CompareLogging("WARN skipping endpoint 172.17.1.104 of service default/echo: port 'http' was not found")
}

func TestSyncRootPathLast(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(
		c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"),
		c.createIng1("default/echo", "echo.example.com", "/app", "echo:8080"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app
    backend: default_echo_8080
  - path: /
    backend: default_echo_8080`)
}

func TestSyncHostSorted(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo1", "8080", "172.17.0.11")
	c.createSvc1("default/echo2", "8080", "172.17.0.12")
	c.createSvc1("default/echo3", "8080", "172.17.0.13")
	c.Sync(
		c.createIng1("default/echo1", "echo-B.example.com", "/", "echo1:8080"),
		c.createIng1("default/echo2", "echo-A.example.com", "/", "echo2:8080"),
		c.createIng1("default/echo3", "echo-C.example.com", "/", "echo3:8080"),
	)

	c.compareConfigFront(`
- hostname: echo-A.example.com
  paths:
  - path: /
    backend: default_echo2_8080
- hostname: echo-B.example.com
  paths:
  - path: /
    backend: default_echo1_8080
- hostname: echo-C.example.com
  paths:
  - path: /
    backend: default_echo3_8080`)
}

func TestSyncBackendSorted(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo3", "8080", "172.17.0.13")
	c.createSvc1("default/echo2", "8080", "172.17.0.12")
	c.createSvc1("default/echo1", "8080", "172.17.0.11")
	c.Sync(
		c.createIng1("default/echo2", "echo.example.com", "/app2", "echo2:8080"),
		c.createIng1("default/echo1", "echo.example.com", "/app1", "echo1:8080"),
		c.createIng1("default/echo3", "echo.example.com", "/app3", "echo3:8080"),
	)

	c.compareConfigBack(`
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080
- id: default_echo3_8080
  endpoints:
  - ip: 172.17.0.13
    port: 8080` + defaultBackendConfig)
}

func TestSyncRedeclarePath(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo1", "8080", "172.17.0.11")
	c.createSvc1("default/echo2", "8080", "172.17.0.12")
	c.Sync(
		c.createIng1("default/echo1", "echo.example.com", "/p1", "echo1:8080"),
		c.createIng1("default/echo1", "echo.example.com", "/p1", "echo2:8080"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /p1
    backend: default_echo1_8080`)

	c.compareConfigBack(`
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080` + defaultBackendConfig)

	c.logger.CompareLogging(`
WARN skipping redeclared path '/p1' of ingress 'default/echo1'`)
}

func TestSyncTLSDefault(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIngTLS1("default/echo", "echo.example.com", "/", "echo:8080", ""))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/tls-default.pem`)
}

func TestSyncTLSSecretNotFound(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIngTLS1("default/echo", "echo.example.com", "/", "echo:8080", "ing-tls"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/tls-default.pem`)

	c.logger.CompareLogging(`
WARN using default certificate due to an error reading secret 'ing-tls' on ingress 'default/echo': secret not found: 'default/ing-tls'`)
}

func TestSyncTLSCustom(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.createSecretTLS1("default/tls-echo")
	c.Sync(c.createIngTLS1("default/echo", "echo.example.com", "/", "echo:8080", "tls-echo"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/default/tls-echo.pem`)
}

func TestSyncRedeclareTLS(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.createSecretTLS1("default/tls-echo1")
	c.createSecretTLS1("default/tls-echo2")
	c.Sync(c.createIngTLS1("default/echo1", "echo.example.com", "/", "echo:8080", "tls-echo1:echo.example.com;tls-echo2:echo.example.com"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/default/tls-echo1.pem`)

	c.logger.CompareLogging(`
WARN skipping TLS secret 'tls-echo2' of ingress 'default/echo1': TLS of host 'echo.example.com' was already assigned`)
}

func TestSyncRedeclareSameTLS(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.createSecretTLS1("default/tls-echo1")
	c.Sync(
		c.createIngTLS1("default/echo1", "echo.example.com", "/", "echo:8080", "tls-echo1:echo.example.com"),
		c.createIngTLS1("default/echo2", "echo.example.com", "/app", "echo:8080", "tls-echo1:echo.example.com"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app
    backend: default_echo_8080
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/default/tls-echo1.pem`)
}

func TestSyncRedeclareTLSDefaultFirst(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.createSecretTLS1("default/tls-echo1")
	c.Sync(
		c.createIngTLS1("default/echo1", "echo.example.com", "/", "echo:8080", ""),
		c.createIngTLS1("default/echo2", "echo.example.com", "/app", "echo:8080", "tls-echo1:echo.example.com"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app
    backend: default_echo_8080
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/tls-default.pem`)

	c.logger.CompareLogging(`
WARN skipping TLS secret 'tls-echo1' of ingress 'default/echo2': TLS of host 'echo.example.com' was already assigned`)
}

func TestSyncRedeclareTLSCustomFirst(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.createSecretTLS1("default/tls-echo1")
	c.Sync(
		c.createIngTLS1("default/echo1", "echo.example.com", "/", "echo:8080", "tls-echo1:echo.example.com"),
		c.createIngTLS1("default/echo2", "echo.example.com", "/app", "echo:8080", ""),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app
    backend: default_echo_8080
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/default/tls-echo1.pem`)

	c.logger.CompareLogging(`
WARN skipping default TLS secret of ingress 'default/echo2': TLS of host 'echo.example.com' was already assigned`)
}

func TestSyncInvalidTLS(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.cache.SecretTLSPath = map[string]string{}
	c.createSvc1Auto()
	c.Sync(c.createIngTLS1("default/echo", "echo.example.com", "/", "echo:8080", "tls-invalid"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080
  tls:
    tlsfilename: /tls/tls-default.pem`)

	c.logger.CompareLogging(`
WARN using default certificate due to an error reading secret 'tls-invalid' on ingress 'default/echo': secret not found: 'default/tls-invalid'`)
}

func TestSyncRootPathDefault(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/app", "echo:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app
    backend: default_echo_8080`)
}

func TestSyncPathEmpty(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng1("default/echo", "echo.example.com", "", "echo:8080"))

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080`)
}

func TestSyncBackendDefault(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng2("default/echo", "echo:8080"))

	c.compareConfigDefaultFront(`
hostname: '*'
paths:
- path: /
  backend: default_echo_8080`)

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080` + defaultBackendConfig)
}

func TestSyncBackendSvcNotFound(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng2("default/echo", "notfound:8080"))

	c.compareConfigFront(`[]`)
	c.compareConfigBack(defaultBackendConfig)

	c.logger.CompareLogging(`
WARN skipping default backend of ingress 'default/echo': service not found: 'default/notfound'`)
}

func TestSyncBackendReuseDefaultSvc(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.Sync(c.createIng1("system/defbackend", "default.example.com", "/app", "default:8080"))

	c.compareConfigFront(`
- hostname: default.example.com
  paths:
  - path: /app
    backend: _default_backend`)

	c.compareConfigDefaultFront(`[]`)
	c.compareConfigBack(defaultBackendConfig)
}

func TestSyncDefaultBackendReusedPath1(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo1", "8080", "172.17.0.11")
	c.createSvc1("default/echo2", "8080", "172.17.0.12")
	c.Sync(
		c.createIng1("default/echo1", "'*'", "/", "echo1:8080"),
		c.createIng2("default/echo2", "echo2:8080"),
	)

	c.compareConfigDefaultFront(`
hostname: '*'
paths:
- path: /
  backend: default_echo1_8080`)

	c.compareConfigBack(`
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080` + defaultBackendConfig)

	c.logger.CompareLogging(`
WARN skipping default backend of ingress 'default/echo2': path / was already defined on default host`)
}

func TestSyncDefaultBackendReusedPath2(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo1", "8080", "172.17.0.11")
	c.createSvc1("default/echo2", "8080", "172.17.0.12")
	c.Sync(
		c.createIng2("default/echo1", "echo1:8080"),
		c.createIng1("default/echo2", "'*'", "/", "echo2:8080"),
	)

	c.compareConfigDefaultFront(`
hostname: '*'
paths:
- path: /
  backend: default_echo1_8080`)

	c.compareConfigBack(`
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080` + defaultBackendConfig)

	c.logger.CompareLogging(`
WARN skipping redeclared path '/' of ingress 'default/echo2'`)
}

func TestSyncEmptyHTTP(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.Sync(c.createIng3("default/echo"))
	c.compareConfigFront(`[]`)
}

func TestSyncEmptyHost(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng1("default/echo", "", "/", "echo:8080"))

	c.compareConfigDefaultFront(`
hostname: '*'
paths:
- path: /
  backend: default_echo_8080`)
}

func TestSyncMultiNamespace(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("ns1/echo", "8080", "172.17.0.11")
	c.createSvc1("ns2/echo", "8080", "172.17.0.12")

	c.Sync(
		c.createIng1("ns1/echo", "echo.example.com", "/app1", "echo:8080"),
		c.createIng1("ns2/echo", "echo.example.com", "/app2", "echo:8080"),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app2
    backend: ns2_echo_8080
  - path: /app1
    backend: ns1_echo_8080`)

	c.compareConfigBack(`
- id: ns1_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
- id: ns2_echo_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080` + defaultBackendConfig)
}

func TestSyncPartial(t *testing.T) {
	svcDefault := [][]string{
		{"default/echo1", "8080", "172.17.0.11"},
		{"default/echo2", "8080", "172.17.0.12"},
	}
	ingDefault := [][]string{
		{"default/echo1", "echo.example.com", "/app1", "echo1:8080"},
		{"default/echo2", "echo.example.com", "/app2", "echo2:8080"},
	}
	ingTLSDefault := [][]string{
		{"default/echo1", "echo.example.com", "/app1", "echo1:8080", "tls1"},
		{"default/echo2", "echo.example.com", "/app2", "echo2:8080", "default/tls1"},
	}
	secTLSDefault := [][]string{
		{"default/tls1"},
	}
	expFrontDefault := `
- hostname: echo.example.com
  paths:
  - path: /app2
    backend: default_echo2_8080
  - path: /app1
    backend: default_echo1_8080`
	expBackDefault := `
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080` + defaultBackendConfig
	explogging := `INFO-V(2) changed hosts: [echo.example.com]; backends: [default_echo1_8080 default_echo2_8080]`

	testCases := []struct {
		//
		svc, ing, ingtls, sec [][]string
		//
		svcAdd, svcUpd, svcDel [][]string
		ingAdd, ingUpd, ingDel [][]string
		secAdd, secUpd, secDel [][]string
		//
		endpoints [][]string
		//
		expFront string
		expBack  string
		logging  string
	}{
		// 0
		{
			svc: svcDefault,
			ing: ingDefault,
			ingAdd: [][]string{
				{"default/echo3", "echo.example.com", "/app33", "echo2:8080"},
			},
			expFront: `
- hostname: echo.example.com
  paths:
  - path: /app33
    backend: default_echo2_8080
  - path: /app2
    backend: default_echo2_8080
  - path: /app1
    backend: default_echo1_8080`,
			expBack: expBackDefault,
		},
		// 1
		{
			svc: svcDefault,
			ing: ingDefault,
			ingUpd: [][]string{
				{"default/echo1", "echo.example.com", "/app11", "echo1:8080"},
			},
			logging: explogging,
			expFront: `
- hostname: echo.example.com
  paths:
  - path: /app2
    backend: default_echo2_8080
  - path: /app11
    backend: default_echo1_8080`,
			expBack: expBackDefault,
		},
		// 2
		{
			svc: svcDefault,
			ing: ingDefault,
			ingDel: [][]string{
				{"default/echo1", "echo.example.com", "/app1", "echo1:8080"},
			},
			logging: explogging,
			expFront: `
- hostname: echo.example.com
  paths:
  - path: /app2
    backend: default_echo2_8080`,
			expBack: `
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080` + defaultBackendConfig,
		},
		// 3
		{
			svc: svcDefault,
			ing: ingDefault,
			ingAdd: [][]string{
				{"default/echo3", "echo3.example.com", "/app33", "echo2:8080"},
			},
			ingDel: [][]string{
				{"default/echo2", "echo.example.com", "/app2", "echo2:8080"},
			},
			logging: explogging,
			expFront: `
- hostname: echo.example.com
  paths:
  - path: /app1
    backend: default_echo1_8080
- hostname: echo3.example.com
  paths:
  - path: /app33
    backend: default_echo2_8080`,
			expBack: expBackDefault,
		},
		// 4
		{
			svc: svcDefault,
			ing: [][]string{
				{"default/echo1", "echo.example.com", "/app1", "echo1:8080"},
				{"default/echo2", "echo.example.com", "/app2", "echo2:8080"},
				{"default/echo3", "echo.example.com", "/app3", "echo3:8080"},
			},
			svcAdd: [][]string{
				{"default/echo3", "8080", "172.17.0.13"},
			},
			logging: explogging,
			expFront: `
- hostname: echo.example.com
  paths:
  - path: /app3
    backend: default_echo3_8080
  - path: /app2
    backend: default_echo2_8080
  - path: /app1
    backend: default_echo1_8080`,
			expBack: `
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080
- id: default_echo3_8080
  endpoints:
  - ip: 172.17.0.13
    port: 8080` + defaultBackendConfig,
		},
		// 5
		{
			svc: svcDefault,
			ing: ingDefault,
			svcUpd: [][]string{
				{"default/echo2", "8080", "172.17.0.22"},
			},
			logging:  explogging,
			expFront: expFrontDefault,
			expBack: `
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.22
    port: 8080` + defaultBackendConfig,
		},
		// 6
		{
			svc: svcDefault,
			ing: ingDefault,
			svcDel: [][]string{
				{"default/echo2", "8080", "172.17.0.12"},
			},
			logging: explogging + `
WARN skipping backend config of ingress 'default/echo2': service not found: 'default/echo2'`,
			expFront: `
- hostname: echo.example.com
  paths:
  - path: /app1
    backend: default_echo1_8080`,
			expBack: `
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080` + defaultBackendConfig,
		},
		// 7
		{
			svc: svcDefault,
			ing: ingDefault,
			endpoints: [][]string{
				{"default/echo1", "8080", "172.17.0.21,172.17.0.22,172.17.0.23"},
			},
			logging:  explogging,
			expFront: expFrontDefault,
			expBack: `
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.21
    port: 8080
  - ip: 172.17.0.22
    port: 8080
  - ip: 172.17.0.23
    port: 8080
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080` + defaultBackendConfig,
		},
		// 8
		{
			svc:     svcDefault,
			ingtls:  ingTLSDefault,
			secAdd:  secTLSDefault,
			logging: explogging,
			expFront: expFrontDefault + `
  tls:
    tlsfilename: /tls/default/tls1.pem`,
			expBack: expBackDefault,
		},
		// 9
		{
			svc:    svcDefault,
			sec:    secTLSDefault,
			ingtls: ingTLSDefault,
			secDel: secTLSDefault,
			logging: explogging + `
WARN using default certificate due to an error reading secret 'tls1' on ingress 'default/echo1': secret not found: 'default/tls1'
WARN using default certificate due to an error reading secret 'default/tls1' on ingress 'default/echo2': secret not found: 'default/tls1'`,
			expFront: expFrontDefault + `
  tls:
    tlsfilename: /tls/tls-default.pem`,
			expBack: expBackDefault,
		},
	}

	for _, test := range testCases {
		c := setup(t)

		for _, svc := range test.svc {
			c.createSvc1(svc[0], svc[1], svc[2])
		}
		for _, ing := range test.ing {
			c.cache.IngList = append(c.cache.IngList, c.createIng1(ing[0], ing[1], ing[2], ing[3]))
		}
		for _, ing := range test.ingtls {
			c.cache.IngList = append(c.cache.IngList, c.createIngTLS1(ing[0], ing[1], ing[2], ing[3], ing[4]))
		}
		for _, sec := range test.sec {
			c.cache.SecretTLSPath[sec[0]] = "/tls/" + sec[0] + ".pem"
		}
		c.Sync()
		c.logger.Logging = []string{}

		ings := func(slice *[]*extensions.Ingress, params [][]string) {
			for _, param := range params {
				*slice = append(*slice, c.createIng1(param[0], param[1], param[2], param[3]))
			}
		}
		svcs := func(slice *[]*api.Service, params [][]string) {
			for _, param := range params {
				svc, _ := c.createSvc1(param[0], param[1], param[2])
				*slice = append(*slice, svc)
			}
		}
		secs := func(slice *[]*api.Secret, params [][]string) {
			for _, param := range params {
				secret := c.createSecretTLS2(param[0])
				*slice = append(*slice, secret)
			}
		}
		endp := func(slice *[]*api.Endpoints, params [][]string) {
			for _, param := range params {
				_, ep := conv_helper.CreateService(param[0], param[1], param[2])
				*slice = append(*slice, ep)
			}
		}
		ings(&c.cache.Changed.IngressesAdd, test.ingAdd)
		ings(&c.cache.Changed.IngressesUpd, test.ingUpd)
		ings(&c.cache.Changed.IngressesDel, test.ingDel)
		svcs(&c.cache.Changed.ServicesAdd, test.svcAdd)
		svcs(&c.cache.Changed.ServicesUpd, test.svcUpd)
		svcs(&c.cache.Changed.ServicesDel, test.svcDel)
		secs(&c.cache.Changed.SecretsAdd, test.secAdd)
		secs(&c.cache.Changed.SecretsUpd, test.secUpd)
		secs(&c.cache.Changed.SecretsDel, test.secDel)
		endp(&c.cache.Changed.Endpoints, test.endpoints)
		c.Sync()

		c.compareConfigFront(test.expFront)
		c.compareConfigBack(test.expBack)
		c.logger.CompareLogging(test.logging)

		c.teardown()
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  ANNOTATIONS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

func TestSyncAnnFront(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(
		c.createIng1Ann("default/echo", "echo.example.com", "/", "echo:8080", map[string]string{
			"ingress.kubernetes.io/app-root": "/app",
		}),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /
    backend: default_echo_8080
  rootredirect: /app`)
}

func TestSyncAnnFrontsConflict(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(
		c.createIng1Ann("default/echo1", "echo.example.com", "/", "echo:8080", map[string]string{
			"ingress.kubernetes.io/timeout-client": "1s",
		}),
		c.createIng1Ann("default/echo2", "echo.example.com", "/app", "echo:8080", map[string]string{
			"ingress.kubernetes.io/timeout-client": "2s",
		}),
	)

	c.compareConfigFront(`
- hostname: echo.example.com
  paths:
  - path: /app
    backend: default_echo_8080
  - path: /
    backend: default_echo_8080`)
}

func TestSyncAnnFronts(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(
		c.createIng1Ann("default/echo1", "echo1.example.com", "/app1", "echo:8080", map[string]string{
			"ingress.kubernetes.io/timeout-client": "1s",
		}),
		c.createIng1Ann("default/echo2", "echo2.example.com", "/app2", "echo:8080", map[string]string{
			"ingress.kubernetes.io/timeout-client": "2s",
		}),
	)

	c.compareConfigFront(`
- hostname: echo1.example.com
  paths:
  - path: /app1
    backend: default_echo_8080
- hostname: echo2.example.com
  paths:
  - path: /app2
    backend: default_echo_8080`)
}

func TestSyncAnnFrontDefault(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.cache.Changed.GlobalNew = map[string]string{"timeout-client": "1s"}
	c.Sync(
		c.createIng1Ann("default/echo1", "echo1.example.com", "/app", "echo:8080", map[string]string{
			"ingress.kubernetes.io/timeout-client": "2s",
		}),
		c.createIng1Ann("default/echo2", "echo2.example.com", "/app", "echo:8080", map[string]string{
			"ingress.kubernetes.io/timeout-client": "1s",
		}),
		c.createIng1Ann("default/echo3", "echo3.example.com", "/app", "echo:8080", map[string]string{}),
	)

	c.compareConfigFront(`
- hostname: echo1.example.com
  paths:
  - path: /app
    backend: default_echo_8080
- hostname: echo2.example.com
  paths:
  - path: /app
    backend: default_echo_8080
- hostname: echo3.example.com
  paths:
  - path: /app
    backend: default_echo_8080`)
}

func TestSyncAnnBack(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1Auto()
	c.Sync(c.createIng1Ann("default/echo", "echo.example.com", "/", "echo:8080", map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	}))

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
  balancealgorithm: leastconn` + defaultBackendConfig)
}

func TestSyncAnnBackSvc(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1AutoAnn(map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	})
	c.Sync(c.createIng1("default/echo", "echo.example.com", "/", "echo:8080"))

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
  balancealgorithm: leastconn` + defaultBackendConfig)
}

func TestSyncAnnBackSvcIngConflict(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1AutoAnn(map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	})
	c.Sync(c.createIng1Ann("default/echo", "echo.example.com", "/", "echo:8080", map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "first",
	}))

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
  balancealgorithm: leastconn` + defaultBackendConfig)

	c.logger.CompareLogging(`
WARN skipping backend 'echo:8080' annotation(s) from ingress 'default/echo' due to conflict: [balance-algorithm]`)
}

func TestSyncAnnBacksSvcIng(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1AutoAnn(map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	})
	c.Sync(c.createIng1Ann("default/echo", "echo.example.com", "/", "echo:8080", map[string]string{
		"ingress.kubernetes.io/maxconn-server": "10",
	}))

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
  balancealgorithm: leastconn
  maxconnserver: 10` + defaultBackendConfig)
}

func TestSyncAnnBackDefault(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	c.createSvc1("default/echo1", "8080", "172.17.0.11")
	c.createSvc1("default/echo2", "8080", "172.17.0.12")
	c.createSvc1("default/echo3", "8080", "172.17.0.13")
	c.createSvc1Ann("default/echo4", "8080", "172.17.0.14", map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	})
	c.createSvc1Ann("default/echo5", "8080", "172.17.0.15", map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	})
	c.createSvc1Ann("default/echo6", "8080", "172.17.0.16", map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "leastconn",
	})
	c.createSvc1Ann("default/echo7", "8080", "172.17.0.17", map[string]string{
		"ingress.kubernetes.io/balance-algorithm": "roundrobin",
	})
	c.cache.Changed.GlobalNew = map[string]string{"balance-algorithm": "roundrobin"}
	c.Sync(
		c.createIng1Ann("default/echo1", "echo.example.com", "/app1", "echo1:8080", map[string]string{
			"ingress.kubernetes.io/balance-algorithm": "leastconn",
		}),
		c.createIng1Ann("default/echo2", "echo.example.com", "/app2", "echo2:8080", map[string]string{
			"ingress.kubernetes.io/balance-algorithm": "roundrobin",
		}),
		c.createIng1Ann("default/echo3", "echo.example.com", "/app3", "echo3:8080", map[string]string{}),
		c.createIng1Ann("default/echo4", "echo.example.com", "/app4", "echo4:8080", map[string]string{}),
		c.createIng1Ann("default/echo5", "echo.example.com", "/app5", "echo5:8080", map[string]string{
			"ingress.kubernetes.io/balance-algorithm": "first",
		}),
		c.createIng1Ann("default/echo6", "echo.example.com", "/app6", "echo6:8080", map[string]string{
			"ingress.kubernetes.io/balance-algorithm": "leastconn",
		}),
		c.createIng1Ann("default/echo7", "echo.example.com", "/app7", "echo7:8080", map[string]string{
			"ingress.kubernetes.io/balance-algorithm": "leastconn",
		}),
	)

	c.compareConfigBack(`
- id: default_echo1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
  balancealgorithm: leastconn
- id: default_echo2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080
  balancealgorithm: roundrobin
- id: default_echo3_8080
  endpoints:
  - ip: 172.17.0.13
    port: 8080
  balancealgorithm: roundrobin
- id: default_echo4_8080
  endpoints:
  - ip: 172.17.0.14
    port: 8080
  balancealgorithm: leastconn
- id: default_echo5_8080
  endpoints:
  - ip: 172.17.0.15
    port: 8080
  balancealgorithm: leastconn
- id: default_echo6_8080
  endpoints:
  - ip: 172.17.0.16
    port: 8080
  balancealgorithm: leastconn
- id: default_echo7_8080
  endpoints:
  - ip: 172.17.0.17
    port: 8080
  balancealgorithm: roundrobin
- id: _default_backend
  endpoints:
  - ip: 172.17.0.99
    port: 8080
  balancealgorithm: roundrobin`)

	c.logger.CompareLogging(`
WARN skipping backend 'echo5:8080' annotation(s) from ingress 'default/echo5' due to conflict: [balance-algorithm]
WARN skipping backend 'echo7:8080' annotation(s) from ingress 'default/echo7' due to conflict: [balance-algorithm]`)
}

func TestSyncAnnPassthrough(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	svc, ep := c.createSvc1("default/echo", "http:8080", "172.17.1.101")
	svcPort := api.ServicePort{
		Name:       "https",
		Port:       8443,
		TargetPort: intstr.FromInt(8443),
	}
	epPort := api.EndpointPort{
		Name:     "https",
		Port:     8443,
		Protocol: api.ProtocolTCP,
	}
	svc.Spec.Ports = append(svc.Spec.Ports, svcPort)
	ep.Subsets[0].Ports = append(ep.Subsets[0].Ports, epPort)
	c.Sync(
		c.createIng1Ann("default/echo1", "echo1.example.com", "/", "echo:8443",
			map[string]string{
				"ingress.kubernetes.io/ssl-passthrough":           "true",
				"ingress.kubernetes.io/ssl-passthrough-http-port": "8080",
			}),
		c.createIng1Ann("default/echo2", "echo2.example.com", "/", "echo:8443",
			map[string]string{
				"ingress.kubernetes.io/ssl-passthrough":           "true",
				"ingress.kubernetes.io/ssl-passthrough-http-port": "9000",
			}),
	)

	c.compareConfigFront(`
- hostname: echo1.example.com
  paths:
  - path: /
    backend: default_echo_8443
- hostname: echo2.example.com
  paths:
  - path: /
    backend: default_echo_8443
`)

	c.compareConfigBack(`
- id: default_echo_8080
  endpoints:
  - ip: 172.17.1.101
    port: 8080
- id: default_echo_8443
  endpoints:
  - ip: 172.17.1.101
    port: 8443
- id: _default_backend
  endpoints:
  - ip: 172.17.0.99
    port: 8080
`)

	c.logger.CompareLogging(`
WARN skipping http port config of ssl-passthrough on ingress 'default/echo2': port not found: '9000'
`)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  BUILDERS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

type testConfig struct {
	t       *testing.T
	decode  func(data []byte, defaults *schema.GroupVersionKind, into runtime.Object) (runtime.Object, *schema.GroupVersionKind, error)
	hconfig haproxy.Config
	logger  *types_helper.LoggerMock
	cache   *conv_helper.CacheMock
	tracker convtypes.Tracker
	updater *updaterMock
}

func setup(t *testing.T) *testConfig {
	logger := types_helper.NewLoggerMock(t)
	c := &testConfig{
		t:       t,
		decode:  scheme.Codecs.UniversalDeserializer().Decode,
		hconfig: haproxy.CreateInstance(logger, haproxy.InstanceOptions{}).Config(),
		cache:   conv_helper.NewCacheMock(),
		logger:  logger,
		tracker: tracker.NewTracker(),
	}
	c.createSvc1("system/default", "8080", "172.17.0.99")
	return c
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
}

var defaultBackendConfig = `
- id: _default_backend
  endpoints:
  - ip: 172.17.0.99
    port: 8080`

func (c *testConfig) Sync(ing ...*extensions.Ingress) {
	if ing != nil {
		c.cache.IngList = ing
	}
	if c.cache.Changed.GlobalCur == nil && c.cache.Changed.GlobalNew == nil {
		// first run, set GlobalNew != nil and run SyncFull
		c.cache.Changed.GlobalNew = map[string]string{}
	}
	defaultConfig := func() map[string]string {
		return map[string]string{
			ingtypes.BackInitialWeight: "100",
		}
	}
	conv := NewIngressConverter(
		&ingtypes.ConverterOptions{
			Cache:          c.cache,
			Logger:         c.logger,
			Tracker:        c.tracker,
			DefaultConfig:  defaultConfig,
			DefaultBackend: "system/default",
			DefaultSSLFile: convtypes.CrtFile{
				Filename:   "/tls/tls-default.pem",
				SHA1Hash:   "1",
				CommonName: "localhost.localdomain",
				NotAfter:   time.Now().AddDate(0, 0, 30),
			},
			AnnotationPrefix: "ingress.kubernetes.io",
		},
		c.hconfig,
	).(*converter)
	conv.updater = c.updater
	conv.Sync()
}

func (c *testConfig) createSvc1Auto() (*api.Service, *api.Endpoints) {
	return c.createSvc1("default/echo", "8080", "172.17.0.11")
}

func (c *testConfig) createSvc1AutoAnn(ann map[string]string) (*api.Service, *api.Endpoints) {
	svc, ep := c.createSvc1Auto()
	svc.SetAnnotations(ann)
	return svc, ep
}

func (c *testConfig) createSvc1Ann(name, port, endpoints string, ann map[string]string) (*api.Service, *api.Endpoints) {
	svc, ep := c.createSvc1(name, port, endpoints)
	svc.SetAnnotations(ann)
	return svc, ep
}

func (c *testConfig) createSvc1(name, port, endpoints string) (*api.Service, *api.Endpoints) {
	svc, ep := conv_helper.CreateService(name, port, endpoints)
	// TODO change SvcList to map
	var has bool
	for i, svc1 := range c.cache.SvcList {
		if svc1.Namespace+"/"+svc1.Name == name {
			c.cache.SvcList[i] = svc
			has = true
			break
		}
	}
	if !has {
		c.cache.SvcList = append(c.cache.SvcList, svc)
	}
	c.cache.EpList[name] = ep
	return svc, ep
}

func (c *testConfig) createPod1(name, ip, port string) *api.Pod {
	pname := strings.Split(name, "/")
	pport := strings.Split(port, ":")

	pod := c.createObject(`
apiVersion: v1
kind: Pod
metadata:
  name: ` + pname[1] + `
  namespace: ` + pname[0] + `
spec:
  containers:
  - ports:
    - name: ` + pport[0] + `
      containerPort: ` + pport[1] + `
status:
  podIP: ` + ip).(*api.Pod)

	return pod
}

func (c *testConfig) createSecretTLS1(secretName string) {
	c.cache.SecretTLSPath[secretName] = "/tls/" + secretName + ".pem"
}

func (c *testConfig) createSecretTLS2(secretName string) *api.Secret {
	sname := strings.Split(secretName, "/")
	return c.createObject(`
apiVersion: v1
kind: Secret
metadata:
  name: ` + sname[1] + `
  namespace: ` + sname[0]).(*api.Secret)
}

func (c *testConfig) createIng1(name, hostname, path, service string) *extensions.Ingress {
	sname := strings.Split(name, "/")
	sservice := strings.Split(service, ":")
	return c.createObject(`
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ` + sname[1] + `
  namespace: ` + sname[0] + `
spec:
  rules:
  - host: ` + hostname + `
    http:
      paths:
      - path: ` + path + `
        backend:
          serviceName: ` + sservice[0] + `
          servicePort: ` + sservice[1]).(*extensions.Ingress)
}

func (c *testConfig) createIng1Ann(name, hostname, path, service string, ann map[string]string) *extensions.Ingress {
	ing := c.createIng1(name, hostname, path, service)
	ing.SetAnnotations(ann)
	return ing
}

func (c *testConfig) createIng2(name, service string) *extensions.Ingress {
	sname := strings.Split(name, "/")
	sservice := strings.Split(service, ":")
	return c.createObject(`
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ` + sname[1] + `
  namespace: ` + sname[0] + `
spec:
  backend:
    serviceName: ` + sservice[0] + `
    servicePort: ` + sservice[1]).(*extensions.Ingress)
}

func (c *testConfig) createIng3(name string) *extensions.Ingress {
	sname := strings.Split(name, "/")
	return c.createObject(`
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ` + sname[1] + `
  namespace: ` + sname[0] + `
spec:
  rules:
  - http:`).(*extensions.Ingress)
}

func (c *testConfig) createIngTLS1(name, hostname, path, service, secretHostName string) *extensions.Ingress {
	tls := []extensions.IngressTLS{}
	for _, secret := range strings.Split(secretHostName, ";") {
		ssecret := strings.Split(secret, ":")
		hosts := []string{}
		if len(ssecret) > 1 {
			for _, host := range strings.Split(ssecret[1], ",") {
				hosts = append(hosts, host)
			}
		}
		if len(hosts) == 0 {
			hosts = []string{hostname}
		}
		tls = append(tls, extensions.IngressTLS{
			Hosts:      hosts,
			SecretName: ssecret[0],
		})
	}
	ing := c.createIng1(name, hostname, path, service)
	ing.Spec.TLS = tls
	return ing
}

func (c *testConfig) createObject(cfg string) runtime.Object {
	obj, _, err := c.decode([]byte(cfg), nil, nil)
	if err != nil {
		c.t.Errorf("error decoding object: %v", err)
		return nil
	}
	return obj
}

func _yamlMarshal(in interface{}) string {
	out, _ := yaml.Marshal(in)
	return string(out)
}

func (c *testConfig) compareText(actual, expected string) {
	txt1 := "\n" + strings.Trim(expected, "\n")
	txt2 := "\n" + strings.Trim(actual, "\n")
	if txt1 != txt2 {
		c.t.Error(diff.Diff(txt1, txt2))
	}
}

type updaterMock struct{}

func (u *updaterMock) UpdateGlobalConfig(haproxyConfig haproxy.Config, config *annotations.Mapper) {
}

func (u *updaterMock) UpdateHostConfig(host *hatypes.Host, mapper *annotations.Mapper) {
	host.RootRedirect = mapper.Get(ingtypes.HostAppRoot).Value
}

func (u *updaterMock) UpdateBackendConfig(backend *hatypes.Backend, mapper *annotations.Mapper) {
	backend.Server.MaxConn = mapper.Get(ingtypes.BackMaxconnServer).Int()
	backend.BalanceAlgorithm = mapper.Get(ingtypes.BackBalanceAlgorithm).Value
}

type (
	pathMock struct {
		Path      string
		BackendID string `yaml:"backend"`
	}
	timeoutMock struct {
		Client string `yaml:",omitempty"`
	}
	tlsMock struct {
		TLSFilename string `yaml:",omitempty"`
	}
	hostMock struct {
		Hostname     string
		Paths        []pathMock
		RootRedirect string  `yaml:",omitempty"`
		TLS          tlsMock `yaml:",omitempty"`
	}
)

func convertHost(hafronts ...*hatypes.Host) []hostMock {
	hosts := []hostMock{}
	for _, f := range hafronts {
		paths := []pathMock{}
		for _, p := range f.Paths {
			paths = append(paths, pathMock{Path: p.Path, BackendID: p.Backend.ID})
		}
		hosts = append(hosts, hostMock{
			Hostname:     f.Hostname,
			Paths:        paths,
			RootRedirect: f.RootRedirect,
			TLS:          tlsMock{TLSFilename: f.TLS.TLSFilename},
		})
	}
	return hosts
}

func (c *testConfig) compareConfigFront(expected string) {
	c.compareText(_yamlMarshal(convertHost(c.hconfig.Hosts().BuildSortedItems()...)), expected)
}

func (c *testConfig) compareConfigDefaultFront(expected string) {
	host := c.hconfig.Hosts().DefaultHost()
	if host != nil {
		c.compareText(_yamlMarshal(convertHost(host)[0]), expected)
	} else {
		c.compareText("[]", expected)
	}
}

type (
	endpointMock struct {
		IP    string
		Port  int
		Drain bool `yaml:",omitempty"`
	}
	backendMock struct {
		ID               string
		Endpoints        []endpointMock `yaml:",omitempty"`
		BalanceAlgorithm string         `yaml:",omitempty"`
		MaxConnServer    int            `yaml:",omitempty"`
	}
)

func convertBackend(habackends ...*hatypes.Backend) []backendMock {
	backends := []backendMock{}
	for _, b := range habackends {
		endpoints := []endpointMock{}
		for _, e := range b.Endpoints {
			endpoints = append(endpoints, endpointMock{IP: e.IP, Port: e.Port, Drain: e.Weight == 0})
		}
		backends = append(backends, backendMock{
			ID:               b.ID,
			Endpoints:        endpoints,
			BalanceAlgorithm: b.BalanceAlgorithm,
			MaxConnServer:    b.Server.MaxConn,
		})
	}
	return backends
}

func (c *testConfig) compareConfigBack(expected string) {
	c.compareText(_yamlMarshal(convertBackend(c.hconfig.Backends().BuildSortedItems()...)), expected)
}
