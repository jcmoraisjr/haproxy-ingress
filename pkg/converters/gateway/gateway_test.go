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

package gateway

import (
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gateway "sigs.k8s.io/gateway-api/apis/v1alpha1"
	"sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/scheme"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

func TestSync(t *testing.T) {
	testCases := []struct {
		id             string
		config         func(c *testConfig)
		expDefaultHost string
		expHosts       string
		expBackends    string
		expLogging     string
	}{
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
  backend: default_echoserver_8080
`,
			expBackends: `
- id: default_echoserver_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
`,
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
  backend: default_echoserver3_8080
`,
			expBackends: `
- id: default_echoserver3_8080
  endpoints:
  - ip: 172.17.0.13
    port: 8080
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
  backend: default_echoserver1_8080
- path: /
  match: prefix
  backend: default_echoserver2_8080
`,
			expBackends: `
- id: default_echoserver1_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
- id: default_echoserver2_8080
  endpoints:
  - ip: 172.17.0.12
    port: 8080
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
    backend: default_echoserver_8080
`,
			expBackends: `
- id: default_echoserver_8080
  endpoints:
  - ip: 172.17.0.11
    port: 8080
`,
		},
	}

	for _, test := range testCases {
		c := setup(t)

		test.config(c)
		c.sync()

		if test.expDefaultHost == "" {
			test.expDefaultHost = "[]"
		}
		if test.expHosts == "" {
			test.expHosts = "[]"
		}
		c.compareConfigDefaultHost(test.id, test.expDefaultHost)
		c.compareConfigHosts(test.id, test.expHosts)
		c.compareConfigBacks(test.id, test.expBackends)
		c.logger.CompareLoggingID(test.id, test.expLogging)

		c.teardown()
	}
}

type testConfig struct {
	t       *testing.T
	cache   *conv_helper.CacheMock
	logger  *types_helper.LoggerMock
	hconfig haproxy.Config
}

func setup(t *testing.T) *testConfig {
	logger := types_helper.NewLoggerMock(t)
	c := &testConfig{
		t:       t,
		hconfig: haproxy.CreateInstance(logger, haproxy.InstanceOptions{}).Config(),
		cache:   conv_helper.NewCacheMock(nil),
		logger:  logger,
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
	options := &types.ConverterOptions{
		Cache:  c.cache,
		Logger: c.logger,
	}
	return NewGatewayConverter(options, c.hconfig, c.cache.SwapChangedObjects())
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
	c.cache.GwClassList = append(c.cache.GwClassList, gc)
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
	c.cache.GwList = append(c.cache.GwList, gw)
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
      port: ` + svc[1]).(*gateway.HTTPRoute)
	for _, label := range strings.Split(labels, ",") {
		l := strings.Split(label, "=")
		r.ObjectMeta.Labels[l[0]] = l[1]
	}
	c.cache.HTTPRouteList = append(c.cache.HTTPRouteList, r)
	return r
}

func (c *testConfig) createHTTPRoute2(name, labels, service, paths string) *gateway.HTTPRoute {
	r := c.createHTTPRoute1(name, labels, service)
	for _, path := range strings.Split(paths, ",") {
		match := gateway.HTTPRouteMatch{
			Path: gateway.HTTPPathMatch{
				Value: path,
			},
		}
		r.Spec.Rules[0].Matches = append(r.Spec.Rules[0].Matches, match)
	}
	return r
}

func CreateObject(cfg string) runtime.Object {
	decode := scheme.Codecs.UniversalDeserializer().Decode
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
	c.compareText(id, conv_helper.MarshalBackends(c.hconfig.Backends().BuildSortedItems()...), expected)
}
