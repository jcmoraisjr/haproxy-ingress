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

package annotations

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func TestAuthProxy(t *testing.T) {
	testCases := []struct {
		input    string
		expected hatypes.AuthProxy
		logging  string
	}{
		// 0
		{
			input: "_name:100",
			expected: hatypes.AuthProxy{
				RangeStart: 0,
				RangeEnd:   -1,
			},
			logging: `WARN invalid auth proxy configuration: _name:100`,
		},
		// 1
		{
			input: "_name:non-num",
			expected: hatypes.AuthProxy{
				RangeStart: 0,
				RangeEnd:   -1,
			},
			logging: `WARN invalid auth proxy configuration: _name:non-num`,
		},
		// 2
		{
			input: "=invalid:100-101",
			expected: hatypes.AuthProxy{
				RangeStart: 0,
				RangeEnd:   -1,
			},
			logging: `WARN invalid auth proxy configuration: =invalid:100-101`,
		},
		// 3
		{
			input: "_name:100-101",
			expected: hatypes.AuthProxy{
				Name:       "_name",
				RangeStart: 100,
				RangeEnd:   101,
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{
			ingtypes.GlobalAuthProxy: test.input,
		})
		c.createUpdater().buildGlobalAuthProxy(d)
		c.compareObjects("bind", i, c.haproxy.Frontend().AuthProxy, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestBind(t *testing.T) {
	testCases := []struct {
		ann      map[string]string
		expected hatypes.GlobalBindConfig
	}{
		// 0
		{
			ann: map[string]string{},
			expected: hatypes.GlobalBindConfig{
				HTTPBind:  "*:80",
				HTTPSBind: "*:443",
			},
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.GlobalBindHTTP: ":80,:8080",
			},
			expected: hatypes.GlobalBindConfig{
				HTTPBind:  ":80,:8080",
				HTTPSBind: "*:443",
			},
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.GlobalBindHTTPS: ":443,:8443",
			},
			expected: hatypes.GlobalBindConfig{
				HTTPBind:  "*:80",
				HTTPSBind: ":443,:8443",
			},
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.GlobalBindIPAddrHTTP: "127.0.0.1",
			},
			expected: hatypes.GlobalBindConfig{
				HTTPBind:  "127.0.0.1:80",
				HTTPSBind: "127.0.0.1:443",
			},
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.GlobalHTTPPort:  "8080",
				ingtypes.GlobalHTTPSPort: "8443",
			},
			expected: hatypes.GlobalBindConfig{
				HTTPBind:  "*:8080",
				HTTPSBind: "*:8443",
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{
			ingtypes.GlobalHTTPPort:       "80",
			ingtypes.GlobalHTTPSPort:      "443",
			ingtypes.GlobalBindIPAddrHTTP: "*",
		})
		d.mapper.AddAnnotations(nil, hatypes.CreateHostPathLink("-", "-", hatypes.MatchBegin), test.ann)
		c.createUpdater().buildGlobalBind(d)
		c.compareObjects("bind", i, d.global.Bind, test.expected)
		c.teardown()
	}
}

func TestCloseSessions(t *testing.T) {
	testCases := []struct {
		annDuration string
		annStop     string
		expDuration time.Duration
		untrack     bool
		logging     string
	}{
		// 0
		{},
		// 1
		{
			annDuration: "5m",
			annStop:     "10m",
			untrack:     true,
			logging:     `WARN ignoring close-sessions-duration config: tracking old instances is disabled`,
		},
		// 2
		{
			annDuration: "10m",
			logging:     `WARN ignoring close-sessions-duration config: timeout-stop need to be configured`,
		},
		// 3
		{
			annDuration: "10m",
			annStop:     "10%",
			logging:     `WARN ignoring close-sessions-duration due to invalid timeout-stop config: time: unknown unit "%" in duration "10%"`,
		},
		// 4
		{
			annDuration: "1%",
			annStop:     "10m",
			logging:     `WARN ignoring '1%' for close-sessions-duration value: value should be between 5% and 95%`,
		},
		// 5
		{
			annDuration: "99%",
			annStop:     "10m",
			logging:     `WARN ignoring '99%' for close-sessions-duration value: value should be between 5% and 95%`,
		},
		// 6
		{
			annDuration: "10x",
			annStop:     "10m",
			logging:     `WARN ignoring invalid close-sessions-duration config: time: unknown unit "x" in duration "10x"`,
		},
		// 7
		{
			annDuration: "10m",
			annStop:     "10m",
			logging:     `WARN ignoring invalid close-sessions-duration config: close-sessions-duration should be lower than timeout-stop`,
		},
		// 8
		{
			annDuration: "5m",
			annStop:     "10m",
			expDuration: 5 * time.Minute,
		},
		// 9
		{
			annDuration: "5%",
			annStop:     "10m",
			expDuration: 30 * time.Second,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{
			ingtypes.GlobalCloseSessionsDuration: test.annDuration,
			ingtypes.GlobalTimeoutStop:           test.annStop,
		})
		u := c.createUpdater()
		if !test.untrack {
			u.options.TrackInstances = true
		}
		u.buildGlobalCloseSessions(d)
		c.compareObjects("close sessions duration", i, d.global.CloseSessionsDuration, test.expDuration)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestCustomConfigProxy(t *testing.T) {
	testCases := []struct {
		config   string
		expected map[string][]string
		logging  string
	}{
		// 0
		{},
		// 1
		{
			config: `
proxy_1
  acl test`,
			expected: map[string][]string{
				"proxy_1": {"acl test"},
			},
		},
		// 2
		{
			config: `
backend_1
  acl ok always_true
  http-request deny if !ok
backend_2
  ## two spaces
    ## four spaces
		## two tabs`,
			expected: map[string][]string{
				"backend_1": {"acl ok always_true", "http-request deny if !ok"},
				"backend_2": {"## two spaces", "## four spaces", "## two tabs"},
			},
		},
		// 3
		{
			config: `
  ## trailing line 1
proxy_1
  acl ok always_true
`,
			expected: map[string][]string{
				"proxy_1": {"acl ok always_true"},
			},
			logging: `WARN non scoped 1 line(s) in the config-proxy configuration were ignored`,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{ingtypes.GlobalConfigProxy: test.config})
		c.createUpdater().buildGlobalCustomConfig(d)
		if test.expected == nil {
			test.expected = map[string][]string{}
		}
		c.compareObjects("custom config", i, d.global.CustomProxy, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestCustomConfigFrontendLegacy(t *testing.T) {
	testCases := []struct {
		config   string
		expected []string
		logging  string
	}{
		// 0
		{
			config:   "http-response set-header X-Server HAProxy",
			expected: []string{"http-response set-header X-Server HAProxy"},
		},
		// 1
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{ingtypes.GlobalConfigFrontend: test.config})
		c.createUpdater().buildGlobalCustomConfig(d)
		if test.expected == nil {
			test.expected = []string{}
		}
		c.compareObjects("custom config", i, d.global.CustomFrontendLate, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestModSecurity(t *testing.T) {
	testCases := []struct {
		endpoints string
		expected  []string
	}{
		// 0
		{
			endpoints: "",
			expected:  nil,
		},
		// 1
		{
			endpoints: "127.0.0.1:12345",
			expected:  []string{"127.0.0.1:12345"},
		},
		// 2
		{
			endpoints: "10.0.0.1:12345, 10.0.0.2:12345",
			expected:  []string{"10.0.0.1:12345", "10.0.0.2:12345"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{ingtypes.GlobalModsecurityEndpoints: test.endpoints})
		c.createUpdater().buildGlobalModSecurity(d)
		c.compareObjects("modsecurity endpoints", i, d.global.ModSecurity.Endpoints, test.expected)
		c.teardown()
	}
}

func TestDNS(t *testing.T) {
	testCases := []struct {
		config   map[string]string
		expected hatypes.DNSConfig
		logging  string
	}{
		// 0
		{
			config: map[string]string{
				ingtypes.GlobalDNSResolvers: "k8s",
			},
			logging: `WARN ignoring misconfigured resolver: k8s`,
		},
		// 1
		{
			config: map[string]string{
				ingtypes.GlobalDNSClusterDomain: "cluster.local",
				ingtypes.GlobalDNSResolvers:     "k8s=10.0.1.11",
			},
			expected: hatypes.DNSConfig{
				ClusterDomain: "cluster.local",
				Resolvers: []*hatypes.DNSResolver{
					{
						Name: "k8s",
						Nameservers: []*hatypes.DNSNameserver{
							{
								Name:     "ns01",
								Endpoint: "10.0.1.11:53",
							},
						},
					},
				},
			},
		},
		// 2
		{
			config: map[string]string{
				ingtypes.GlobalDNSClusterDomain: "cluster.local",
				ingtypes.GlobalDNSResolvers: `
k8s1=10.0.1.11
k8s2=10.0.1.21:53,10.0.1.22:53,

k8s3=10.0.1.31:10053,10.0.1.32:10053,10.0.1.33:10053,
`,
			},
			expected: hatypes.DNSConfig{
				ClusterDomain: "cluster.local",
				Resolvers: []*hatypes.DNSResolver{
					{
						Name: "k8s1",
						Nameservers: []*hatypes.DNSNameserver{
							{
								Name:     "ns01",
								Endpoint: "10.0.1.11:53",
							},
						},
					},
					{
						Name: "k8s2",
						Nameservers: []*hatypes.DNSNameserver{
							{
								Name:     "ns01",
								Endpoint: "10.0.1.21:53",
							},
							{
								Name:     "ns02",
								Endpoint: "10.0.1.22:53",
							},
						},
					},
					{
						Name: "k8s3",
						Nameservers: []*hatypes.DNSNameserver{
							{
								Name:     "ns01",
								Endpoint: "10.0.1.31:10053",
							},
							{
								Name:     "ns02",
								Endpoint: "10.0.1.32:10053",
							},
							{
								Name:     "ns03",
								Endpoint: "10.0.1.33:10053",
							},
						},
					},
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(test.config)
		c.createUpdater().buildGlobalDNS(d)
		c.compareObjects("dns", i, d.global.DNS, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestDynamic(t *testing.T) {
	testCases := []struct {
		config        map[string]string
		staticSecrets bool
		expected      convtypes.DynamicConfig
		logging       string
	}{
		// 0
		{
			config: map[string]string{
				ingtypes.GlobalCrossNamespaceSecretsCA: "error",
			},
			logging: `
WARN ignoring invalid value 'error' on global 'cross-namespace-secrets-ca', using 'deny'
`,
		},
		// 1
		{
			config: map[string]string{
				ingtypes.GlobalCrossNamespaceSecretsCA:  "allow",
				ingtypes.GlobalCrossNamespaceSecretsCrt: "fail",
			},
			expected: convtypes.DynamicConfig{
				CrossNamespaceSecretCA: true,
			},
			logging: `
WARN ignoring invalid value 'fail' on global 'cross-namespace-secrets-crt', using 'deny'
`,
		},
		// 2
		{
			config: map[string]string{
				ingtypes.GlobalCrossNamespaceSecretsCA:  "deny",
				ingtypes.GlobalCrossNamespaceSecretsCrt: "allow",
			},
			expected: convtypes.DynamicConfig{
				CrossNamespaceSecretCertificate: true,
			},
		},
		// 3
		{
			config: map[string]string{
				ingtypes.GlobalCrossNamespaceSecretsCA:     "allow",
				ingtypes.GlobalCrossNamespaceSecretsCrt:    "allow",
				ingtypes.GlobalCrossNamespaceSecretsPasswd: "allow",
				ingtypes.GlobalCrossNamespaceServices:      "allow",
			},
			expected: convtypes.DynamicConfig{
				CrossNamespaceSecretCA:          true,
				CrossNamespaceSecretCertificate: true,
				CrossNamespaceSecretPasswd:      true,
				CrossNamespaceServices:          true,
			},
		},
		// 4
		{
			config: map[string]string{
				ingtypes.GlobalCrossNamespaceSecretsCA: "allow",
			},
			staticSecrets: true,
			expected: convtypes.DynamicConfig{
				CrossNamespaceSecretCA:          true,
				CrossNamespaceSecretCertificate: true,
				CrossNamespaceSecretPasswd:      true,
				StaticCrossNamespaceSecrets:     true,
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(test.config)
		u := c.createUpdater()
		u.options.DynamicConfig.StaticCrossNamespaceSecrets = test.staticSecrets
		u.buildGlobalDynamic(d)
		if !reflect.DeepEqual(*u.options.DynamicConfig, test.expected) {
			c.compareObjects("dynamic", i, *u.options.DynamicConfig, test.expected)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestForwardFor(t *testing.T) {
	testCases := []struct {
		conf     string
		expected string
		logging  string
	}{
		// 0
		{
			conf:     "",
			expected: "add",
			logging:  "",
		},
		// 1
		{
			conf:     "non",
			expected: "add",
			logging:  "WARN Invalid forwardfor value option on configmap: 'non'. Using 'add' instead",
		},
		// 2
		{
			conf:     "add",
			expected: "add",
			logging:  "",
		},
		// 3
		{
			conf:     "ignore",
			expected: "ignore",
			logging:  "",
		},
		// 4
		{
			conf:     "ifmissing",
			expected: "ifmissing",
			logging:  "",
		},
		// 5
		{
			conf:     "update",
			expected: "update",
			logging:  "",
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{ingtypes.GlobalForwardfor: test.conf})
		c.createUpdater().buildGlobalForwardFor(d)
		c.compareObjects("forward-for", i, d.global.ForwardFor, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestFrontingProxy(t *testing.T) {
	testCases := []struct {
		ann      map[string]string
		expected hatypes.GlobalBindConfig
	}{
		// 0
		{
			ann: map[string]string{
				ingtypes.GlobalHTTPStoHTTPPort: "8000",
			},
			expected: hatypes.GlobalBindConfig{
				FrontingBind: ":8000",
			},
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.GlobalFrontingProxyPort: "9000",
			},
			expected: hatypes.GlobalBindConfig{
				FrontingBind: ":9000",
			},
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.GlobalHTTPStoHTTPPort:   "9000",
				ingtypes.GlobalBindFrontingProxy: ":7000",
			},
			expected: hatypes.GlobalBindConfig{
				FrontingBind: ":7000",
			},
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.GlobalFrontingProxyPort: "8000",
				ingtypes.GlobalBindFrontingProxy: "127.0.0.1:7000",
			},
			expected: hatypes.GlobalBindConfig{
				FrontingBind: "127.0.0.1:7000",
			},
		},
	}
	frontingSockID := 10011
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(test.ann)
		c.createUpdater().buildGlobalHTTPStoHTTP(d)
		test.expected.FrontingSockID = frontingSockID
		c.compareObjects("fronting proxy", i, d.global.Bind, test.expected)
		c.teardown()
	}
}

func TestDisableCpuMap(t *testing.T) {
	testCases := []struct {
		ann      map[string]string
		expected string
	}{
		// 0
		{
			ann: map[string]string{
				ingtypes.GlobalUseCPUMap:     "false",
				ingtypes.GlobalNbthread:      "1",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "",
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.GlobalUseCPUMap:     "false",
				ingtypes.GlobalCPUMap:        "auto 1/1 1-",
				ingtypes.GlobalNbthread:      "1",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "",
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.GlobalUseCPUMap:     "true",
				ingtypes.GlobalCPUMap:        "auto:1/1 1-",
				ingtypes.GlobalNbthread:      "4",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "auto:1/1 1-",
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.GlobalUseCPUMap:     "true",
				ingtypes.GlobalNbthread:      "2",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "auto:1/1-2 0-1",
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(test.ann)
		c.createUpdater().buildGlobalProc(d)
		c.compareObjects("cpu map", i, d.global.Procs.CPUMap, test.expected)
		c.teardown()
	}
}

func TestPathTypeOrder(t *testing.T) {
	testCases := []struct {
		order    string
		expected []hatypes.MatchType
		logging  string
	}{
		// 0
		{
			order:    "regex,begin",
			expected: hatypes.DefaultMatchOrder,
			logging:  "WARN all path types should be used in [regex begin], using default order [exact prefix begin regex]",
		},
		// 1
		{
			order:    "regex,begin,regex,begin",
			expected: hatypes.DefaultMatchOrder,
			logging:  "WARN invalid or duplicated path type 'regex', using default order [exact prefix begin regex]",
		},
		// 2
		{
			order:    "regex,begin,prefix,Exact",
			expected: hatypes.DefaultMatchOrder,
			logging:  "WARN invalid or duplicated path type 'Exact', using default order [exact prefix begin regex]",
		},
		// 3
		{
			order:    "prefix,invalid",
			expected: hatypes.DefaultMatchOrder,
			logging:  "WARN invalid or duplicated path type 'invalid', using default order [exact prefix begin regex]",
		},
		// 4
		{
			order:    "regex,begin,prefix,exact",
			expected: []hatypes.MatchType{hatypes.MatchRegex, hatypes.MatchBegin, hatypes.MatchPrefix, hatypes.MatchExact},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(map[string]string{ingtypes.GlobalPathTypeOrder: test.order})
		c.createUpdater().buildGlobalPathTypeOrder(d)
		c.compareObjects("path type order", i, d.global.MatchOrder, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestSecurity(t *testing.T) {
	testCases := []struct {
		ann      map[string]string
		expected hatypes.SecurityConfig
		logging  string
	}{
		// 0
		{
			ann: map[string]string{
				ingtypes.GlobalUseChroot: "true",
			},
			expected: hatypes.SecurityConfig{
				UseChroot: true,
			},
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.GlobalUsername: "someuser",
			},
			expected: hatypes.SecurityConfig{},
			logging:  `WARN if configuring non root user, both username and groupname must be defined`,
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.GlobalUsername:  "someuser",
				ingtypes.GlobalGroupname: "somegroup",
			},
			expected: hatypes.SecurityConfig{
				Username:  "someuser",
				Groupname: "somegroup",
			},
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.GlobalUsername:       "someuser",
				ingtypes.GlobalGroupname:      "somegroup",
				ingtypes.GlobalUseHAProxyUser: "true",
			},
			expected: hatypes.SecurityConfig{
				Username:  "someuser",
				Groupname: "somegroup",
			},
			logging: `WARN username and groupname are already defined as 'someuser' and 'somegroup', ignoring 'use-haproxy-user' config`,
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.GlobalUsername:       "someuser",
				ingtypes.GlobalUseHAProxyUser: "true",
			},
			expected: hatypes.SecurityConfig{
				Username:  "haproxy",
				Groupname: "haproxy",
			},
			logging: `WARN if configuring non root user, both username and groupname must be defined`,
		},
		// 5
		{
			ann: map[string]string{
				ingtypes.GlobalUsername:       "haproxy",
				ingtypes.GlobalGroupname:      "haproxy",
				ingtypes.GlobalUseHAProxyUser: "true",
			},
			expected: hatypes.SecurityConfig{
				Username:  "haproxy",
				Groupname: "haproxy",
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(test.ann)
		c.createUpdater().buildSecurity(d)
		c.compareObjects("fronting proxy", i, d.global.Security, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestCustomResponse(t *testing.T) {
	const default404 = `
---
send-404 404 'Not Found'
[{Content-Length 83} {Content-Type text/html} {Cache-Control no-cache}]
<html><body><h1>404 Not Found</h1>
The requested URL was not found.
</body></html>
`
	testCases := []struct {
		config   map[string]string
		expected string
		logging  string
	}{
		// 0
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404 Not Found`,
			},
			expected: `
---
send-404 404 'Not Found'
[{Content-Length 0}]
`,
		},
		// 1
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
h1:value1
h2: value2
h3:  value3
h4 : value4
 h5:value5

payload
`,
			},
			expected: `
---
send-404 404 'Not Found'
[{Content-Length 8} {h1 value1} {h2 value2} {h3 value3} {h4 value4} {h5 value5}]
payload
`,
		},
		// 2
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404`,
				ingtypes.GlobalHTTPResponse413: `413 Too Large

<h1>
  413 two spaces left
413 to spaces right  
</h1>
`,
			},
			expected: `
---
send-404 404 'Not Found'
[{Content-Length 0}]
---
send-413 413 'Too Large'
[{Content-Length 53}]
<h1>
  413 two spaces left
413 to spaces right
</h1>
`,
		},
		// 3
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `999 Invalid Code`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: invalid status code: 999`,
		},
		// 4
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
h space: value
`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: invalid chars in the header name: 'h space'`,
		},
		// 5
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
h invalid
`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: missing a colon ':' in the header declaration: h invalid`,
		},
		// 6
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
h: "invalid"
`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: invalid chars in the header value: '"invalid"'`,
		},
		// 7
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
h:
`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: header name and value must not be empty: 'h:'`,
		},
		// 8
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
: v
`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: header name and value must not be empty: ': v'`,
		},
		// 9
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse404: `404
h1: value1

payload lua ]==] conflict
`,
			},
			expected: default404,
			logging:  `WARN ignoring 'http-response-404' due to a malformed response: the string ']==]' cannot be used in the body`,
		},
		// 10
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse413: `
body`,
			},
			expected: `
---
send-413 413 'Payload Too Large'
[{Content-Length 5}]
body
`,
		},
		// 11
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse421: `h1: value1`,
			},
			expected: `
---
send-421 421 'Misdirected Request'
[{Content-Length 0} {h1 value1}]
`,
		},
		// 12
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse495: `h1: value1

body`,
			},
			expected: `
---
send-495 495 'SSL Certificate Error'
[{Content-Length 5} {h1 value1}]
body
`,
		},
		// 13
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse503: `h1: value1

body`,
			},
			expected: `
---
503 503 'Service Unavailable'
[{Content-Length 5} {h1 value1}]
body
`,
		},
		// 14
		{
			config: map[string]string{
				ingtypes.GlobalHTTPResponse403: `Content-length: 10

body`,
			},
			expected: `
---
403 403 'Forbidden'
[{Content-Length 5}]
body
`,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createGlobalData(test.config)
		c.createUpdater().buildGlobalCustomResponses(d)
		var has string
		for _, rsp := range customHTTPResponses {
			for key := range test.config {
				if rsp.key == key {
					has += rsp.name + ","
				}
			}
		}
		var actual string
		for _, response := range append(d.global.CustomHTTPLuaResponses, d.global.CustomHTTPHAResponses...) {
			if !strings.Contains(has, response.Name) {
				continue
			}
			actual += fmt.Sprintf("---\n%s %d '%s'\n%v\n",
				response.Name, response.StatusCode, response.StatusReason, response.Headers)
			for _, l := range response.Body {
				actual += l + "\n"
			}
		}
		c.compareText("custom responses", i, actual, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
