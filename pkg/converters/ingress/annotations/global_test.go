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
	"testing"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

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
		d.mapper.AddAnnotations(nil, hatypes.CreatePathLink("-", "-"), test.ann)
		c.createUpdater().buildGlobalBind(d)
		c.compareObjects("bind", i, d.global.Bind, test.expected)
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
				ingtypes.GlobalUseCpuMap:     "false",
				ingtypes.GlobalNbthread:      "1",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "",
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.GlobalUseCpuMap:     "false",
				ingtypes.GlobalCpuMap:        "auto 1/1 1-",
				ingtypes.GlobalNbthread:      "1",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "",
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.GlobalUseCpuMap:     "true",
				ingtypes.GlobalCpuMap:        "auto:1/1 1-",
				ingtypes.GlobalNbthread:      "4",
				ingtypes.GlobalNbprocBalance: "1",
			},
			expected: "auto:1/1 1-",
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.GlobalUseCpuMap:     "true",
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
