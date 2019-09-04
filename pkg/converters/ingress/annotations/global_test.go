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
