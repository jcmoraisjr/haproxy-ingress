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

package configmap

import (
	"reflect"
	"strings"
	"testing"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

func TestTCPSvcSync(t *testing.T) {
	testCases := []struct {
		svcmock        map[string]string
		secretCertMock map[string]string
		secretCAMock   map[string]string
		secretCRLMock  map[string]string
		services       map[string]string
		expected       []*hatypes.TCPBackend
		logging        string
	}{
		// 0
		{
			services: map[string]string{},
		},
		// 1
		{
			services: map[string]string{"15432": "default/pg:5432"},
			logging:  `WARN skipping TCP service on public port 15432: service not found: 'default/pg'`,
		},
		// 2
		{
			svcmock: map[string]string{
				"default/pg:5432":     "172.17.0.101",
				"default/sendmail:25": "172.17.0.201,172.17.0.202",
			},
			services: map[string]string{
				"15432": "default/pg:5432",
				"10025": "default/sendmail:25",
			},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 15432,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
				},
				{
					Name: "default_sendmail",
					Port: 10025,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.201", Port: 25},
						{Name: "srv002", IP: "172.17.0.202", Port: 25},
					},
					CheckInterval: "2s",
				},
			},
		},
		// 3
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/notfound:5432"},
			logging:  `WARN skipping TCP service on public port 5432: service not found: 'default/notfound'`,
		},
		// 4
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:15432"},
			logging:  `WARN skipping TCP service on public port 5432: port not found: default/pg:15432`,
		},
		// 5
		{
			services: map[string]string{"5432": ":5432"},
			logging:  `WARN skipping empty TCP service name on public port 5432`,
		},
		// 6
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"err5432": "default/pg:5432"},
			logging:  `WARN skipping invalid public listening port of TCP service: err5432`,
		},
		// 7
		{
			svcmock:  map[string]string{"default/pg:5432": ""},
			services: map[string]string{"5432": "default/pg:5432"},
			expected: []*hatypes.TCPBackend{
				{
					Name:          "default_pg",
					Port:          5432,
					CheckInterval: "2s",
				},
			},
		},
		// 8
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:5432:proxy"},
			expected: []*hatypes.TCPBackend{
				{
					Name:      "default_pg",
					Port:      5432,
					ProxyProt: hatypes.TCPProxyProt{Decode: true},
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
				},
			},
		},
		// 9
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:5432::proxy-v1"},
			expected: []*hatypes.TCPBackend{
				{
					Name:      "default_pg",
					Port:      5432,
					ProxyProt: hatypes.TCPProxyProt{EncodeVersion: "v1"},
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
				},
			},
		},
		// 10
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:5432::proxy::-"},
			expected: []*hatypes.TCPBackend{
				{
					Name:      "default_pg",
					Port:      5432,
					ProxyProt: hatypes.TCPProxyProt{EncodeVersion: "v2"},
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
				},
			},
		},
		// 11
		{
			svcmock:        map[string]string{"default/pg:5432": "172.17.0.101"},
			secretCertMock: map[string]string{"default/crt": ""},
			services:       map[string]string{"5432": "default/pg:5432:::default/notfound"},
			logging:        `WARN skipping TCP service on public port 5432: secret not found: 'default/notfound'`,
		},
		// 12
		{
			svcmock:        map[string]string{"default/pg:5432": "172.17.0.101"},
			secretCertMock: map[string]string{"default/crt": "/var/haproxy/ssl/crt.pem"},
			services:       map[string]string{"5432": "default/pg:5432:::default/crt"},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 5432,
					SSL:  hatypes.TCPSSL{Filename: "/var/haproxy/ssl/crt.pem"},
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
				},
			},
		},
		// 13
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:5432::::fail"},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 5432,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
				},
			},
			logging: `WARN using default check interval '2s' due to an invalid time config on TCP service 5432: fail`,
		},
		// 14
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:5432::::2s"},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 5432,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
				},
			},
		},
		// 15
		{
			svcmock:  map[string]string{"default/pg:5432": "172.17.0.101"},
			services: map[string]string{"5432": "default/pg:5432::::2s:default/bogus-secret-ca"},
			logging:  `WARN skipping TCP service on public port 5432: secret not found: 'default/bogus-secret-ca'`,
		},
		// 16
		{
			svcmock:      map[string]string{"default/pg:5432": "172.17.0.101"},
			secretCAMock: map[string]string{"default/ca-only": "/var/haproxy/ssl/ca.pem"},
			services:     map[string]string{"5432": "default/pg:5432:::::default/ca-only"},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 5432,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
					SSL: hatypes.TCPSSL{
						CAFilename:  "/var/haproxy/ssl/ca.pem",
						CRLFilename: "",
					},
				},
			},
		},
		// 17
		{
			svcmock:        map[string]string{"default/pg:5432": "172.17.0.101"},
			secretCertMock: map[string]string{"default/real-secret-tls": "/var/haproxy/ssl/crt.pem"},
			secretCAMock:   map[string]string{"default/real-secret-ca": "/var/haproxy/ssl/ca.pem"},
			services:       map[string]string{"5432": "default/pg:5432:::default/real-secret-tls:2s:default/real-secret-ca"},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 5432,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
					SSL: hatypes.TCPSSL{
						Filename:   "/var/haproxy/ssl/crt.pem",
						CAFilename: "/var/haproxy/ssl/ca.pem",
					},
				},
			},
		},
		// 18
		{
			svcmock:        map[string]string{"default/pg:5432": "172.17.0.101"},
			secretCertMock: map[string]string{"default/real-secret-tls": "/var/haproxy/ssl/crt.pem"},
			secretCAMock:   map[string]string{"default/real-secret-ca": "/var/haproxy/ssl/ca.pem"},
			secretCRLMock:  map[string]string{"default/real-secret-ca": "/var/haproxy/ssl/crl.pem"},
			services:       map[string]string{"5432": "default/pg:5432:::default/real-secret-tls:2s:default/real-secret-ca"},
			expected: []*hatypes.TCPBackend{
				{
					Name: "default_pg",
					Port: 5432,
					Endpoints: []*hatypes.TCPEndpoint{
						{Name: "srv001", IP: "172.17.0.101", Port: 5432},
					},
					CheckInterval: "2s",
					SSL: hatypes.TCPSSL{
						Filename:    "/var/haproxy/ssl/crt.pem",
						CAFilename:  "/var/haproxy/ssl/ca.pem",
						CRLFilename: "/var/haproxy/ssl/crl.pem",
					},
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		for svckey, endpoinds := range test.svcmock {
			svcport := strings.Split(svckey, ":")
			svc, ep := conv_helper.CreateService(svcport[0], svcport[1], endpoinds)
			c.cache.SvcList = append(c.cache.SvcList, svc)
			c.cache.EpList[svcport[0]] = ep
		}
		c.cache.SecretTLSPath = test.secretCertMock
		c.cache.SecretCAPath = test.secretCAMock
		c.cache.SecretCRLPath = test.secretCRLMock
		NewTCPServicesConverter(c.logger, c.haproxy, c.cache).Sync(test.services)
		backends := c.haproxy.TCPBackends().BuildSortedItems()
		for _, b := range backends {
			for _, ep := range b.Endpoints {
				ep.Target = ""
			}
		}
		if !reflect.DeepEqual(backends, test.expected) {
			t.Errorf("backend differs on %d -- expected: %+v -- actual: %+v", i, test.expected, backends)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

type testConfig struct {
	t       *testing.T
	haproxy haproxy.Config
	logger  *types_helper.LoggerMock
	cache   *conv_helper.CacheMock
}

func setup(t *testing.T) *testConfig {
	logger := types_helper.NewLoggerMock(t)
	c := &testConfig{
		t:       t,
		logger:  logger,
		cache:   conv_helper.NewCacheMock(),
		haproxy: haproxy.CreateInstance(logger, haproxy.InstanceOptions{}).Config(),
	}
	return c
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
}
