/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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

func TestAuthTLS(t *testing.T) {
	testCases := []struct {
		annDefault map[string]string
		ann        map[string]string
		expected   hatypes.HostTLSConfig
		logging    string
	}{
		// 0
		{},
		// 1
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret: "caerr",
			},
			expected: hatypes.HostTLSConfig{},
			logging:  "ERROR error building TLS auth config on ingress 'system/ing1': secret not found: 'system/caerr'",
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSStrict: "true",
			},
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret: "caerr",
				ingtypes.HostAuthTLSStrict: "true",
			},
			expected: hatypes.HostTLSConfig{
				CAFilename: fakeCAFilename,
				CAHash:     fakeCAHash,
			},
			logging: "ERROR error building TLS auth config on ingress 'system/ing1': secret not found: 'system/caerr'",
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret: "cafile",
			},
			expected: hatypes.HostTLSConfig{
				CAFilename: "/path/ca.crt",
				CAHash:     "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
			},
		},
		// 5
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSVerifyClient: "optional",
			},
		},
		// 6
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSStrict:       "true",
				ingtypes.HostAuthTLSVerifyClient: "optional",
			},
		},
		// 7
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret:       "caerr",
				ingtypes.HostAuthTLSStrict:       "true",
				ingtypes.HostAuthTLSVerifyClient: "optional",
			},
			expected: hatypes.HostTLSConfig{
				CAFilename:       fakeCAFilename,
				CAHash:           fakeCAHash,
				CAVerifyOptional: true,
			},
			logging: "ERROR error building TLS auth config on ingress 'system/ing1': secret not found: 'system/caerr'",
		},
		// 8
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret:       "cafile",
				ingtypes.HostAuthTLSStrict:       "true",
				ingtypes.HostAuthTLSVerifyClient: "optional",
			},
			expected: hatypes.HostTLSConfig{
				CAFilename:       "/path/ca.crt",
				CAHash:           "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
				CAVerifyOptional: true,
			},
		},
		// 9
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret:       "cafile",
				ingtypes.HostAuthTLSVerifyClient: "optional",
			},
			expected: hatypes.HostTLSConfig{
				CAFilename:       "/path/ca.crt",
				CAHash:           "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
				CAVerifyOptional: true,
			},
		},
	}
	source := &Source{Namespace: "system", Name: "ing1", Type: "ingress"}
	for i, test := range testCases {
		c := setup(t)
		c.cache.SecretCAPath = map[string]string{
			"system/cafile": "/path/ca.crt",
		}
		d := c.createHostData(source, test.ann, test.annDefault)
		c.createUpdater().buildHostAuthTLS(d)
		c.compareObjects("auth-tls", i, d.host.TLS, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
