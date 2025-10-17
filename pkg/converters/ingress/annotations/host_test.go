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

func TestBuildHostRedirect(t *testing.T) {
	testCases := []struct {
		annPrev    map[string]string
		ann        map[string]string
		annDefault map[string]string
		nopath     bool
		expected   hatypes.HostRedirectConfig
		logging    string
	}{
		// 0
		{
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			expected: hatypes.HostRedirectConfig{RedirectHost: "www.d.local"},
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			expected: hatypes.HostRedirectConfig{RedirectHost: "www.d.local"},
		},
		// 2
		{
			annPrev: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			logging: `WARN ignoring redirect from 'www.d.local' on ingress 'default/ing1', it's already targeting to 'dprev.local'`,
		},
		// 3
		{
			annPrev: map[string]string{
				ingtypes.HostRedirectFromRegex: "[a-z]+\\.d\\.local",
			},
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			expected: hatypes.HostRedirectConfig{RedirectHost: "www.d.local"},
		},
		// 4
		{
			annPrev: map[string]string{
				ingtypes.HostRedirectFromRegex: "[a-z]+\\.d\\.local",
			},
			ann: map[string]string{
				ingtypes.HostRedirectFromRegex: "[a-z]+\\.d\\.local",
			},
			logging: `WARN ignoring regex redirect from '[a-z]+\.d\.local' on ingress 'default/ing1', it's already targeting to 'dprev.local'`,
		},
		// 5
		{
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "*.d.local",
			},
			// haproxy/config's responsibility to convert wildcard hostnames to regex
			expected: hatypes.HostRedirectConfig{RedirectHost: "*.d.local"},
		},
		// 6
		{
			annPrev: map[string]string{
				ingtypes.HostRedirectFrom: "*.d.local",
			},
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "*.d.local",
			},
			logging: `WARN ignoring redirect from '*.d.local' on ingress 'default/ing1', it's already targeting to 'dprev.local'`,
		},
		// 7
		{
			annPrev: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			ann: map[string]string{
				ingtypes.HostRedirectFrom: "www.d.local",
			},
			nopath: true,
		},
	}
	sprev := &Source{Namespace: "prev", Name: "ingprev", Type: "ingress"}
	source := &Source{Namespace: "default", Name: "ing1", Type: "ingress"}
	for i, test := range testCases {
		c := setup(t)
		if test.annDefault == nil {
			test.annDefault = map[string]string{}
		}
		b := c.haproxy.Backends().AcquireBackend("default", "d", "8080")
		dprev := c.createHostData(sprev, test.annPrev, test.annDefault)
		d := c.createHostData(source, test.ann, test.annDefault)
		df := c.haproxy.Frontends().Default()
		dprev.host = df.AcquireHost("dprev.local")
		d.host = df.AcquireHost("d.local")
		if !test.nopath {
			dprev.host.AddPath(b, "/", hatypes.MatchPrefix)
			d.host.AddPath(b, "/", hatypes.MatchPrefix)
		}
		updater := c.createUpdater()
		updater.buildHostRedirect(dprev)
		updater.buildHostRedirect(d)
		c.compareObjects("host redirect", i, d.host.Redirect, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestTLSConfig(t *testing.T) {
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
				TLSConfig: hatypes.TLSConfig{
					CAFilename: fakeCAFilename,
					CAHash:     fakeCAHash,
					CAVerify:   hatypes.CAVerifyAlways,
				},
			},
			logging: "ERROR error building TLS auth config on ingress 'system/ing1': secret not found: 'system/caerr'",
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret: "cafile",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					CAFilename: "/path/ca.crt",
					CAHash:     "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
					CAVerify:   hatypes.CAVerifyAlways,
				},
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
				TLSConfig: hatypes.TLSConfig{
					CAFilename: fakeCAFilename,
					CAHash:     fakeCAHash,
					CAVerify:   hatypes.CAVerifyOptional,
				}},
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
				TLSConfig: hatypes.TLSConfig{
					CAFilename: "/path/ca.crt",
					CAHash:     "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
					CAVerify:   hatypes.CAVerifyOptional,
				}},
		},
		// 9
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret:       "cafile",
				ingtypes.HostAuthTLSVerifyClient: "optional",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					CAFilename: "/path/ca.crt",
					CAHash:     "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
					CAVerify:   hatypes.CAVerifyOptional,
				}},
		},
		// 10
		{
			ann: map[string]string{
				ingtypes.HostAuthTLSSecret:       "cafile",
				ingtypes.HostAuthTLSVerifyClient: "optional_no_ca",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					CAFilename: "/path/ca.crt",
					CAHash:     "c0e1bf73caf75d7353cf3ecdd20ceb2f6fa1cab1",
					CAVerify:   hatypes.CAVerifySkipCheck,
				}},
		},
		// 11
		{
			annDefault: map[string]string{
				ingtypes.HostSSLCiphers: "some-cipher-1:some-cipher-2",
			},
			expected: hatypes.HostTLSConfig{},
		},
		// 12
		{
			annDefault: map[string]string{
				ingtypes.HostSSLCiphers: "some-cipher-1:some-cipher-2",
			},
			ann: map[string]string{
				ingtypes.HostSSLCiphers: "some-cipher-2:some-cipher-3",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					Ciphers: "some-cipher-2:some-cipher-3",
				}},
		},
		// 13
		{
			annDefault: map[string]string{
				ingtypes.HostSSLCipherSuites: "some-cipher-1:some-cipher-2",
			},
			expected: hatypes.HostTLSConfig{},
		},
		// 14
		{
			annDefault: map[string]string{
				ingtypes.HostSSLCipherSuites: "some-cipher-suite-1:some-cipher-suite-2",
			},
			ann: map[string]string{
				ingtypes.HostSSLCipherSuites: "some-cipher-suite-2:some-cipher-suite-3",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					CipherSuites: "some-cipher-suite-2:some-cipher-suite-3",
				}},
		},
		// 15
		{
			annDefault: map[string]string{
				ingtypes.HostTLSALPN: "h2,http/1.1",
			},
			expected: hatypes.HostTLSConfig{},
		},
		// 16
		{
			annDefault: map[string]string{
				ingtypes.HostTLSALPN: "h2,http/1.1",
			},
			ann: map[string]string{
				ingtypes.HostTLSALPN: "h2",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					ALPN: "h2",
				}},
		},
		// 17
		{
			annDefault: map[string]string{
				ingtypes.HostSSLOptionsHost: "ssl-min-ver TLSv1.2",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					Options: "ssl-min-ver TLSv1.2",
				}},
		},
		// 18
		{
			annDefault: map[string]string{
				ingtypes.HostSSLOptionsHost: "ssl-min-ver TLSv1.2",
			},
			ann: map[string]string{
				ingtypes.HostSSLOptionsHost: "ssl-min-ver TLSv1.0 ssl-max-ver TLSv1.2",
			},
			expected: hatypes.HostTLSConfig{
				TLSConfig: hatypes.TLSConfig{
					Options: "ssl-min-ver TLSv1.0 ssl-max-ver TLSv1.2",
				}},
		},
	}
	source := &Source{Namespace: "system", Name: "ing1", Type: "ingress"}
	for i, test := range testCases {
		c := setup(t)
		c.cache.SecretCAPath = map[string]string{
			"system/cafile": "/path/ca.crt",
		}
		d := c.createHostData(source, test.ann, test.annDefault)
		updater := c.createUpdater()
		updater.buildHostAuthTLS(d)
		updater.buildHostTLSConfig(d)
		c.compareObjects("tls", i, d.host.TLS, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
