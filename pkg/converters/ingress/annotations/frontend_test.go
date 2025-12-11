/*
Copyright 2025 The HAProxy Ingress Controller Authors.

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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

func TestFrontendLocalConfig(t *testing.T) {

	source := &Source{Type: types.ResourceIngress, Namespace: "default", Name: "ing1"}

	keyOverride := map[string]struct {
		skipHTTP  bool
		skipHTTPS bool
		value     string
	}{
		ingtypes.FrontBindHTTPS: {skipHTTP: true},
		//
		ingtypes.FrontHTTPPassthrough: {skipHTTPS: true},
		ingtypes.FrontBindHTTP:        {skipHTTPS: true},
		//
		ingtypes.FrontBindHTTPPassthrough: {skipHTTP: true, skipHTTPS: true}, // they are always behind proper http passthrough config
		ingtypes.FrontBindFrontingProxy:   {skipHTTP: true, skipHTTPS: true},
		ingtypes.FrontUseForwardedProto:   {skipHTTP: true, skipHTTPS: true},
	}

	for key := range ingtypes.AnnFront {
		if key == ingtypes.FrontHTTPFrontend {
			continue
		}
		t.Run(key, func(t *testing.T) {
			c := setup(t)
			defer c.teardown()
			config := keyOverride[key]
			value := config.value
			if value == "" {
				value = "1"
			}
			global := map[string]string{
				ingtypes.GlobalHTTPPort:  "80",
				ingtypes.GlobalHTTPSPort: "443",
			}
			ann := map[string]string{key: value}

			u := c.createUpdater()
			check := func(isHTTPS bool, expLogging string) {
				d, err := c.createFrontData(source, isHTTPS, ann, global)
				require.NoError(t, err)
				u.UpdateFrontConfig(d.front, d.mapper, d.localPorts)
				c.logger.CompareLogging(expLogging)
			}
			httpCheck := func(expLogging string) {
				if !config.skipHTTP {
					check(false, expLogging)
				}
				if !config.skipHTTPS {
					check(true, expLogging)
				}
			}

			// missing local key
			// we're skipping keys that will not be called, short-circuited due to validations - they will not produce warning logs so we'll skip them here
			httpCheck(fmt.Sprintf("WARN skipping '%s' configuration on %s: missing 'http-frontend' key", key, source))

			// first, declare local http(s) ports
			global[ingtypes.GlobalHTTPFrontends] = "Front8000=8080/8443"
			ann[ingtypes.FrontHTTPFrontend] = "Front8000"

			// ... and test the custom bind keys first
			if slices.Contains(listeningBindFrontendKeys, key) {
				httpCheck(fmt.Sprintf("WARN skipping '%s' configuration on %s: custom bind configuration not allowed", key, source))
				global[ingtypes.GlobalAllowLocalBind] = "true"
			}

			// now the key configuration should succeed
			check(false, "")
			check(true, "")
		})
	}
}

func TestHTTPPassthrough(t *testing.T) {
	testCases := map[string]struct {
		global      map[string]string
		ann         map[string]string
		expFrontErr string
		expHTTPPass bool
		expBind     string
		logging     string
	}{
		"test01": {
			global: map[string]string{
				ingtypes.GlobalHTTPStoHTTPPort: "8000",
			},
			expHTTPPass: true,
			expBind:     ":8000",
		},
		"test02": {
			global: map[string]string{
				ingtypes.GlobalFrontingProxyPort: "8000",
			},
			expHTTPPass: true,
			expBind:     ":8000",
		},
		"test03": {
			global: map[string]string{
				ingtypes.GlobalHTTPPassthroughPort: "8000",
			},
			expHTTPPass: true,
			expBind:     ":8000",
		},
		"test04": {
			global: map[string]string{
				ingtypes.GlobalHTTPPassthroughPort: "8000",
				ingtypes.FrontBindFrontingProxy:    ":8000,:7000",
			},
			expHTTPPass: true,
			expBind:     ":8000,:7000",
		},
		"test05": {
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend:    "Front7000",
				ingtypes.FrontHTTPPassthrough: "true",
			},
			expBind:     ":80",
			expFrontErr: `frontend ID not found on ingress 'default/ing1': 'Front7000'`,
		},
		"test06": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front7000=7000/8443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPPassthrough: "true",
			},
			expBind: ":80",
			logging: `WARN skipping 'http-passthrough' configuration on ingress 'default/ing1': missing 'http-frontend' key`,
		},
		"test07": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front7000=7000/8443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend:      "Front700",
				ingtypes.FrontBindFrontingProxy: ":7000",
			},
			expBind:     ":80",
			expFrontErr: `frontend ID not found on ingress 'default/ing1': 'Front700'`,
		},
		"test08": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends:       "Front7000=7000/8443",
				ingtypes.GlobalHTTPPassthroughPort: "8000",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend:      "Front7000",
				ingtypes.FrontBindFrontingProxy: ":7000",
			},
			expHTTPPass: true,
			expBind:     ":8000",
			logging:     `WARN skipping 'bind-fronting-proxy' configuration on ingress 'default/ing1': custom bind configuration not allowed`,
		},
		"test09": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends:       "Front7000=7000/443",
				ingtypes.GlobalHTTPPassthroughPort: "9000",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend:    "Front7000",
				ingtypes.FrontHTTPPassthrough: "true",
			},
			expHTTPPass: true,
			expBind:     ":9000",
			expFrontErr: `frontend ID not found on ingress 'default/ing1': 'Front7000'`,
			logging:     `WARN ignoring local frontend configuration: local frontend ports cannot collide with global ones [80 443 9000]`,
		},
	}
	source := &Source{Namespace: "default", Name: "ing1", Type: "ingress"}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			c := setup(t)
			defer c.teardown()
			if test.global == nil {
				test.global = make(map[string]string)
			}
			if test.global[ingtypes.GlobalHTTPPort] == "" {
				test.global[ingtypes.GlobalHTTPPort] = "80"
			}
			if test.global[ingtypes.GlobalHTTPSPort] == "" {
				test.global[ingtypes.GlobalHTTPSPort] = "443"
			}
			if d, err := c.createFrontData(source, false, test.ann, test.global); err == nil {
				c.createUpdater().buildFrontHTTPPassthrough(d)
				assert.Equal(t, test.expHTTPPass, d.front.HTTPPassthrough, "HTTPPassthrough")
				assert.Equal(t, test.expBind, d.front.Bind, "Bind")
			} else {
				assert.EqualError(t, err, test.expFrontErr)
			}
			c.logger.CompareLogging(test.logging)
		})
	}
}

func TestFrontendBind(t *testing.T) {
	testCases := map[string]struct {
		global, ann  map[string]string
		expHTTPBind  string
		expHTTPSBind string
		expHTTPErr   string
		expHTTPSErr  string
		expHTTPLog   string
		expHTTPSLog  string
	}{
		"test01": {
			ann:          map[string]string{},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
		},
		"test02": {
			ann: map[string]string{
				ingtypes.FrontBindHTTP: ":80,:8080",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN skipping 'bind-http' configuration on ingress 'default/ing1': missing 'http-frontend' key`,
		},
		"test03": {
			ann: map[string]string{
				ingtypes.FrontBindHTTPS: ":443,:8443",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPSLog:  `WARN skipping 'bind-https' configuration on ingress 'default/ing1': missing 'http-frontend' key`,
		},
		"test04": {
			ann: map[string]string{
				ingtypes.FrontBindIPAddrHTTP: "127.0.0.1",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN skipping 'bind-ip-addr-http' configuration on ingress 'default/ing1': missing 'http-frontend' key`,
			expHTTPSLog:  `WARN skipping 'bind-ip-addr-http' configuration on ingress 'default/ing1': missing 'http-frontend' key`,
		},
		"test05": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
				ingtypes.FrontBindHTTP:     ":80,:8080",
			},
			expHTTPBind:  "*:9090",
			expHTTPSBind: "*:9443",
			expHTTPLog:   `WARN skipping 'bind-http' configuration on ingress 'default/ing1': custom bind configuration not allowed`,
		},
		"test06": {
			global: map[string]string{
				ingtypes.GlobalAllowLocalBind: "true",
				ingtypes.GlobalHTTPFrontends:  "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
				ingtypes.FrontBindHTTP:     ":80,:8080",
			},
			expHTTPBind:  ":80,:8080",
			expHTTPSBind: "*:9443",
		},
		"test07": {
			global: map[string]string{
				ingtypes.GlobalAllowLocalBind: "true",
				ingtypes.GlobalHTTPFrontends:  "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
				ingtypes.FrontBindHTTPS:    ":443,:8443",
			},
			expHTTPBind:  "*:9090",
			expHTTPSBind: ":443,:8443",
		},
		"test08": {
			global: map[string]string{
				ingtypes.GlobalAllowLocalBind: "true",
				ingtypes.GlobalHTTPFrontends:  "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend:   "Front9000",
				ingtypes.FrontBindIPAddrHTTP: "127.0.0.1",
			},
			expHTTPBind:  "127.0.0.1:9090",
			expHTTPSBind: "127.0.0.1:9443",
		},
		"test09": {
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
		},
		"test11": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: `
Front8000=8080/8443
Front8000=9090/8443
`,
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring local frontend configuration: frontend ID already in use: 'Front8000'`,
			expHTTPSLog:  `WARN ignoring local frontend configuration: frontend ID already in use: 'Front8000'`,
		},
		"test12": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=9090/443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPLog:   `WARN ignoring local frontend configuration: local frontend ports cannot collide with global ones [80 443]`,
			expHTTPSLog:  `WARN ignoring local frontend configuration: local frontend ports cannot collide with global ones [80 443]`,
		},
		"test13": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=80/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPLog:   `WARN ignoring local frontend configuration: local frontend ports cannot collide with global ones [80 443]`,
			expHTTPSLog:  `WARN ignoring local frontend configuration: local frontend ports cannot collide with global ones [80 443]`,
		},
		"test14": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=9090/-9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPLog:   `WARN ignoring local frontend configuration: invalid port numbers: '9090/-9443'`,
			expHTTPSLog:  `WARN ignoring local frontend configuration: invalid port numbers: '9090/-9443'`,
		},
		"test15": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=9090/invalid",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPLog:   `WARN ignoring local frontend configuration: invalid port numbers: '9090/invalid'`,
			expHTTPSLog:  `WARN ignoring local frontend configuration: invalid port numbers: '9090/invalid'`,
		},
		"test16": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front900",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front900'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front900'`,
		},
		"test17": {
			global: map[string]string{
				ingtypes.GlobalHTTPFrontends: "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
			},
			expHTTPBind:  "*:9090",
			expHTTPSBind: "*:9443",
		},
		"test19": {
			global: map[string]string{
				ingtypes.GlobalAllowLocalBind: "true",
				ingtypes.GlobalHTTPFrontends:  "Front9000=9090",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
				ingtypes.FrontBindHTTP:     "127.0.0.1:9090",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPErr:   `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPSErr:  `frontend ID not found on ingress 'default/ing1': 'Front9000'`,
			expHTTPLog:   `WARN ignoring local frontend configuration: invalid port declaration syntax: 'Front9000=9090'`,
			expHTTPSLog:  `WARN ignoring local frontend configuration: invalid port declaration syntax: 'Front9000=9090'`,
		},
		"test20": {
			global: map[string]string{
				ingtypes.GlobalAllowLocalBind: "true",
				ingtypes.GlobalHTTPFrontends:  "Front9000=9090/9443",
			},
			ann: map[string]string{
				ingtypes.FrontHTTPFrontend: "Front9000",
				ingtypes.FrontBindHTTP:     "127.0.0.1:9090",
			},
			expHTTPBind:  "127.0.0.1:9090",
			expHTTPSBind: "*:9443",
		},
	}
	source := &Source{Namespace: "default", Name: "ing1", Type: "ingress"}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			c := setup(t)
			defer c.teardown()
			if test.global == nil {
				test.global = make(map[string]string)
			}
			if test.global[ingtypes.GlobalHTTPPort] == "" {
				test.global[ingtypes.GlobalHTTPPort] = "80"
			}
			if test.global[ingtypes.GlobalHTTPSPort] == "" {
				test.global[ingtypes.GlobalHTTPSPort] = "443"
			}
			if test.global[ingtypes.FrontBindIPAddrHTTP] == "" {
				test.global[ingtypes.FrontBindIPAddrHTTP] = "*"
			}
			if dHTTP, err := c.createFrontData(source, false, test.ann, test.global); err == nil {
				c.createUpdater().buildFrontBindHTTP(dHTTP)
				assert.Equal(t, test.expHTTPBind, dHTTP.front.Bind, "HTTPBind")
			} else {
				assert.EqualError(t, err, test.expHTTPErr, "HTTPBind")
			}
			c.logger.CompareLogging(test.expHTTPLog)

			if dHTTPS, err := c.createFrontData(source, true, test.ann, test.global); err == nil {
				c.createUpdater().buildFrontBindHTTPS(dHTTPS)
				assert.Equal(t, test.expHTTPSBind, dHTTPS.front.Bind, "HTTPSBind")
			} else {
				assert.EqualError(t, err, test.expHTTPSErr, "HTTPSBind")
			}
			c.logger.CompareLogging(test.expHTTPSLog)
		})
	}
}
