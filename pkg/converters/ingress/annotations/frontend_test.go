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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

func TestFrontendLocalConfig(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	source := &Source{Type: types.ResourceIngress, Namespace: "default", Name: "ing1"}
	annDefault := map[string]string{
		ingtypes.GlobalHTTPPort:  "80",
		ingtypes.GlobalHTTPSPort: "443",
	}

	keyOverride := map[string]struct {
		skipHTTP  bool
		skipHTTPS bool
		value     string
	}{
		ingtypes.FrontBindHTTPS: {skipHTTP: true},
		//
		ingtypes.FrontBindFrontingProxy: {skipHTTPS: true},
		ingtypes.FrontBindHTTP:          {skipHTTPS: true},
		ingtypes.FrontFrontingProxyPort: {skipHTTPS: true},
		ingtypes.FrontHTTPStoHTTPPort:   {skipHTTPS: true},
		//
		ingtypes.FrontUseForwardedProto: {skipHTTP: true, skipHTTPS: true}, // it is always behind fronting proxy port
	}

	for key := range ingtypes.AnnFront {
		if key == ingtypes.FrontHTTPPortsLocal {
			continue
		}
		t.Run(key, func(t *testing.T) {
			config := keyOverride[key]
			value := config.value
			if value == "" {
				value = "1"
			}
			ann := map[string]string{key: value}

			u := c.createUpdater()
			check := func(isHTTPS bool, expLogging string) {
				d := c.createFrontData(source, isHTTPS, ann, annDefault)
				u.UpdateFrontConfig(d.front, d.mapper, d.localPorts)
				c.logger.CompareLogging(expLogging)
			}

			// missing local key
			// we're skipping keys that will not be called - they will not produce warning logs
			expLogging := fmt.Sprintf("WARN skipping '%s' configuration on Ingress 'default/ing1': missing 'http-ports-local' key", key)
			if !config.skipHTTP {
				check(false, expLogging)
			}
			if !config.skipHTTPS {
				check(true, expLogging)
			}

			// declare local http(s) ports, which should make all the keys to succeed, so now checking all of them
			ann[ingtypes.FrontHTTPPortsLocal] = "8080/8443"
			check(false, "")
			check(true, "")
		})
	}
}

func TestFrontingProxy(t *testing.T) {
	testCases := map[string]struct {
		ann              map[string]string
		expFrontingProxy bool
		expBind          string
	}{
		"test01": {
			ann: map[string]string{
				ingtypes.FrontHTTPStoHTTPPort: "8000",
			},
			expFrontingProxy: true,
			expBind:          ":8000",
		},
		"test02": {
			ann: map[string]string{
				ingtypes.FrontFrontingProxyPort: "9000",
			},
			expFrontingProxy: true,
			expBind:          ":9000",
		},
		"test03": {
			ann: map[string]string{
				ingtypes.FrontHTTPStoHTTPPort:   "9000",
				ingtypes.FrontBindFrontingProxy: ":7000",
			},
			expFrontingProxy: true,
			expBind:          ":7000",
		},
		"test04": {
			ann: map[string]string{
				ingtypes.FrontFrontingProxyPort: "8000",
				ingtypes.FrontBindFrontingProxy: "127.0.0.1:7000",
			},
			expFrontingProxy: true,
			expBind:          "127.0.0.1:7000",
		},
	}
	source := &Source{Namespace: "default", Name: "ing1", Type: "ingress"}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			c := setup(t)
			defer c.teardown()
			test.ann[ingtypes.FrontHTTPPortsLocal] = "9090/9443"
			d := c.createFrontData(source, false, test.ann, map[string]string{})
			c.createUpdater().buildFrontFrontingProxy(d)
			require.Equal(t, test.expFrontingProxy, d.front.IsFrontingProxy, "FrontingProxy")
			require.Equal(t, test.expBind, d.front.Bind, "Bind")
		})
	}
}

func TestFrontendBind(t *testing.T) {
	testCases := map[string]struct {
		ann          map[string]string
		expHTTPBind  string
		expHTTPSBind string
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
			expHTTPLog:   `WARN skipping 'bind-http' configuration on ingress 'default/ing1': missing 'http-ports-local' key`,
		},
		"test03": {
			ann: map[string]string{
				ingtypes.FrontBindHTTPS: ":443,:8443",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPSLog:  `WARN skipping 'bind-https' configuration on ingress 'default/ing1': missing 'http-ports-local' key`,
		},
		"test04": {
			ann: map[string]string{
				ingtypes.FrontBindIPAddrHTTP: "127.0.0.1",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN skipping 'bind-ip-addr-http' configuration on ingress 'default/ing1': missing 'http-ports-local' key`,
			expHTTPSLog:  `WARN skipping 'bind-ip-addr-http' configuration on ingress 'default/ing1': missing 'http-ports-local' key`,
		},
		"test05": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/9443",
				ingtypes.FrontBindHTTP:       ":80,:8080",
			},
			expHTTPBind:  ":80,:8080",
			expHTTPSBind: "*:9443",
		},
		"test06": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/9443",
				ingtypes.FrontBindHTTPS:      ":443,:8443",
			},
			expHTTPBind:  "*:9090",
			expHTTPSBind: ":443,:8443",
		},
		"test07": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/9443",
				ingtypes.FrontBindIPAddrHTTP: "127.0.0.1",
			},
			expHTTPBind:  "127.0.0.1:9090",
			expHTTPSBind: "127.0.0.1:9443",
		},
		"test09": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring invalid http/https ports configuration '9090' on ingress 'default/ing1'`,
			expHTTPSLog:  `WARN ignoring invalid http/https ports configuration '9090' on ingress 'default/ing1'`,
		},
		"test10": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/https",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring invalid http/https ports configuration '9090/https' on ingress 'default/ing1'`,
			expHTTPSLog:  `WARN ignoring invalid http/https ports configuration '9090/https' on ingress 'default/ing1'`,
		},
		"test11": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "80/9090/9443",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring invalid http/https ports configuration '80/9090/9443' on ingress 'default/ing1'`,
			expHTTPSLog:  `WARN ignoring invalid http/https ports configuration '80/9090/9443' on ingress 'default/ing1'`,
		},
		"test12": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/443",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
			expHTTPSLog:  `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
		},
		"test13": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "80/9443",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
			expHTTPSLog:  `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
		},
		"test14": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "80/443",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
			expHTTPSLog:  `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
		},
		"test15": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "443/8080",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog:   `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
			expHTTPSLog:  `WARN ignoring http/https ports configuration on ingress 'default/ing1': local http(s) ports cannot collide with global '80/443' ones`,
		},
		"test16": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/9443",
			},
			expHTTPBind:  "*:9090",
			expHTTPSBind: "*:9443",
		},
		"test17": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/invalid",
				ingtypes.FrontBindHTTP:       "127.0.0.1:9090",
			},
			expHTTPBind:  "*:80",
			expHTTPSBind: "*:443",
			expHTTPLog: `
WARN ignoring invalid http/https ports configuration '9090/invalid' on ingress 'default/ing1'
WARN skipping 'bind-http' configuration on ingress 'default/ing1': missing 'http-ports-local' key
`,
			expHTTPSLog: `WARN ignoring invalid http/https ports configuration '9090/invalid' on ingress 'default/ing1'`,
		},
		"test18": {
			ann: map[string]string{
				ingtypes.FrontHTTPPortsLocal: "9090/9443",
				ingtypes.FrontBindHTTP:       "127.0.0.1:9090",
			},
			expHTTPBind:  "127.0.0.1:9090",
			expHTTPSBind: "*:9443",
		},
	}
	source := &Source{Namespace: "default", Name: "ing1", Type: "ingress"}
	annDefault := map[string]string{
		ingtypes.GlobalHTTPPort:      "80",
		ingtypes.GlobalHTTPSPort:     "443",
		ingtypes.FrontBindIPAddrHTTP: "*",
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			c := setup(t)
			defer c.teardown()

			dHTTP := c.createFrontData(source, false, test.ann, annDefault)
			c.createUpdater().buildFrontBindHTTP(dHTTP)
			assert.Equal(t, test.expHTTPBind, dHTTP.front.Bind, "HTTPBind")
			c.logger.CompareLogging(test.expHTTPLog)

			dHTTPS := c.createFrontData(source, true, test.ann, annDefault)
			c.createUpdater().buildFrontBindHTTPS(dHTTPS)
			assert.Equal(t, test.expHTTPSBind, dHTTPS.front.Bind, "HTTPSBind")
			c.logger.CompareLogging(test.expHTTPSLog)
		})
	}
}
