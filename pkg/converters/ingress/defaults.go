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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/utils"
)

const (
	defaultSSLCiphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
)

func createDefaults() *types.Config {
	return &types.Config{
		ConfigDefaults: types.ConfigDefaults{
			BalanceAlgorithm: "roundrobin",
			CookieKey:        "Ingress",
			HSTS:             true,
			HSTSIncludeSubdomains: false,
			HSTSMaxAge:            "15768000",
			HSTSPreload:           false,
			ProxyBodySize:         "",
			SSLRedirect:           true,
			TimeoutClient:         "50s",
			TimeoutClientFin:      "50s",
			TimeoutConnect:        "5s",
			TimeoutHTTPRequest:    "5s",
			TimeoutKeepAlive:      "1m",
			TimeoutQueue:          "5s",
			TimeoutServer:         "50s",
			TimeoutServerFin:      "50s",
			TimeoutTunnel:         "1h",
		},
		ConfigGlobals: types.ConfigGlobals{
			BackendCheckInterval:         "2s",
			BackendServerSlotsIncrement:  32,
			BindIPAddrHealthz:            "*",
			BindIPAddrHTTP:               "*",
			BindIPAddrStats:              "*",
			BindIPAddrTCP:                "*",
			ConfigFrontend:               "",
			ConfigGlobal:                 "",
			DNSAcceptedPayloadSize:       8192,
			DNSClusterDomain:             "cluster.local",
			DNSHoldObsolete:              "0s",
			DNSHoldValid:                 "1s",
			DNSResolvers:                 "",
			DNSTimeoutRetry:              "1s",
			DrainSupport:                 false,
			DynamicScaling:               false,
			Forwardfor:                   "add",
			HealthzPort:                  10253,
			HTTPLogFormat:                "",
			HTTPPort:                     80,
			HTTPSLogFormat:               "",
			HTTPSPort:                    443,
			HTTPStoHTTPPort:              0,
			LoadServerState:              false,
			MaxConnections:               2000,
			ModsecurityEndpoints:         "",
			ModsecurityTimeoutHello:      "100ms",
			ModsecurityTimeoutIdle:       "30s",
			ModsecurityTimeoutProcessing: "1s",
			NbprocBalance:                1,
			NbprocSSL:                    0,
			Nbthread:                     1,
			NoTLSRedirectLocations:       "/.well-known/acme-challenge",
			SSLCiphers:                   defaultSSLCiphers,
			SSLDHDefaultMaxSize:          2048,
			SSLDHParam:                   "",
			SSLEngine:                    "",
			SSLHeadersPrefix:             "X-SSL",
			SSLModeAsync:                 false,
			SSLOptions:                   "no-sslv3 no-tls-tickets",
			StatsAuth:                    "",
			StatsPort:                    1936,
			StatsProxyProtocol:           false,
			StatsSSLCert:                 "",
			StrictHost:                   true,
			Syslog:                       "",
			TCPLogFormat:                 "",
			TimeoutStop:                  "",
			UseProxyProtocol:             false,
		},
	}
}

func mergeConfig(configDefault *types.Config, config map[string]string) *types.Config {
	utils.MergeMap(config, configDefault)
	return configDefault
}
