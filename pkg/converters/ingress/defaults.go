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
)

const (
	defaultSSLCiphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
)

func createDefaults() (ann map[string]string, global *types.ConfigGlobals) {
	ann = map[string]string{
		types.HostTimeoutClient:         "50s",
		types.HostTimeoutClientFin:      "50s",
		types.BackBackendServerSlotsInc: "32",
		types.BackBalanceAlgorithm:      "roundrobin",
		types.BackHSTS:                  "true",
		types.BackHSTSIncludeSubdomains: "false",
		types.BackHSTSMaxAge:            "15768000",
		types.BackHSTSPreload:           "false",
		types.BackSessionCookieDynamic:  "true",
		types.BackSSLRedirect:           "true",
		types.BackTimeoutConnect:        "5s",
		types.BackTimeoutHTTPRequest:    "5s",
		types.BackTimeoutKeepAlive:      "1m",
		types.BackTimeoutQueue:          "5s",
		types.BackTimeoutServer:         "50s",
		types.BackTimeoutServerFin:      "50s",
		types.BackTimeoutTunnel:         "1h",
	}
	global = &types.ConfigGlobals{
		BackendCheckInterval:         "2s",
		BindIPAddrHealthz:            "*",
		BindIPAddrHTTP:               "*",
		BindIPAddrStats:              "*",
		BindIPAddrTCP:                "*",
		ConfigDefaults:               "",
		ConfigFrontend:               "",
		ConfigGlobal:                 "",
		CookieKey:                    "Ingress",
		DNSAcceptedPayloadSize:       8192,
		DNSClusterDomain:             "cluster.local",
		DNSHoldObsolete:              "0s",
		DNSHoldValid:                 "1s",
		DNSResolvers:                 "",
		DNSTimeoutRetry:              "1s",
		DrainSupport:                 false,
		DrainSupportRedispatch:       true,
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
		SyslogEndpoint:               "",
		SyslogFormat:                 "rfc5424",
		SyslogTag:                    "ingress",
		TCPLogFormat:                 "",
		TimeoutClient:                ann[types.HostTimeoutClient],
		TimeoutClientFin:             ann[types.HostTimeoutClientFin],
		TimeoutConnect:               ann[types.BackTimeoutConnect],
		TimeoutHTTPRequest:           ann[types.BackTimeoutHTTPRequest],
		TimeoutKeepAlive:             ann[types.BackTimeoutKeepAlive],
		TimeoutQueue:                 ann[types.BackTimeoutQueue],
		TimeoutServer:                ann[types.BackTimeoutServer],
		TimeoutServerFin:             ann[types.BackTimeoutServerFin],
		TimeoutStop:                  "",
		TimeoutTunnel:                ann[types.BackTimeoutTunnel],
		UseProxyProtocol:             false,
	}
	return ann, global
}
