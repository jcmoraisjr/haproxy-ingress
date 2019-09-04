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

func createDefaults() map[string]string {
	return map[string]string{
		types.HostTimeoutClient:    "50s",
		types.HostTimeoutClientFin: "50s",
		//
		types.BackBackendServerSlotsInc: "32",
		types.BackBalanceAlgorithm:      "roundrobin",
		types.BackCorsAllowHeaders:      "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
		types.BackCorsAllowMethods:      "GET, PUT, POST, DELETE, PATCH, OPTIONS",
		types.BackCorsAllowOrigin:       "*",
		types.BackCorsMaxAge:            "86400",
		types.BackHealthCheckInterval:   "2s",
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
		//
		types.GlobalBindIPAddrHealthz:            "*",
		types.GlobalBindIPAddrHTTP:               "*",
		types.GlobalBindIPAddrStats:              "*",
		types.GlobalBindIPAddrTCP:                "*",
		types.GlobalCookieKey:                    "Ingress",
		types.GlobalDNSAcceptedPayloadSize:       "8192",
		types.GlobalDNSClusterDomain:             "cluster.local",
		types.GlobalDNSHoldObsolete:              "0s",
		types.GlobalDNSHoldValid:                 "1s",
		types.GlobalDNSTimeoutRetry:              "1s",
		types.GlobalDrainSupportRedispatch:       "true",
		types.GlobalForwardfor:                   "add",
		types.GlobalHealthzPort:                  "10253",
		types.GlobalHTTPPort:                     "80",
		types.GlobalHTTPSPort:                    "443",
		types.GlobalMaxConnections:               "2000",
		types.GlobalModsecurityTimeoutHello:      "100ms",
		types.GlobalModsecurityTimeoutIdle:       "30s",
		types.GlobalModsecurityTimeoutProcessing: "1s",
		types.GlobalNbprocBalance:                "1",
		types.GlobalNbthread:                     "1",
		types.GlobalNoTLSRedirectLocations:       "/.well-known/acme-challenge",
		types.GlobalSSLCiphers:                   defaultSSLCiphers,
		types.GlobalSSLDHDefaultMaxSize:          "2048",
		types.GlobalSSLHeadersPrefix:             "X-SSL",
		types.GlobalSSLOptions:                   "no-sslv3 no-tls-tickets",
		types.GlobalStatsPort:                    "1936",
		types.GlobalSyslogFormat:                 "rfc5424",
		types.GlobalSyslogTag:                    "ingress",
		types.GlobalTimeoutStop:                  "10m",
		types.GlobalTLSALPN:                      "h2,http/1.1",
	}
}
