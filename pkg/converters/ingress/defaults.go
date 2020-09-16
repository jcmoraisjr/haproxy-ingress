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
	defaultSSLOptions = "no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets"
	// TLS up to 1.2
	defaultSSLCiphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
	// TLS 1.3
	defaultSSLCipherSuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
)

func createDefaults() map[string]string {
	return map[string]string{
		types.HostAuthTLSStrict:   "false",
		types.HostSSLCiphers:      defaultSSLCiphers,
		types.HostSSLCipherSuites: defaultSSLCipherSuites,
		types.HostSSLOptionsHost:  "",
		types.HostTLSALPN:         "h2,http/1.1",
		//
		types.BackBackendServerNaming:    "sequence",
		types.BackBackendServerSlotsInc:  "1",
		types.BackSlotsMinFree:           "6",
		types.BackBalanceAlgorithm:       "roundrobin",
		types.BackCorsAllowHeaders:       "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization",
		types.BackCorsAllowMethods:       "GET, PUT, POST, DELETE, PATCH, OPTIONS",
		types.BackCorsAllowOrigin:        "*",
		types.BackCorsMaxAge:             "86400",
		types.BackDynamicScaling:         "true",
		types.BackHealthCheckInterval:    "2s",
		types.BackHSTS:                   "true",
		types.BackHSTSIncludeSubdomains:  "false",
		types.BackHSTSMaxAge:             "15768000",
		types.BackHSTSPreload:            "false",
		types.BackInitialWeight:          "1",
		types.BackSessionCookieDynamic:   "true",
		types.BackSessionCookiePreserve:  "false",
		types.BackSessionCookieValue:     "server-name",
		types.BackSSLRedirect:            "true",
		types.BackSSLCipherSuitesBackend: defaultSSLCipherSuites,
		types.BackSSLCiphersBackend:      defaultSSLCiphers,
		types.BackSSLOptionsBackend:      defaultSSLOptions,
		types.BackTimeoutConnect:         "5s",
		types.BackTimeoutHTTPRequest:     "5s",
		types.BackTimeoutKeepAlive:       "1m",
		types.BackTimeoutQueue:           "5s",
		types.BackTimeoutServer:          "50s",
		types.BackTimeoutServerFin:       "50s",
		types.BackTimeoutTunnel:          "1h",
		types.BackWAFMode:                "deny",
		//
		types.GlobalAcmeExpiring:                 "30",
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
		types.GlobalModsecurityTimeoutConnect:    "5s",
		types.GlobalModsecurityTimeoutHello:      "100ms",
		types.GlobalModsecurityTimeoutIdle:       "30s",
		types.GlobalModsecurityTimeoutProcessing: "1s",
		types.GlobalModsecurityTimeoutServer:     "5s",
		types.GlobalNbprocBalance:                "1",
		types.GlobalNbthread:                     "2",
		types.GlobalNoTLSRedirectLocations:       "/.well-known/acme-challenge",
		types.GlobalPathTypeOrder:                "exact,prefix,begin,regex",
		types.GlobalSSLDHDefaultMaxSize:          "2048",
		types.GlobalSSLHeadersPrefix:             "X-SSL",
		types.GlobalSSLOptions:                   defaultSSLOptions,
		types.GlobalStatsPort:                    "1936",
		types.GlobalSyslogFormat:                 "rfc5424",
		types.GlobalSyslogLength:                 "1024",
		types.GlobalSyslogTag:                    "ingress",
		types.GlobalTimeoutClient:                "50s",
		types.GlobalTimeoutClientFin:             "50s",
		types.GlobalTimeoutStop:                  "10m",
		types.GlobalUseCpuMap:                    "true",
		types.GlobalUseForwardedProto:            "true",
		types.GlobalUseHTX:                       "true",
	}
}
