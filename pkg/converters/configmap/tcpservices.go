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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// TCPServicesConverter ...
type TCPServicesConverter interface {
	Sync(tcpservices map[string]string)
}

// NewTCPServicesConverter ...
func NewTCPServicesConverter(logger types.Logger, haproxy haproxy.Config, cache convtypes.Cache) TCPServicesConverter {
	return &tcpSvcConverter{
		logger:  logger,
		cache:   cache,
		haproxy: haproxy,
	}
}

type tcpSvcConverter struct {
	logger  types.Logger
	cache   convtypes.Cache
	haproxy haproxy.Config
}

var regexValidTime = regexp.MustCompile(`^[0-9]+(us|ms|s|m|h|d)$`)

func (c *tcpSvcConverter) Sync(tcpservices map[string]string) {
	c.haproxy.TCPBackends().RemoveAll()

	// map[key]value is:
	// - key   => port to expose
	// - value => <service-name>:<port>:[<PROXY>]:[<PROXY[-<V1|V2>]]:<secret-name-cert>:check-interval:<secret-name-ca>
	//   - 0: namespace/name of the target service
	//   - 1: target port number
	//   - 2: "PROXY" means accept proxy protocol
	//   - 3: "PROXY[-V1|V2]" means send proxy protocol, defaults to V2
	//   - 4: namespace/name of crt/key secret if should ssl-offload
	//   - 5: check interval
	//   - 6: namespace/name of ca/crl secret if should verify client ssl
	for k, v := range tcpservices {
		publicport, err := strconv.Atoi(k)
		if err != nil {
			c.logger.Warn("skipping invalid public listening port of TCP service: %s", k)
			continue
		}
		svc := c.parseService(v)
		if svc.name == "" {
			c.logger.Warn("skipping empty TCP service name on public port %d", publicport)
			continue
		}
		service, err := c.cache.GetService(svc.name)
		if err != nil {
			c.logger.Warn("skipping TCP service on public port %d: %v", publicport, err)
			continue
		}
		svcport := convutils.FindServicePort(service, svc.port)
		if svcport == nil {
			c.logger.Warn("skipping TCP service on public port %d: port not found: %s:%s", publicport, svc.name, svc.port)
			continue
		}
		addrs, _, err := convutils.CreateEndpoints(c.cache, service, svcport)
		if err != nil {
			c.logger.Warn("skipping TCP service on public port %d: %v", svc.port, err)
			continue
		}
		var crtfile convtypes.CrtFile
		if svc.secretTLS != "" {
			crtfile, err = c.cache.GetTLSSecretPath("", svc.secretTLS, convtypes.TrackingTarget{})
			if err != nil {
				c.logger.Warn("skipping TCP service on public port %d: %v", publicport, err)
				continue
			}
		}
		var cafile, crlfile convtypes.File
		if svc.secretCA != "" {
			cafile, crlfile, err = c.cache.GetCASecretPath("", svc.secretCA, convtypes.TrackingTarget{})
			if err != nil {
				c.logger.Warn("skipping TCP service on public port %d: %v", publicport, err)
				continue
			}
		}
		checkInterval := "2s"
		if svc.checkInt != "" {
			if svc.checkInt == "-" {
				checkInterval = ""
			} else if regexValidTime.MatchString(svc.checkInt) {
				checkInterval = svc.checkInt
			} else {
				c.logger.Warn(
					"using default check interval '%s' due to an invalid time config on TCP service %d: %s",
					checkInterval, publicport, svc.checkInt)
			}
		}
		servicename := fmt.Sprintf("%s_%s", service.Namespace, service.Name)
		backend := c.haproxy.TCPBackends().Acquire(servicename, publicport)
		for _, addr := range addrs {
			backend.AddEndpoint(addr.IP, addr.Port)
		}
		backend.ProxyProt.Decode = strings.ToLower(svc.inProxy) == "proxy"
		backend.CheckInterval = checkInterval
		switch strings.ToLower(svc.outProxy) {
		case "proxy", "proxy-v2":
			backend.ProxyProt.EncodeVersion = "v2"
		case "proxy-v1":
			backend.ProxyProt.EncodeVersion = "v1"
		}
		backend.SSL.Filename = crtfile.Filename
		backend.SSL.CAFilename = cafile.Filename
		backend.SSL.CRLFilename = crlfile.Filename
	}
}

type tcpSvc struct {
	name      string
	port      string
	inProxy   string
	outProxy  string
	secretTLS string
	secretCA  string
	checkInt  string
}

func (c *tcpSvcConverter) parseService(service string) *tcpSvc {
	svc := make([]string, 7)
	for i, v := range strings.Split(service, ":") {
		if i < 7 {
			svc[i] = v
		}
	}
	return &tcpSvc{
		name:      svc[0],
		port:      svc[1],
		inProxy:   svc[2],
		outProxy:  svc[3],
		secretTLS: svc[4],
		checkInt:  svc[5],
		secretCA:  svc[6],
	}
}
