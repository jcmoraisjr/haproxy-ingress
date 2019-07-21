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

package annotations

import (
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
)

func (c *updater) buildHostAuthTLS(d *hostData) {
	tlsSecret, _, foundTLSSecret := d.mapper.GetStr(ingtypes.HostAuthTLSSecret)
	if !foundTLSSecret {
		return
	}
	verify := d.mapper.GetStrValue(ingtypes.HostAuthTLSVerifyClient)
	if verify == "off" {
		return
	}
	if cafile, err := c.cache.GetCASecretPath(tlsSecret); err == nil {
		d.host.TLS.CAFilename = cafile.Filename
		d.host.TLS.CAHash = cafile.SHA1Hash
		d.host.TLS.CAVerifyOptional = verify == "optional" || verify == "optional_no_ca"
		d.host.TLS.CAErrorPage = d.mapper.GetStrValue(ingtypes.HostAuthTLSErrorPage)
	} else {
		c.logger.Error("error building TLS auth config: %v", err)
	}
}

func (c *updater) buildHostSSLPassthrough(d *hostData) {
	sslpassthrough, srcSSLPassthrough, _ := d.mapper.GetBool(ingtypes.HostSSLPassthrough)
	if !sslpassthrough {
		return
	}
	rootPath := d.host.FindPath("/")
	if rootPath == nil {
		c.logger.Warn("skipping SSL of %s: root path was not configured", srcSSLPassthrough)
		return
	}
	for _, path := range d.host.Paths {
		if path.Path != "/" {
			c.logger.Warn("ignoring path '%s' from %s: ssl-passthrough only support root path", path.Path, srcSSLPassthrough)
		}
	}
	sslpassHTTPPort, _, foundSSLPassHTTPPort := d.mapper.GetStr(ingtypes.HostSSLPassthroughHTTPPort)
	if foundSSLPassHTTPPort {
		httpBackend := c.haproxy.FindBackend(rootPath.Backend.Namespace, rootPath.Backend.Name, sslpassHTTPPort)
		if httpBackend != nil {
			d.host.HTTPPassthroughBackend = httpBackend.ID
		}
	}
	backend := c.haproxy.AcquireBackend(rootPath.Backend.Namespace, rootPath.Backend.Name, rootPath.Backend.Port)
	backend.ModeTCP = true
	d.host.SSLPassthrough = true
}
