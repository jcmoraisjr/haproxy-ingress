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

func (c *updater) buildHostAuthTLS(d *hostData) {
	if d.ann.AuthTLSSecret == "" {
		return
	}
	verify := d.ann.AuthTLSVerifyClient
	if verify == "off" {
		return
	}
	if cafile, err := c.cache.GetCASecretPath(d.ann.AuthTLSSecret); err == nil {
		d.host.TLS.CAFilename = cafile.Filename
		d.host.TLS.CAHash = cafile.SHA1Hash
		d.host.TLS.CAVerifyOptional = verify == "optional" || verify == "optional_no_ca"
		d.host.TLS.CAErrorPage = d.ann.AuthTLSErrorPage
		d.host.TLS.AddCertHeader = d.ann.AuthTLSCertHeader
	} else {
		c.logger.Error("error building TLS auth config: %v", err)
	}
}

func (c *updater) buildHostSSLPassthrough(d *hostData) {
	if !d.ann.SSLPassthrough {
		return
	}
	rootPath := d.host.FindPath("/")
	if rootPath == nil {
		c.logger.Warn("skipping SSL of %s: root path was not configured", d.ann.Source)
		return
	}
	for _, path := range d.host.Paths {
		if path.Path != "/" {
			c.logger.Warn("ignoring path '%s' from '%s': ssl-passthrough only support root path", path.Path, d.ann.Source)
		}
	}
	if d.ann.SSLPassthroughHTTPPort != 0 {
		httpBackend := c.haproxy.FindBackend(rootPath.Backend.Namespace, rootPath.Backend.Name, d.ann.SSLPassthroughHTTPPort)
		d.host.HTTPPassthroughBackend = httpBackend
	}
	rootPath.Backend.ModeTCP = true
	d.host.SSLPassthrough = true
}
