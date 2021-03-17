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
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

func (c *updater) buildHostAuthTLS(d *hostData) {
	tlsSecret := d.mapper.Get(ingtypes.HostAuthTLSSecret)
	if tlsSecret.Source == nil || tlsSecret.Value == "" {
		return
	}
	verify := d.mapper.Get(ingtypes.HostAuthTLSVerifyClient)
	if verify.Value == "off" {
		return
	}
	tls := &d.host.TLS
	if cafile, crlfile, err := c.cache.GetCASecretPath(
		tlsSecret.Source.Namespace,
		tlsSecret.Value,
		convtypes.TrackingTarget{Hostname: d.host.Hostname},
	); err == nil {
		tls.CAFilename = cafile.Filename
		tls.CAHash = cafile.SHA1Hash
		tls.CRLFilename = crlfile.Filename
		tls.CRLHash = crlfile.SHA1Hash
	} else {
		c.logger.Error("error building TLS auth config on %s: %v", tlsSecret.Source, err)
	}
	if tls.CAFilename == "" && d.mapper.Get(ingtypes.HostAuthTLSStrict).Bool() {
		// Here we have a misconfigured auth-tls and auth-tls-strict as `true`.
		// Using a fake and self-generated CA so any connection attempt will fail with
		// HTTP 495 (invalid crt) or 496 (crt wasn't provided) instead of allow the request.
		tls.CAFilename = c.fakeCA.Filename
		tls.CAHash = c.fakeCA.SHA1Hash
	}
	tls.CAVerifyOptional = verify.Value == "optional" || verify.Value == "optional_no_ca"
	tls.CAErrorPage = d.mapper.Get(ingtypes.HostAuthTLSErrorPage).Value
}

func (c *updater) buildHostCertSigner(d *hostData) {
	signer := d.mapper.Get(ingtypes.HostCertSigner)
	if signer.Value == "" {
		return
	}
	if signer.Value != "acme" {
		c.logger.Warn("ignoring invalid cert-signer on %v: %s", signer.Source, signer.Value)
		return
	}
	acmeData := c.haproxy.AcmeData()
	if acmeData.Endpoint == "" || acmeData.Emails == "" {
		c.logger.Warn("ignoring acme signer on %v due to missing endpoint or email config", signer.Source)
		return
	}
	// just the warnings, ingress.syncIngress() has already added the domains
}

func (c *updater) buildHostRedirect(d *hostData) {
	// TODO need a host<->host tracking if a target is found
	redir := d.mapper.Get(ingtypes.HostServerRedirect)
	if target := c.haproxy.Hosts().FindTargetRedirect(redir.Value, false); target != nil {
		c.logger.Warn("ignoring redirect from '%s' on %v, it's already targeting to '%s'",
			redir.Value, redir.Source, target.Hostname)
	} else {
		d.host.Redirect.RedirectHost = redir.Value
	}
	redirRegex := d.mapper.Get(ingtypes.HostServerRedirectRegex)
	if target := c.haproxy.Hosts().FindTargetRedirect(redirRegex.Value, true); target != nil {
		c.logger.Warn("ignoring regex redirect from '%s' on %v, it's already targeting to '%s'",
			redirRegex.Value, redirRegex.Source, target.Hostname)
	} else {
		d.host.Redirect.RedirectHostRegex = redirRegex.Value
	}
	d.host.Redirect.RedirectCode = d.mapper.Get(ingtypes.HostServerRedirectCode).Int()
}

func (c *updater) buildHostSSLPassthrough(d *hostData) {
	sslpassthrough := d.mapper.Get(ingtypes.HostSSLPassthrough)
	if !sslpassthrough.Bool() {
		return
	}
	rootPath := d.host.FindPath("/")
	if rootPath == nil {
		c.logger.Warn("skipping SSL of %s: root path was not configured", sslpassthrough.Source)
		return
	}
	for _, path := range d.host.Paths {
		if path.Path != "/" {
			c.logger.Warn("ignoring path '%s' from %s: ssl-passthrough only support root path", path.Path, sslpassthrough.Source)
		}
	}
	sslpassHTTPPort := d.mapper.Get(ingtypes.HostSSLPassthroughHTTPPort)
	if sslpassHTTPPort.Source != nil {
		httpBackend := c.haproxy.Backends().FindBackend(rootPath.Backend.Namespace, rootPath.Backend.Name, sslpassHTTPPort.Value)
		if httpBackend != nil {
			d.host.HTTPPassthroughBackend = httpBackend.ID
		}
	}
	backend := c.haproxy.Backends().AcquireBackend(rootPath.Backend.Namespace, rootPath.Backend.Name, rootPath.Backend.Port)
	backend.ModeTCP = true
	d.host.SetSSLPassthrough(true)
}

func (c *updater) buildHostTLSConfig(d *hostData) {
	if cfg := d.mapper.Get(ingtypes.HostSSLCiphers); cfg.Source != nil {
		d.host.TLS.Ciphers = cfg.Value
	}
	if cfg := d.mapper.Get(ingtypes.HostSSLCipherSuites); cfg.Source != nil {
		d.host.TLS.CipherSuites = cfg.Value
	}
	if cfg := d.mapper.Get(ingtypes.HostTLSALPN); cfg.Source != nil {
		d.host.TLS.ALPN = cfg.Value
	}
	d.host.TLS.Options = d.mapper.Get(ingtypes.HostSSLOptionsHost).Value
}
