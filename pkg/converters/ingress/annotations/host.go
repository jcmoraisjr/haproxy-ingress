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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func (c *updater) setAuthTLSConfig(mapper *Mapper, target *types.TLSConfig, hostname string) bool {
	tlsSecret := mapper.Get(ingtypes.HostAuthTLSSecret)
	if tlsSecret.Source == nil || tlsSecret.Value == "" {
		return false
	}
	verify := mapper.Get(ingtypes.HostAuthTLSVerifyClient)
	if verify.Value == "off" {
		return false
	}
	tls := target
	if cafile, crlfile, err := c.cache.GetCASecretPath(
		tlsSecret.Source.Namespace,
		tlsSecret.Value,
		[]convtypes.TrackingRef{{Context: convtypes.ResourceHAHostname, UniqueName: hostname}},
	); err == nil {
		tls.CAFilename = cafile.Filename
		tls.CAHash = cafile.SHA1Hash
		tls.CRLFilename = crlfile.Filename
		tls.CRLHash = crlfile.SHA1Hash
	} else {
		c.logger.Error("error building TLS auth config on %s: %v", tlsSecret.Source, err)
	}
	if tls.CAFilename == "" && mapper.Get(ingtypes.HostAuthTLSStrict).Bool() {
		// Here we have a misconfigured auth-tls and auth-tls-strict as `true`.
		// Using a fake and self-generated CA so any connection attempt will fail with
		// HTTP 495 (invalid crt) or 496 (crt wasn't provided) instead of allow the request.
		tls.CAFilename = c.fakeCA.Filename
		tls.CAHash = c.fakeCA.SHA1Hash
	}
	switch verify.Value {
	case "optional_no_ca":
		tls.CAVerify = types.CAVerifySkipCheck
	case "optional":
		tls.CAVerify = types.CAVerifyOptional
	case "on":
		tls.CAVerify = types.CAVerifyAlways
	default:
		if tls.CAFilename != "" {
			tls.CAVerify = types.CAVerifyAlways
		}
	}
	return true
}

func (c *updater) buildTCPAuthTLS(d *tcpData) {
	_ = c.setAuthTLSConfig(d.mapper, &d.tcpPort.TLS, d.tcpHost.Hostname())
}

func (c *updater) buildHostAuthTLS(d *hostData) {
	if c.setAuthTLSConfig(d.mapper, &d.host.TLS.TLSConfig, d.host.Hostname) {
		d.host.TLS.CAErrorPage = d.mapper.Get(ingtypes.HostAuthTLSErrorPage).Value
	}
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
	redir := d.mapper.Get(ingtypes.HostRedirectFrom)
	if target := c.haproxy.Hosts().FindTargetRedirect(redir.Value, false); target != nil {
		c.logger.Warn("ignoring redirect from '%s' on %v, it's already targeting to '%s'",
			redir.Value, redir.Source, target.Hostname)
	} else if len(d.host.Paths) > 0 {
		d.host.Redirect.RedirectHost = redir.Value
	}
	redirRegex := d.mapper.Get(ingtypes.HostRedirectFromRegex)
	if target := c.haproxy.Hosts().FindTargetRedirect(redirRegex.Value, true); target != nil {
		c.logger.Warn("ignoring regex redirect from '%s' on %v, it's already targeting to '%s'",
			redirRegex.Value, redirRegex.Source, target.Hostname)
	} else if len(d.host.Paths) > 0 {
		d.host.Redirect.RedirectHostRegex = redirRegex.Value
	}
}

func (c *updater) buildHostSSLPassthrough(d *hostData) {
	sslpassthrough := d.mapper.Get(ingtypes.HostSSLPassthrough)
	if !sslpassthrough.Bool() {
		return
	}
	rootPaths := d.host.FindPath("/")
	if len(rootPaths) == 0 {
		c.logger.Warn("skipping SSL of %s: root path was not configured", sslpassthrough.Source)
		return
	}
	hostBackend := rootPaths[0].Backend
	sslpassHTTPPort := d.mapper.Get(ingtypes.HostSSLPassthroughHTTPPort)
	if sslpassHTTPPort.Source != nil {
		httpBackend := c.haproxy.Backends().FindBackend(hostBackend.Namespace, hostBackend.Name, sslpassHTTPPort.Value)
		if httpBackend != nil {
			d.host.HTTPPassthroughBackend = httpBackend.ID
		}
	}
	backend := c.haproxy.Backends().AcquireBackend(hostBackend.Namespace, hostBackend.Name, hostBackend.Port)
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
