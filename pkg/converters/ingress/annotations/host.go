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
	"fmt"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func (c *updater) buildHTTPFrontBind(d *frontData) {
	d.front.AcceptProxy = d.mapper.Get(ingtypes.FrontUseProxyProtocol).Bool()
	if bindHTTP := d.mapper.Get(ingtypes.FrontBindHTTP).Value; bindHTTP != "" {
		d.front.Bind = bindHTTP
	} else {
		ip := d.mapper.Get(ingtypes.FrontBindIPAddrHTTP).Value
		port := d.mapper.Get(ingtypes.FrontHTTPPort).Int()
		d.front.Bind = fmt.Sprintf("%s:%d", ip, port)
	}
}

func (c *updater) buildHTTPSFrontBind(d *frontData) {
	d.front.AcceptProxy = d.mapper.Get(ingtypes.FrontUseProxyProtocol).Bool()
	if bindHTTPS := d.mapper.Get(ingtypes.FrontBindHTTPS).Value; bindHTTPS != "" {
		d.front.Bind = bindHTTPS
	} else {
		ip := d.mapper.Get(ingtypes.FrontBindIPAddrHTTP).Value
		port := d.mapper.Get(ingtypes.FrontHTTPSPort).Int()
		d.front.Bind = fmt.Sprintf("%s:%d", ip, port)
	}
}

func (c *updater) buildHTTPFrontFrontingProxy(d *frontData) {
	bind := d.mapper.Get(ingtypes.FrontBindFrontingProxy).Value
	if bind == "" {
		port := d.mapper.Get(ingtypes.FrontFrontingProxyPort).Int()
		if port == 0 {
			port = d.mapper.Get(ingtypes.FrontHTTPStoHTTPPort).Int()
		}
		if port == 0 {
			return
		}
		bind = fmt.Sprintf("%s:%d", d.mapper.Get(ingtypes.FrontBindIPAddrHTTP).Value, port)
	}
	d.front.IsFrontingProxy = true
	d.front.IsFrontingUseProto = d.mapper.Get(ingtypes.FrontUseForwardedProto).Bool()
	d.front.Bind = bind
}

func (c *updater) buildHostAuthExternal(d *hostData) {
	isFrontend := d.mapper.Get(ingtypes.BackAuthExternalPlacement).ToLower() == "frontend"
	url := d.mapper.Get(ingtypes.BackAuthURL)
	if isFrontend && url.Value != "" {
		for _, path := range d.host.Paths {
			c.setAuthExternal(d.mapper, &path.AuthExtFront, url)
		}
	}
}

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
	hostname := d.tcpHost.Hostname()
	tcpTLSConfig := d.tcpPort.TLS[hostname]
	if tcpTLSConfig != nil {
		// only exists on TLS TCP services
		_ = c.setAuthTLSConfig(d.mapper, &tcpTLSConfig.TLSConfig, hostname)
	}
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
	redirOnPort := func(port int32) {
		f := c.haproxy.Frontends().FindFrontend(port)
		if f == nil {
			return
		}
		redir := d.mapper.Get(ingtypes.HostRedirectFrom)
		if target := f.FindTargetRedirect(redir.Value, false); target != nil {
			c.logger.Warn("ignoring redirect from '%s' port %d on %v, it's already targeting to '%s'",
				redir.Value, port, redir.Source, target.Hostname)
		} else if len(d.host.Paths) > 0 {
			d.host.Redirect.RedirectHost = redir.Value
		}
		redirRegex := d.mapper.Get(ingtypes.HostRedirectFromRegex)
		if target := f.FindTargetRedirect(redirRegex.Value, true); target != nil {
			c.logger.Warn("ignoring regex redirect from '%s' port %d on %v, it's already targeting to '%s'",
				redirRegex.Value, port, redirRegex.Source, target.Hostname)
		} else if len(d.host.Paths) > 0 {
			d.host.Redirect.RedirectHostRegex = redirRegex.Value
		}
	}
	redirOnPort(d.mapper.Get(ingtypes.FrontHTTPPort).Int32())
	redirOnPort(d.mapper.Get(ingtypes.FrontHTTPSPort).Int32())
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

func (c *updater) buildHostCustomResponses(d *hostData) {
	d.host.CustomHTTPResponses = c.buildHTTPResponses(d.mapper, keyScopeHost)
}
