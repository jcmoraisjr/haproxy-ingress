/*
Copyright 2017 The Kubernetes Authors.

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

package controller

import (
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxybackend"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/alias"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/auth"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/authreq"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/authtls"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/balance"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/bluegreen"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/clientbodybuffersize"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/connection"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/cors"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/defaultbackend"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/dnsresolvers"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/healthcheck"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/hsts"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/ipwhitelist"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/portinredirect"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/ratelimit"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/redirect"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/rewrite"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/secureupstream"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/serversnippet"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/serviceupstream"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/sessionaffinity"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/slotsincrement"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/snippet"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/sslpassthrough"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/upstreamhashby"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/upstreamvhost"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/vtsfilterkey"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/waf"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/errors"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	extensions "k8s.io/api/extensions/v1beta1"
)

type extractorConfig interface {
	resolver.AuthCertificate
	resolver.DefaultBackend
	resolver.Secret
	resolver.Configuration
	resolver.Service
}

type annotationExtractor struct {
	secretResolver resolver.Secret
	annotations    map[string]parser.IngressAnnotation
}

func newAnnotationExtractor(cfg extractorConfig) annotationExtractor {
	return annotationExtractor{
		cfg,
		map[string]parser.IngressAnnotation{
			"Balance":              balance.NewParser(cfg),
			"BasicDigestAuth":      auth.NewParser(auth.AuthDirectory, cfg, cfg),
			"ExternalAuth":         authreq.NewParser(),
			"CertificateAuth":      authtls.NewParser(cfg),
			"CorsConfig":           cors.NewParser(),
			"UseResolver":          dnsresolvers.NewParser(cfg),
			"HealthCheck":          healthcheck.NewParser(cfg),
			"HSTS":                 hsts.NewParser(cfg),
			"Whitelist":            ipwhitelist.NewParser(cfg),
			"UsePortInRedirects":   portinredirect.NewParser(cfg),
			"Proxy":                proxy.NewParser(cfg),
			"ProxyBackend":         proxybackend.NewParser(),
			"RateLimit":            ratelimit.NewParser(cfg),
			"Connection":           connection.NewParser(),
			"Redirect":             redirect.NewParser(),
			"Rewrite":              rewrite.NewParser(cfg),
			"SecureUpstream":       secureupstream.NewParser(cfg, cfg),
			"ServiceUpstream":      serviceupstream.NewParser(),
			"SessionAffinity":      sessionaffinity.NewParser(),
			"SlotsIncrement":       slotsincrement.NewParser(cfg),
			"WAF":                  waf.NewParser(),
			"BlueGreen":            bluegreen.NewParser(),
			"SSLPassthrough":       sslpassthrough.NewParser(),
			"ConfigurationSnippet": snippet.NewParser(),
			"Alias":                alias.NewParser(),
			"ClientBodyBufferSize": clientbodybuffersize.NewParser(),
			"DefaultBackend":       defaultbackend.NewParser(cfg),
			"UpstreamHashBy":       upstreamhashby.NewParser(),
			"UpstreamVhost":        upstreamvhost.NewParser(),
			"VtsFilterKey":         vtsfilterkey.NewParser(),
			"ServerSnippet":        serversnippet.NewParser(),
		},
	}
}

func (e *annotationExtractor) Extract(ing *extensions.Ingress) map[string]interface{} {
	anns := make(map[string]interface{})
	for name, annotationParser := range e.annotations {
		val, err := annotationParser.Parse(ing)
		glog.V(5).Infof("annotation %v in Ingress %v/%v: %v", name, ing.GetNamespace(), ing.GetName(), val)
		if err != nil {
			if errors.IsMissingAnnotations(err) {
				continue
			}

			if !errors.IsLocationDenied(err) {
				glog.Errorf("error parsing annotation %v/%v: %v", ing.Namespace, ing.Name, err)
				continue
			}

			_, alreadyDenied := anns[DeniedKeyName]
			if !alreadyDenied {
				anns[DeniedKeyName] = err
				glog.Errorf("error reading %v annotation in Ingress %v/%v: %v", name, ing.GetNamespace(), ing.GetName(), err)
				continue
			}

			glog.V(5).Infof("error reading %v annotation in Ingress %v/%v: %v", name, ing.GetNamespace(), ing.GetName(), err)
		}

		if val != nil {
			anns[name] = val
		}
	}

	return anns
}

const (
	balanceAlgorithm     = "Balance"
	secureUpstream       = "SecureUpstream"
	healthCheck          = "HealthCheck"
	blueGreen            = "BlueGreen"
	proxyBackend         = "ProxyBackend"
	sslPassthrough       = "SSLPassthrough"
	configSnippet        = "ConfigurationSnippet"
	sessionAffinity      = "SessionAffinity"
	serviceUpstream      = "ServiceUpstream"
	slotsIncrement       = "SlotsIncrement"
	conn                 = "Connection"
	serverAlias          = "Alias"
	corsConfig           = "CorsConfig"
	clientBodyBufferSize = "ClientBodyBufferSize"
	certificateAuth      = "CertificateAuth"
	serverSnippet        = "ServerSnippet"
	upstreamHashBy       = "UpstreamHashBy"
	useResolver          = "UseResolver"
)

func (e *annotationExtractor) BalanceAlgorithm(ing *extensions.Ingress) string {
	val, _ := e.annotations[balanceAlgorithm].Parse(ing)
	return val.(string)
}

func (e *annotationExtractor) ServiceUpstream(ing *extensions.Ingress) bool {
	val, _ := e.annotations[serviceUpstream].Parse(ing)
	return val.(bool)
}

func (e *annotationExtractor) SecureUpstream(ing *extensions.Ingress) *secureupstream.Secure {
	val, err := e.annotations[secureUpstream].Parse(ing)
	if err != nil {
		glog.Errorf("error parsing secure upstream: %v", err)
	}
	secure := val.(*secureupstream.Secure)
	return secure
}

func (e *annotationExtractor) SlotsIncrement(ing *extensions.Ingress) int {
	val, _ := e.annotations[slotsIncrement].Parse(ing)
	return val.(int)
}

func (e *annotationExtractor) Connection(ing *extensions.Ingress) *connection.Config {
	val, _ := e.annotations[conn].Parse(ing)
	return val.(*connection.Config)
}

func (e *annotationExtractor) HealthCheck(ing *extensions.Ingress) *healthcheck.Upstream {
	val, _ := e.annotations[healthCheck].Parse(ing)
	return val.(*healthcheck.Upstream)
}

func (e *annotationExtractor) BlueGreen(ing *extensions.Ingress) *bluegreen.Config {
	val, err := e.annotations[blueGreen].Parse(ing)
	if err != nil {
		return &bluegreen.Config{
			DeployWeight: []bluegreen.DeployWeight{},
		}
	}
	return val.(*bluegreen.Config)
}

func (e *annotationExtractor) ProxyBackend(ing *extensions.Ingress) *proxybackend.Config {
	val, err := e.annotations[proxyBackend].Parse(ing)
	if err != nil {
		return &proxybackend.Config{}
	}
	return val.(*proxybackend.Config)
}

func (e *annotationExtractor) SSLPassthrough(ing *extensions.Ingress) bool {
	val, _ := e.annotations[sslPassthrough].Parse(ing)
	return val.(bool)
}

func (e *annotationExtractor) ConfigurationSnippet(ing *extensions.Ingress) snippet.Config {
	val, _ := e.annotations[configSnippet].Parse(ing)
	return val.(snippet.Config)
}

func (e *annotationExtractor) Alias(ing *extensions.Ingress) string {
	val, _ := e.annotations[serverAlias].Parse(ing)
	return val.(string)
}

func (e *annotationExtractor) ClientBodyBufferSize(ing *extensions.Ingress) string {
	val, _ := e.annotations[clientBodyBufferSize].Parse(ing)
	return val.(string)
}

func (e *annotationExtractor) SessionAffinity(ing *extensions.Ingress) *sessionaffinity.AffinityConfig {
	val, _ := e.annotations[sessionAffinity].Parse(ing)
	return val.(*sessionaffinity.AffinityConfig)
}

func (e *annotationExtractor) Cors(ing *extensions.Ingress) *cors.CorsConfig {
	val, _ := e.annotations[corsConfig].Parse(ing)
	return val.(*cors.CorsConfig)
}

func (e *annotationExtractor) CertificateAuth(ing *extensions.Ingress) *authtls.AuthSSLConfig {
	val, err := e.annotations[certificateAuth].Parse(ing)
	if errors.IsMissingAnnotations(err) {
		return nil
	}

	if err != nil {
		glog.Errorf("error parsing certificate auth: %v", err)
	}
	secure := val.(*authtls.AuthSSLConfig)
	return secure
}

func (e *annotationExtractor) ServerSnippet(ing *extensions.Ingress) string {
	val, _ := e.annotations[serverSnippet].Parse(ing)
	return val.(string)
}

func (e *annotationExtractor) UpstreamHashBy(ing *extensions.Ingress) string {
	val, _ := e.annotations[upstreamHashBy].Parse(ing)
	return val.(string)
}

func (e *annotationExtractor) UseResolver(ing *extensions.Ingress) string {
	val, _ := e.annotations[useResolver].Parse(ing)
	return val.(string)
}
