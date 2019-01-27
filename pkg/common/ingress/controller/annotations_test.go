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
	"fmt"
	"testing"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/sslpassthrough"

	apiv1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
)

const (
	annotationSecureUpstream         = "ingress.kubernetes.io/secure-backends"
	annotationSecureVerifyCACert     = "ingress.kubernetes.io/secure-verify-ca-secret"
	annotationPassthrough            = "ingress.kubernetes.io/ssl-passthrough"
	annotationAffinityType           = "ingress.kubernetes.io/affinity"
	annotationCorsEnabled            = "ingress.kubernetes.io/enable-cors"
	annotationCorsAllowOrigin        = "ingress.kubernetes.io/cors-allow-origin"
	annotationCorsAllowMethods       = "ingress.kubernetes.io/cors-allow-methods"
	annotationCorsAllowHeaders       = "ingress.kubernetes.io/cors-allow-headers"
	annotationCorsAllowCredentials   = "ingress.kubernetes.io/cors-allow-credentials"
	annotationCorsExposeHeaders      = "ingress.kubernetes.io/cors-expose-headers"
	defaultCorsMethods               = "GET, PUT, POST, DELETE, PATCH, OPTIONS"
	defaultCorsHeaders               = "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
	defaultCorsExposeHeaders         = ""
	annotationAffinityCookieName     = "ingress.kubernetes.io/session-cookie-name"
	annotationAffinityCookieStrategy = "ingress.kubernetes.io/session-cookie-strategy"
	annotationAffinityCookieHash     = "ingress.kubernetes.io/session-cookie-hash"
	annotationAffinityCookieDynamic  = "ingress.kubernetes.io/session-cookie-dynamic"
	annotationUpstreamHashBy         = "ingress.kubernetes.io/upstream-hash-by"
	annotationHealthCheckURI         = "ingress.kubernetes.io/health-check-uri"
	annotationHealthCheckAddr        = "ingress.kubernetes.io/health-check-addr"
	annotationHealthCheckPort        = "ingress.kubernetes.io/health-check-port"
	annotationHealthCheckInterval    = "ingress.kubernetes.io/health-check-interval"
	annotationHealthCheckRiseCount   = "ingress.kubernetes.io/health-check-rise-count"
	annotationHealthCheckFallCount   = "ingress.kubernetes.io/health-check-fall-count"
	annotationAgentCheckAddr         = "ingress.kubernetes.io/agent-check-addr"
	annotationAgentCheckPort         = "ingress.kubernetes.io/agent-check-port"
	annotationAgentCheckInterval     = "ingress.kubernetes.io/agent-check-interval"
	annotationAgentCheckSend         = "ingress.kubernetes.io/agent-check-send"
)

type mockCfg struct {
	MockSecrets  map[string]*apiv1.Secret
	MockServices map[string]*apiv1.Service
}

func (m mockCfg) GetFullResourceName(name, currentNamespace string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("%v/%v", currentNamespace, name)
}

func (m mockCfg) GetDefaultBackend() defaults.Backend {
	return defaults.Backend{}
}

func (m mockCfg) GetSecret(name string) (*apiv1.Secret, error) {
	return m.MockSecrets[name], nil
}

func (m mockCfg) GetService(name string) (*apiv1.Service, error) {
	return m.MockServices[name], nil
}

func (m mockCfg) GetAuthCertificate(name string) (*resolver.AuthSSLCert, error) {
	if secret, _ := m.GetSecret(name); secret != nil {
		return &resolver.AuthSSLCert{
			Secret:     name,
			CAFileName: "/opt/ca.pem",
			PemSHA:     "123",
		}, nil
	}
	return nil, fmt.Errorf("secret not found")
}

func TestAnnotationExtractor(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	m := ec.Extract(ing)
	// the map at least should contains HealthCheck and Proxy information (defaults)
	if _, ok := m["HealthCheck"]; !ok {
		t.Error("expected HealthCheck annotation")
	}
	if _, ok := m["Proxy"]; !ok {
		t.Error("expected Proxy annotation")
	}
}

func buildIngress() *extensions.Ingress {
	defaultBackend := extensions.IngressBackend{
		ServiceName: "default-backend",
		ServicePort: intstr.FromInt(80),
	}

	return &extensions.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: apiv1.NamespaceDefault,
		},
		Spec: extensions.IngressSpec{
			Backend: &extensions.IngressBackend{
				ServiceName: "default-backend",
				ServicePort: intstr.FromInt(80),
			},
			Rules: []extensions.IngressRule{
				{
					Host: "foo.bar.com",
					IngressRuleValue: extensions.IngressRuleValue{
						HTTP: &extensions.HTTPIngressRuleValue{
							Paths: []extensions.HTTPIngressPath{
								{
									Path:    "/foo",
									Backend: defaultBackend,
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestSecureUpstream(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations map[string]string
		er          bool
	}{
		{map[string]string{annotationSecureUpstream: "true"}, true},
		{map[string]string{annotationSecureUpstream: "false"}, false},
		{map[string]string{annotationSecureUpstream + "_no": "true"}, false},
		{map[string]string{}, false},
		{nil, false},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.SecureUpstream(ing)
		if r.IsSecure != foo.er {
			t.Errorf("Returned %v but expected %v", r, foo.er)
		}
	}
}

func TestSecureVerifyCACert(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{
		MockSecrets: map[string]*apiv1.Secret{
			"default/secure-verify-ca": {
				ObjectMeta: metav1.ObjectMeta{
					Name: "secure-verify-ca",
				},
			},
		},
	})

	anns := []struct {
		it          int
		annotations map[string]string
		exists      bool
	}{
		{1, map[string]string{annotationSecureUpstream: "true", annotationSecureVerifyCACert: "not"}, false},
		{2, map[string]string{annotationSecureUpstream: "false", annotationSecureVerifyCACert: "secure-verify-ca"}, false},
		{3, map[string]string{annotationSecureUpstream: "true", annotationSecureVerifyCACert: "secure-verify-ca"}, true},
		{4, map[string]string{annotationSecureUpstream: "true", annotationSecureVerifyCACert + "_not": "secure-verify-ca"}, false},
		{5, map[string]string{annotationSecureUpstream: "true"}, false},
		{6, map[string]string{}, false},
		{7, nil, false},
	}

	for _, ann := range anns {
		ing := buildIngress()
		ing.SetAnnotations(ann.annotations)
		res := ec.SecureUpstream(ing)
		if (res.CACert.CAFileName != "") != ann.exists {
			t.Errorf("Expected exists was %v on iteration %v", ann.exists, ann.it)
		}
	}
}

func TestHealthCheck(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations map[string]string
		uri         string
		addr        string
		port        string
		interval    string
		riseCount   string
		fallCount   string
	}{
		{map[string]string{annotationHealthCheckURI: "/foo", annotationHealthCheckAddr: "1.2.3.4", annotationHealthCheckPort: "8080", annotationHealthCheckInterval: "10", annotationHealthCheckRiseCount: "5", annotationHealthCheckFallCount: "9"}, "/foo", "1.2.3.4", "8080", "10", "5", "9"},
		{map[string]string{annotationHealthCheckURI: "/bar"}, "/bar", "", "", "", "", ""},
		{map[string]string{annotationHealthCheckAddr: "1.2.3.4"}, "", "1.2.3.4", "", "", "", ""},
		{map[string]string{annotationHealthCheckPort: "8180"}, "", "", "8180", "", "", ""},
		{map[string]string{annotationHealthCheckInterval: "5"}, "", "", "", "5", "", ""},
		{map[string]string{annotationHealthCheckRiseCount: "5"}, "", "", "", "", "5", ""},
		{map[string]string{annotationHealthCheckFallCount: "5"}, "", "", "", "", "", "5"},
		{map[string]string{}, "", "", "", "", "", ""},
		{nil, "", "", "", "", "", ""},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.HealthCheck(ing)
		t.Logf("Testing pass %v %v %v %v %v %v", foo.uri, foo.addr, foo.port, foo.interval, foo.riseCount, foo.fallCount)
		if r == nil {
			t.Errorf("Returned nil but expected a healthcheck.Config")
			continue
		}

		if r.URI != foo.uri {
			t.Errorf("Returned %v but expected %v for URI", r.URI, foo.uri)
		}
		if r.Addr != foo.addr {
			t.Errorf("Returned %v but expected %v for Addr", r.Addr, foo.addr)
		}
		if r.Port != foo.port {
			t.Errorf("Returned %v but expected %v for Port", r.Port, foo.port)
		}
		if r.Interval != foo.interval {
			t.Errorf("Returned %v but expected %v for interval", r.Interval, foo.interval)
		}
		if r.RiseCount != foo.riseCount {
			t.Errorf("Returned %v but expected %v for riseCount", r.RiseCount, foo.riseCount)
		}
		if r.FallCount != foo.fallCount {
			t.Errorf("Returned %v but expected %v for fallCount", r.FallCount, foo.fallCount)
		}
	}
}

func TestSSLPassthrough(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations map[string]string
		er          sslpassthrough.Config
	}{
		{map[string]string{annotationPassthrough: "true"}, sslpassthrough.Config{
			HasSSLPassthrough: true,
			HTTPPort:          0},
		},
		{map[string]string{annotationPassthrough: "false"}, sslpassthrough.Config{
			HasSSLPassthrough: false,
			HTTPPort:          0},
		},
		{map[string]string{annotationPassthrough + "_no": "true"}, sslpassthrough.Config{
			HasSSLPassthrough: false,
			HTTPPort:          0},
		},
		{map[string]string{}, sslpassthrough.Config{
			HasSSLPassthrough: false,
			HTTPPort:          0},
		},
		{nil, sslpassthrough.Config{
			HasSSLPassthrough: false,
			HTTPPort:          0},
		},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.SSLPassthrough(ing)
		if r.HasSSLPassthrough != foo.er.HasSSLPassthrough {
			t.Errorf("Returned %v but expected %v", r.HasSSLPassthrough, foo.er.HasSSLPassthrough)
		}
		if r.HTTPPort != foo.er.HTTPPort {
			t.Errorf("Returned port %v but expected %v", r.HTTPPort, foo.er.HTTPPort)
		}
	}
}

func TestUpstreamHashBy(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations map[string]string
		er          string
	}{
		{map[string]string{annotationUpstreamHashBy: "$request_uri"}, "$request_uri"},
		{map[string]string{annotationUpstreamHashBy: "false"}, "false"},
		{map[string]string{annotationUpstreamHashBy + "_no": "true"}, ""},
		{map[string]string{}, ""},
		{nil, ""},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.UpstreamHashBy(ing)
		if r != foo.er {
			t.Errorf("Returned %v but expected %v", r, foo.er)
		}
	}
}

func TestAffinitySession(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations  map[string]string
		affinitytype string
		hash         string
		name         string
		strategy     string
		dynamic      bool
	}{
		{map[string]string{annotationAffinityType: "cookie", annotationAffinityCookieHash: "md5", annotationAffinityCookieName: "route", annotationAffinityCookieStrategy: "prefix", annotationAffinityCookieDynamic: "false"}, "cookie", "md5", "route", "prefix", false},
		{map[string]string{annotationAffinityType: "cookie", annotationAffinityCookieHash: "xpto", annotationAffinityCookieName: "route1", annotationAffinityCookieStrategy: "rewrite", annotationAffinityCookieDynamic: "true"}, "cookie", "md5", "route1", "rewrite", true},
		{map[string]string{annotationAffinityType: "cookie", annotationAffinityCookieHash: "", annotationAffinityCookieName: "", annotationAffinityCookieStrategy: ""}, "cookie", "md5", "INGRESSCOOKIE", "insert", true},
		{map[string]string{}, "", "", "", "", true},
		{nil, "", "", "", "", true},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.SessionAffinity(ing)
		t.Logf("Testing pass %v %v %v %v %v", foo.affinitytype, foo.hash, foo.name, foo.strategy, foo.dynamic)
		if r == nil {
			t.Errorf("Returned nil but expected a SessionAffinity.AffinityConfig")
			continue
		}

		if r.CookieConfig.Hash != foo.hash {
			t.Errorf("Returned %v but expected %v for Hash", r.CookieConfig.Hash, foo.hash)
		}

		if r.CookieConfig.Name != foo.name {
			t.Errorf("Returned %v but expected %v for Name", r.CookieConfig.Name, foo.name)
		}

		if r.CookieConfig.Strategy != foo.strategy {
			t.Errorf("Returned %v but expected %v for Strategy", r.CookieConfig.Strategy, foo.strategy)
		}

		if r.CookieConfig.Dynamic != foo.dynamic {
			t.Errorf("Returned %v but expected %v for Dynamic", r.CookieConfig.Dynamic, foo.dynamic)
		}
	}
}

func TestCors(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations   map[string]string
		corsenabled   bool
		methods       string
		headers       string
		origin        string
		credentials   bool
		exposeHeaders string
	}{
		{map[string]string{annotationCorsEnabled: "true"}, true, defaultCorsMethods, defaultCorsHeaders, "*", true, defaultCorsExposeHeaders},
		{map[string]string{annotationCorsEnabled: "true", annotationCorsAllowMethods: "POST, GET, OPTIONS", annotationCorsAllowHeaders: "$nginx_version", annotationCorsAllowCredentials: "false"}, true, "POST, GET, OPTIONS", defaultCorsHeaders, "*", false, defaultCorsExposeHeaders},
		{map[string]string{annotationCorsEnabled: "true", annotationCorsAllowCredentials: "false"}, true, defaultCorsMethods, defaultCorsHeaders, "*", false, defaultCorsExposeHeaders},
		{map[string]string{annotationCorsEnabled: "true", annotationCorsExposeHeaders: "FOO, BAR, BAZ",}, true, defaultCorsMethods, defaultCorsHeaders, "*", true, "FOO, BAR, BAZ"},
		{map[string]string{}, false, "", "", "", false, ""},
		{nil, false, "", "", "", false, ""},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.Cors(ing)
		t.Logf("Testing pass %v %v %v %v %v %v", foo.corsenabled, foo.methods, foo.headers, foo.origin, foo.credentials, foo.exposeHeaders)
		if r == nil {
			t.Errorf("Returned nil but expected a Cors.CorsConfig")
			continue
		}

		if r.CorsEnabled != foo.corsenabled {
			t.Errorf("Returned %v but expected %v for Cors Enabled", r.CorsEnabled, foo.corsenabled)
		}

		if r.CorsAllowHeaders != foo.headers {
			t.Errorf("Returned %v but expected %v for Cors Headers", r.CorsAllowHeaders, foo.headers)
		}

		if r.CorsAllowMethods != foo.methods {
			t.Errorf("Returned %v but expected %v for Cors Methods", r.CorsAllowMethods, foo.methods)
		}

		if r.CorsAllowOrigin != foo.origin {
			t.Errorf("Returned %v but expected %v for Cors Methods", r.CorsAllowOrigin, foo.origin)
		}

		if r.CorsAllowCredentials != foo.credentials {
			t.Errorf("Returned %v but expected %v for Cors Methods", r.CorsAllowCredentials, foo.credentials)
		}

		if r.CorsExposeHeaders != foo.exposeHeaders {
			t.Errorf("Returned %v but expected %v for Cors Methods", r.CorsExposeHeaders, foo.exposeHeaders)
		}
	}
}

func TestAgentCheck(t *testing.T) {
	ec := newAnnotationExtractor(mockCfg{})
	ing := buildIngress()

	fooAnns := []struct {
		annotations map[string]string
		addr        string
		port        string
		interval    string
		send        string
	}{
		{map[string]string{annotationAgentCheckAddr: "1.2.3.4", annotationAgentCheckPort: "8080", annotationAgentCheckInterval: "10", annotationAgentCheckSend: "hello\n"}, "1.2.3.4", "8080", "10", "hello\n"},
		{map[string]string{annotationAgentCheckAddr: "1.2.3.4"}, "1.2.3.4", "", "", ""},
		{map[string]string{annotationAgentCheckPort: "8180"}, "", "8180", "", ""},
		{map[string]string{annotationAgentCheckInterval: "5"}, "", "", "5", ""},
		{map[string]string{annotationAgentCheckSend: "hello\n"}, "", "", "", "hello\n"},
		{map[string]string{}, "", "", "", ""},
		{nil, "", "", "", ""},
	}

	for _, foo := range fooAnns {
		ing.SetAnnotations(foo.annotations)
		r := ec.AgentCheck(ing)
		t.Logf("Testing pass %v %v %v %v", foo.addr, foo.port, foo.interval, foo.send)
		if r == nil {
			t.Errorf("Returned nil but expected a agentcheck.Config")
			continue
		}

		if r.Addr != foo.addr {
			t.Errorf("Returned %v but expected %v for Addr", r.Addr, foo.addr)
		}
		if r.Port != foo.port {
			t.Errorf("Returned %v but expected %v for Port", r.Port, foo.port)
		}
		if r.Interval != foo.interval {
			t.Errorf("Returned %v but expected %v for interval", r.Interval, foo.interval)
		}
		if r.Send != foo.send {
			t.Errorf("Returned %v but expected %v for send", r.Send, foo.send)
		}
	}
}
