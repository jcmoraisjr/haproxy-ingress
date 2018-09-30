/*
Copyright 2016 The Kubernetes Authors.

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

package secureupstream

import (
	"github.com/pkg/errors"
	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
)

const (
	secureUpstream       = "ingress.kubernetes.io/secure-backends"
	secureCrtSecret      = "ingress.kubernetes.io/secure-crt-secret"
	secureVerifyCASecret = "ingress.kubernetes.io/secure-verify-ca-secret"
)

// Secure describes SSL backend configuration
type Secure struct {
	IsSecure bool                 `json:"secure"`
	Cert     resolver.AuthSSLCert `json:"cert"`
	CACert   resolver.AuthSSLCert `json:"caCert"`
}

type su struct {
	cfg          resolver.Configuration
	certResolver resolver.AuthCertificate
}

// NewParser creates a new secure upstream annotation parser
func NewParser(cfg resolver.Configuration, crt resolver.AuthCertificate) parser.IngressAnnotation {
	return su{
		cfg:          cfg,
		certResolver: crt,
	}
}

// Parse parses the annotations contained in the ingress
// rule used to indicate if the upstream servers should use SSL
func (a su) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, _ := parser.GetBoolAnnotation(secureUpstream, ing)
	crt, _ := parser.GetStringAnnotation(secureCrtSecret, ing)
	CA, _ := parser.GetStringAnnotation(secureVerifyCASecret, ing)
	crtKey := a.cfg.GetFullResourceName(crt, ing.Namespace)
	caKey := a.cfg.GetFullResourceName(CA, ing.Namespace)
	secure := &Secure{
		IsSecure: s,
		Cert:     resolver.AuthSSLCert{},
		CACert:   resolver.AuthSSLCert{},
	}
	if !s && (caKey != "" || crtKey != "") {
		return secure,
			errors.Errorf("trying to use crt or CA from secret %v on a non secure backend", caKey)
	}
	if crtKey != "" {
		cert, err := a.certResolver.GetAuthCertificate(crtKey)
		if err != nil {
			return secure, errors.Wrap(err, "error obtaining certificate")
		}
		secure.Cert = *cert
	}
	if caKey != "" {
		caCert, err := a.certResolver.GetAuthCertificate(caKey)
		if err != nil {
			return secure, errors.Wrap(err, "error obtaining certificate authorities")
		}
		secure.CACert = *caCert
	}
	return secure, nil
}

// Equal tests for equality between two Secure objects
func (s1 *Secure) Equal(s2 *Secure) bool {
	if s1 == nil || s2 == nil {
		return s1 == s2
	}
	if s1.IsSecure != s2.IsSecure {
		return false
	}
	if !s1.Cert.Equal(&s2.Cert) {
		return false
	}
	if !s1.CACert.Equal(&s2.CACert) {
		return false
	}
	return true
}
