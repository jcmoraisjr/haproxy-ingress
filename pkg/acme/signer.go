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

package acme

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// NewSigner ...
func NewSigner(logger types.Logger, cache Cache, metrics types.Metrics) Signer {
	return &signer{
		logger:  logger,
		cache:   cache,
		metrics: metrics,
	}
}

// Signer ...
type Signer interface {
	AcmeAccount(endpoint, emails string, termsAgreed bool)
	AcmeConfig(expiring time.Duration)
	HasAccount() bool
	Notify(item interface{}) error
}

// Cache ...
type Cache interface {
	ClientResolver
	ServerResolver
	SignerResolver
}

// SignerResolver ...
type SignerResolver interface {
	GetTLSSecretContent(secretName string) *TLSSecret
	SetTLSSecretContent(secretName string, pemCrt, pemKey []byte) error
}

// TLSSecret ...
type TLSSecret struct {
	Crt *x509.Certificate
	Key *rsa.PrivateKey
}

type signer struct {
	logger      types.Logger
	cache       Cache
	metrics     types.Metrics
	account     Account
	client      Client
	expiring    time.Duration
	verifyCount int
}

func (s *signer) AcmeAccount(endpoint, emails string, termsAgreed bool) {
	switch endpoint {
	case "v2", "v02":
		endpoint = "https://acme-v02.api.letsencrypt.org"
	case "v2-staging", "v02-staging":
		endpoint = "https://acme-staging-v02.api.letsencrypt.org"
	}
	account := Account{
		Endpoint:    endpoint,
		Emails:      emails,
		TermsAgreed: termsAgreed,
	}
	if reflect.DeepEqual(s.account, account) {
		return
	}
	s.client = nil
	if endpoint == "" && emails == "" && !termsAgreed {
		return
	}
	s.logger.Info("loading account %+v", account)
	client, err := NewClient(s.logger, s.cache, &account)
	if err != nil {
		s.logger.Warn("error creating the acme client: %v", err)
		return
	}
	s.account = account
	s.client = client
}

func (s *signer) AcmeConfig(expiring time.Duration) {
	s.expiring = expiring
}

func (s *signer) HasAccount() bool {
	return s.client != nil
}

func (s *signer) Notify(item interface{}) error {
	if !s.HasAccount() {
		return fmt.Errorf("acme: account was not properly initialized")
	}
	cert := strings.Split(item.(string), ",")
	secretName := cert[0]
	domains := cert[1:]
	err := s.verify(secretName, domains)
	return err
}

func (s *signer) verify(secretName string, domains []string) (verifyErr error) {
	duedate := time.Now().Add(s.expiring)
	tls := s.cache.GetTLSSecretContent(secretName)
	strdomains := strings.Join(domains, ",")
	if tls == nil || tls.Crt.NotAfter.Before(duedate) || !match(domains, tls.Crt.DNSNames) {
		var collector func(domains string, success bool)
		var reason string
		if tls == nil {
			collector = s.metrics.IncCertSigningMissing
			reason = "certificate does not exist"
		} else if tls.Crt.NotAfter.Before(duedate) {
			collector = s.metrics.IncCertSigningOutdated
			reason = fmt.Sprintf("certificate expires in %s", tls.Crt.NotAfter.String())
		} else {
			collector = s.metrics.IncCertSigningChangedDomains
			reason = "added one or more domains to an existing certificate"
		}
		s.verifyCount++
		s.logger.Info("acme: authorizing: id=%d secret=%s domain(s)=%s endpoint=%s reason='%s'",
			s.verifyCount, secretName, strdomains, s.account.Endpoint, reason)
		crt, key, err := s.client.Sign(domains)
		if err == nil {
			if errTLS := s.cache.SetTLSSecretContent(secretName, crt, key); errTLS == nil {
				s.logger.Info("acme: new certificate issued: id=%d secret=%s domain(s)=%s",
					s.verifyCount, secretName, strdomains)
			} else {
				s.logger.Warn("acme: error storing new certificate: id=%d secret=%s domain(s)=%s error=%v",
					s.verifyCount, secretName, strdomains, errTLS)
				verifyErr = errTLS
			}
		} else {
			s.logger.Warn("acme: error signing new certificate: id=%d secret=%s domain(s)=%s error=%v",
				s.verifyCount, secretName, strdomains, err)
			verifyErr = err
		}
		collector(strdomains, verifyErr == nil)
	} else {
		s.logger.InfoV(2, "acme: skipping sign, certificate is updated: secret=%s domain(s)=%s", secretName, strdomains)
	}
	return verifyErr
}

// match return true if all hosts in hostnames (desired configuration)
// are already in dnsnames (current certificate).
func match(domains, dnsnames []string) bool {
	for _, domain := range domains {
		found := false
		for _, dns := range dnsnames {
			if domain == dns {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
