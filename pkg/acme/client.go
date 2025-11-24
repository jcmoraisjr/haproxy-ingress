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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme/x/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
)

const (
	acmeChallengeHTTP01     = "http-01"
	acmeChallengeDNS01      = "dns-01"
	acmeErrAcctDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist"
)

var (
	acmeUserAgent = "haproxy-ingress/" + version.RELEASE
)

// hasWildcardDomain returns true if any domain in the list is a wildcard domain
func hasWildcardDomain(domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			return true
		}
	}
	return false
}

// NewClient ...
func NewClient(logger types.Logger, resolver ClientResolver, account *Account) (Client, error) {
	key, err := resolver.GetKey()
	if err != nil {
		return nil, err
	}
	emails := strings.Split(account.Emails, ",")
	contact := make([]string, len(emails))
	for i, email := range emails {
		contact[i] = "mailto:" + email
	}
	acmeClient := &acme.Client{
		DirectoryURL: account.Endpoint + "/directory",
		Key:          key,
		UserAgent:    acmeUserAgent,
	}
	client := &client{
		client:      acmeClient,
		ctx:         context.Background(),
		contact:     contact,
		endpoint:    account.Endpoint,
		logger:      logger,
		resolver:    resolver,
		termsAgreed: account.TermsAgreed,
	}
	if err := client.ensureAccount(); err != nil {
		return nil, err
	}
	return client, nil
}

// Account ...
type Account struct {
	Emails      string
	Endpoint    string
	TermsAgreed bool
}

// ACMEClient interface for mocking ACME client operations
type ACMEClient interface {
	GetAccount(ctx context.Context) (*acme.Account, error)
	CreateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error)
	UpdateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error)
	CreateOrder(ctx context.Context, order *acme.Order) (*acme.Order, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	AcceptChallenge(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	HTTP01ChallengePath(token string) string
	HTTP01ChallengeResponse(token string) (string, error)
	FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte, altcn string) ([][]byte, error)
}

// ClientResolver ...
type ClientResolver interface {
	GetKey() (crypto.Signer, error)
	SetToken(domain string, uri, token string) error
}

// Client ...
type Client interface {
	Sign(dnsnames []string, preferredChain string) (crt, key []byte, err error)
}

type client struct {
	client      ACMEClient
	contact     []string
	ctx         context.Context
	endpoint    string
	logger      types.Logger
	resolver    ClientResolver
	termsAgreed bool
}

func (c *client) ensureAccount() error {
	if acct, err := c.client.GetAccount(c.ctx); err != nil {
		acmeErr, ok := err.(*acme.Error)
		if ok && acmeErr.Type == acmeErrAcctDoesNotExist {
			_, err = c.client.CreateAccount(c.ctx, &acme.Account{
				Contact:     c.contact,
				TermsAgreed: c.termsAgreed,
			})
			if err != nil {
				return err
			}
			c.logger.Info("acme: terms agreed, new account created on %s", c.endpoint)
		} else {
			return err
		}
	} else if !reflect.DeepEqual(acct.Contact, c.contact) {
		c.logger.InfoV(2, "acme: changing contact from %+v to %+v", acct.Contact, c.contact)
		acct.Contact = c.contact
		if _, err := c.client.UpdateAccount(c.ctx, acct); err == nil {
			c.logger.Info("acme: contact info updated to %s", strings.Join(c.contact, ","))
		} else {
			c.logger.Warn("acme: error trying to update contact info: %v", err)
		}
	} else {
		c.logger.Info("acme: client account successfully retrieved")
	}
	return nil
}

func (c *client) Sign(dnsnames []string, preferredChain string) (crt, key []byte, err error) {
	if len(dnsnames) == 0 {
		return crt, key, fmt.Errorf("dnsnames is empty")
	}
	order, err := c.client.CreateOrder(c.ctx, acme.NewOrder(dnsnames...))
	if err != nil {
		return crt, key, err
	}
	if err := c.authorize(dnsnames, order); err != nil {
		return crt, key, err
	}
	csrTemplate := &x509.CertificateRequest{}
	csrTemplate.Subject.CommonName = dnsnames[0]
	csrTemplate.DNSNames = dnsnames
	return c.signRequest(order, csrTemplate, preferredChain)
}

func (c *client) authorize(dnsnames []string, order *acme.Order) error {
	for _, authStr := range order.Authorizations {
		auth, err := c.client.GetAuthorization(c.ctx, authStr)
		if err != nil {
			return err
		}

		// Check available challenges
		hasHTTP01 := false
		hasDNS01 := false
		for _, challenge := range auth.Challenges {
			switch challenge.Type {
			case acmeChallengeHTTP01:
				hasHTTP01 = true
			case acmeChallengeDNS01:
				hasDNS01 = true
			}
		}

		// If we have wildcard domains, ALWAYS error because HAProxy Ingress doesn't support DNS-01
		if hasWildcardDomain(dnsnames) {
			return fmt.Errorf("acme: DNS-01 challenge required for wildcard domain %s, but haproxy-ingress only supports HTTP-01 challenges. "+
				"Please configure your DNS provider to add a TXT record '_acme-challenge.%s' with the value provided by your ACME client, "+
				"or use a non-wildcard domain", auth.Identifier.Value, auth.Identifier.Value)
		}

		// If no HTTP-01 challenge is available, warn the user
		if !hasHTTP01 {
			if hasDNS01 {
				return fmt.Errorf("acme: HTTP-01 challenge not available for domain %s, only DNS-01 challenge is supported by the ACME server. "+
					"haproxy-ingress only supports HTTP-01 challenges. Please ensure your domain is accessible via HTTP for ACME challenges", auth.Identifier.Value)
			} else {
				return fmt.Errorf("acme: no supported challenge type available for domain %s. haproxy-ingress supports HTTP-01 challenges only", auth.Identifier.Value)
			}
		}

		for _, challenge := range auth.Challenges {
			if challenge.Type == acmeChallengeHTTP01 {
				checkURI := c.client.HTTP01ChallengePath(challenge.Token)
				checkRes, err := c.client.HTTP01ChallengeResponse(challenge.Token)
				if err != nil {
					return err
				}
				if err := c.resolver.SetToken(auth.Identifier.Value, checkURI, checkRes); err != nil {
					return err
				}
				_, err = c.client.AcceptChallenge(c.ctx, challenge)
				if err != nil {
					return err
				}
				_, err = c.client.WaitAuthorization(c.ctx, challenge.URL)
				_ = c.resolver.SetToken(auth.Identifier.Value, checkURI, "")
				if err != nil {
					if acmeErr, ok := err.(acme.AuthorizationError); ok {
						// acme client returns an empty Identifier.Value on acmeErr.Authorization
						return fmt.Errorf("acme: authorization error: domain=%s status=%s", auth.Identifier.Value, acmeErr.Authorization.Status)
					}
					return err
				}
			}
		}
	}
	return nil
}

func (c *client) signRequest(order *acme.Order, csrTemplate *x509.CertificateRequest, preferredChain string) (crt, key []byte, err error) {
	keys, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return crt, key, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, keys)
	if err != nil {
		return crt, key, err
	}
	rawCerts, err := c.client.FinalizeOrder(c.ctx, order.FinalizeURL, csr, preferredChain)
	if err != nil && rawCerts == nil {
		return crt, key, err
	}
	key = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keys),
	})
	for _, rawCert := range rawCerts {
		crt = append(crt, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rawCert,
		})...)
	}
	return crt, key, err
}
