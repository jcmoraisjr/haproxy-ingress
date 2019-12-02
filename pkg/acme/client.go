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
	acmeErrAcctDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist"
)

var (
	acmeUserAgent = "haproxy-ingress/" + version.RELEASE
)

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
	client := &client{
		client: &acme.Client{
			DirectoryURL: account.Endpoint + "/directory",
			Key:          key,
			UserAgent:    acmeUserAgent,
		},
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

// ClientResolver ...
type ClientResolver interface {
	GetKey() (crypto.Signer, error)
	SetToken(domain string, uri, token string) error
}

// Client ...
type Client interface {
	Sign(dnsnames []string) (crt, key []byte, err error)
}

type client struct {
	client      *acme.Client
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

func (c *client) Sign(dnsnames []string) (crt, key []byte, err error) {
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
	return c.signRequest(order, csrTemplate)
}

func (c *client) authorize(dnsnames []string, order *acme.Order) error {
	for _, authStr := range order.Authorizations {
		auth, err := c.client.GetAuthorization(c.ctx, authStr)
		if err != nil {
			return err
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

func (c *client) signRequest(order *acme.Order, csrTemplate *x509.CertificateRequest) (crt, key []byte, err error) {
	keys, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return crt, key, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, keys)
	if err != nil {
		return crt, key, err
	}
	rawCerts, err := c.client.FinalizeOrder(c.ctx, order.FinalizeURL, csr)
	if err != nil {
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
	return crt, key, nil
}
