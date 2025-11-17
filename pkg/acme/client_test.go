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
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

// Update the following keys to run the test. The challenge will be saved in /tmp/out,
// the test will wait 20s to continue and validate the challenge.
const (
	// Add here an email, a domain you have access to and the single-line base64 encoding of a client private key in DER format.
	// Email should be valid and a new account will be created if the key does not exist yet.
	// Optional, nothing will be done if any value is missing.
	//
	// DO NOT COMMIT+PUSH THE CLIENT KEY!
	//
	// single line base64 encoded client's private key in DER format
	// $ openssl genrsa |openssl rsa -outform der |base64 -w0 >privkey ## omit -w0 on macOS/Darwin/BSD
	clientkey = ``
	// email that should be assigned to the account
	email = ``
	// domain used to execute the challenge
	domain = ``
	// an optional preferred chain - note that currently (oct/2021) Let's Encrypt
	// staging doesn't have an alternate chain
	chain = ``
	// a local path where the response of the challenge should be written
	// if empty the challenge will be written to /tmp/out and the test will
	// wait 20s to continue
	wwwpublic = ``
)

func TestSign(t *testing.T) {
	if clientkey == "" || email == "" || domain == "" {
		return
	}
	c := setup(t)
	defer c.teardown()
	resolver := &clientResolver{logger: c.logger}
	client, err := NewClient(c.logger, resolver, &Account{
		Endpoint:    "https://acme-staging-v02.api.letsencrypt.org",
		Emails:      email,
		TermsAgreed: true,
	})
	if err != nil {
		t.Errorf("error creating acme client: %v", err)
	}
	// TODO test resulting crt
	// TODO debug/fine logging in the Sign() steps
	_, _, err = client.Sign([]string{domain}, chain)
	if err != nil {
		t.Errorf("error signing certificate: %v", err)
	}
	// This will only success after the first run - the message changes when the account is created.
	// No problem, run the test again and everything will be fine
	c.logger.CompareLogging("INFO acme: client account successfully retrieved")
}

type clientResolver struct {
	logger *types_helper.LoggerMock
}

func (c *clientResolver) GetKey() (crypto.Signer, error) {
	der, _ := base64.StdEncoding.DecodeString(clientkey)
	key, _ := x509.ParsePKCS1PrivateKey(der)
	return key, nil
}

func (c *clientResolver) SetToken(domain string, uri, token string) error {
	if wwwpublic != "" {
		file := wwwpublic + uri
		if token == "" {
			return os.Remove(file)
		}
		if err := os.MkdirAll(wwwpublic+"/.well-known/acme-challenge", 0755); err != nil {
			return err
		}
		return os.WriteFile(file, []byte(token), 0644)
	}
	if token == "" {
		return nil
	}
	out := fmt.Sprintf("%s%s = %s", domain, uri, token)
	if err := os.WriteFile("/tmp/out", []byte(out), 0644); err != nil {
		return err
	}
	// 20s to copy the challenge from /tmp/out and update the server
	time.Sleep(20 * time.Second)
	return nil
}
