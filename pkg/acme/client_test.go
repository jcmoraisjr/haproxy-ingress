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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme/x/acme"
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

func TestHasWildcardDomain(t *testing.T) {
	testCases := []struct {
		name      string
		domains   []string
		hasWildcard bool
	}{
		{
			name:        "no domains",
			domains:     []string{},
			hasWildcard: false,
		},
		{
			name:        "single non-wildcard domain",
			domains:     []string{"example.com"},
			hasWildcard: false,
		},
		{
			name:        "multiple non-wildcard domains",
			domains:     []string{"example.com", "www.example.com", "api.example.com"},
			hasWildcard: false,
		},
		{
			name:        "single wildcard domain",
			domains:     []string{"*.example.com"},
			hasWildcard: true,
		},
		{
			name:        "mixed wildcard and non-wildcard",
			domains:     []string{"example.com", "*.example.com"},
			hasWildcard: true,
		},
		{
			name:        "multiple wildcards",
			domains:     []string{"*.example.com", "*.api.example.com"},
			hasWildcard: true,
		},
		{
			name:        "wildcard at different levels",
			domains:     []string{"*.example.com", "*.sub.example.com"},
			hasWildcard: true,
		},
		{
			name:        "edge case: asterisk not at start",
			domains:     []string{"example.*.com"},
			hasWildcard: false,
		},
		{
			name:        "edge case: double asterisk",
			domains:     []string{"**.example.com"},
			hasWildcard: false,
		},
		{
			name:        "edge case: asterisk in middle",
			domains:     []string{"sub.*.example.com"},
			hasWildcard: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := hasWildcardDomain(tc.domains)
			if result != tc.hasWildcard {
				t.Errorf("hasWildcardDomain(%v) = %v, want %v", tc.domains, result, tc.hasWildcard)
			}
		})
	}
}

// mockACMEClient implements the necessary ACME client methods for testing
type mockACMEClient struct {
	authorizations map[string]*acme.Authorization
}

func (m *mockACMEClient) GetAccount(ctx context.Context) (*acme.Account, error) {
	return &acme.Account{Contact: []string{"mailto:test@example.com"}}, nil
}

func (m *mockACMEClient) CreateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	return a, nil
}

func (m *mockACMEClient) UpdateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	return a, nil
}

func (m *mockACMEClient) CreateOrder(ctx context.Context, order *acme.Order) (*acme.Order, error) {
	// Return mock order with authorization URLs
	return &acme.Order{
		Authorizations: []string{"auth1"},
		FinalizeURL:    "finalize1",
	}, nil
}

func (m *mockACMEClient) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	if auth, exists := m.authorizations[url]; exists {
		return auth, nil
	}
	return nil, fmt.Errorf("authorization not found")
}

func (m *mockACMEClient) AcceptChallenge(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
	return challenge, nil
}

func (m *mockACMEClient) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return &acme.Authorization{}, nil
}

func (m *mockACMEClient) HTTP01ChallengePath(token string) string {
	return "/.well-known/acme-challenge/" + token
}

func (m *mockACMEClient) HTTP01ChallengeResponse(token string) (string, error) {
	return token + ".response", nil
}

func (m *mockACMEClient) FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte, altcn string) ([][]byte, error) {
	// Return mock certificate data
	return [][]byte{[]byte("mock-cert")}, nil
}

func TestAuthorizeChallenges(t *testing.T) {
	testCases := []struct {
		name             string
		domains          []string
		challenges       []*acme.Challenge
		expectedError    bool
		errorContains    string
		expectSetToken   bool
	}{
		{
			name:    "HTTP-01 available for non-wildcard domain",
			domains: []string{"example.com"},
			challenges: []*acme.Challenge{
				{Type: "http-01", Token: "token1"},
				{Type: "dns-01", Token: "token2"},
			},
			expectedError:  false,
			expectSetToken: true,
		},
		{
			name:    "DNS-01 required for wildcard domain",
			domains: []string{"*.example.com"},
			challenges: []*acme.Challenge{
				{Type: "http-01", Token: "token1"},
				{Type: "dns-01", Token: "token2"},
			},
			expectedError: true,
			errorContains: "DNS-01 challenge required for wildcard domain",
		},
		{
			name:    "HTTP-01 not available, only DNS-01",
			domains: []string{"example.com"},
			challenges: []*acme.Challenge{
				{Type: "dns-01", Token: "token1"},
			},
			expectedError: true,
			errorContains: "HTTP-01 challenge not available",
		},
		{
			name:    "No supported challenges available",
			domains: []string{"example.com"},
			challenges: []*acme.Challenge{
				{Type: "tls-sni-01", Token: "token1"},
			},
			expectedError: true,
			errorContains: "no supported challenge type available",
		},
		{
			name:          "Wildcard domain always requires DNS-01 (even with HTTP-01 available)",
			domains:       []string{"*.example.com"},
			challenges: []*acme.Challenge{
				{Type: "http-01", Token: "token1"},
			},
			expectedError: true,
			errorContains: "DNS-01 challenge required for wildcard domain",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock resolver
			mockResolver := &mockClientResolver{}

			// Create mock ACME client
			mockACME := &mockACMEClient{
				authorizations: map[string]*acme.Authorization{
					"auth1": {
						Identifier: acme.AuthzID{Type: "dns", Value: tc.domains[0]},
						Challenges: tc.challenges,
					},
				},
			}

			// Create client with mock dependencies
			c := &client{
				client:   mockACME,
				ctx:      context.Background(),
				logger:   types_helper.NewLoggerMock(t),
				resolver: mockResolver,
			}

			// Create mock order with authorization URL
			order := &acme.Order{
				Authorizations: []string{"auth1"},
			}

			// Test the authorize method
			err := c.authorize(tc.domains, order)

			// Check error expectations
			if tc.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}

			// Check if SetToken was called when expected
			if tc.expectSetToken && !mockResolver.tokenSet {
				t.Errorf("expected SetToken to be called but it wasn't")
			}
			if !tc.expectSetToken && mockResolver.tokenSet {
				t.Errorf("expected SetToken not to be called but it was")
			}
		})
	}
}

// mockClientResolver tracks if SetToken was called
type mockClientResolver struct {
	tokenSet bool
}

func (m *mockClientResolver) GetKey() (crypto.Signer, error) {
	return nil, nil
}

func (m *mockClientResolver) SetToken(domain string, uri, token string) error {
	m.tokenSet = true
	return nil
}

func TestSignWithDifferentDomainTypes(t *testing.T) {
	testCases := []struct {
		name          string
		domains       []string
		mockAuth      *acme.Authorization
		expectedError bool
		errorContains string
	}{
		{
			name:    "successful sign with non-wildcard domain",
			domains: []string{"example.com"},
			mockAuth: &acme.Authorization{
				Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
				Challenges: []*acme.Challenge{
					{Type: "http-01", Token: "success-token"},
				},
			},
			expectedError: false,
		},
		{
			name:    "wildcard domain triggers DNS-01 warning",
			domains: []string{"*.example.com"},
			mockAuth: &acme.Authorization{
				Identifier: acme.AuthzID{Type: "dns", Value: "*.example.com"},
				Challenges: []*acme.Challenge{
					{Type: "http-01", Token: "http-token"},
					{Type: "dns-01", Token: "dns-token"},
				},
			},
			expectedError: true,
			errorContains: "DNS-01 challenge required for wildcard domain",
		},
		{
			name:    "mixed domains with wildcard",
			domains: []string{"example.com", "*.example.com"},
			mockAuth: &acme.Authorization{
				Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
				Challenges: []*acme.Challenge{
					{Type: "http-01", Token: "http-token"},
					{Type: "dns-01", Token: "dns-token"},
				},
			},
			expectedError: true,
			errorContains: "DNS-01 challenge required for wildcard domain",
		},
		{
			name:    "HTTP-01 not available",
			domains: []string{"example.com"},
			mockAuth: &acme.Authorization{
				Identifier: acme.AuthzID{Type: "dns", Value: "example.com"},
				Challenges: []*acme.Challenge{
					{Type: "dns-01", Token: "dns-token"},
				},
			},
			expectedError: true,
			errorContains: "HTTP-01 challenge not available",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock resolver
			mockResolver := &mockClientResolver{}

			// Create mock ACME client
			mockACME := &mockACMEClient{
				authorizations: map[string]*acme.Authorization{
					"auth1": tc.mockAuth,
				},
			}

			// Create client
			c := &client{
				client:   mockACME,
				ctx:      context.Background(),
				logger:   types_helper.NewLoggerMock(t),
				resolver: mockResolver,
			}

			// Test Sign method
			crt, key, err := c.Sign(tc.domains, "test-chain")

			// Check error expectations
			if tc.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
				if crt != nil || key != nil {
					t.Errorf("expected no certificate data on error, but got crt=%v, key=%v", len(crt), len(key))
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				if crt == nil || key == nil {
					t.Errorf("expected certificate data on success, but got crt=%v, key=%v", crt, key)
				}
			}
		})
	}
}

func TestErrorMessageFormatting(t *testing.T) {
	testCases := []struct {
		name             string
		domains          []string
		expectedMessage  string
	}{
		{
			name:            "wildcard domain error message",
			domains:         []string{"*.example.com"},
			expectedMessage: "acme: DNS-01 challenge required for wildcard domain *.example.com, but haproxy-ingress only supports HTTP-01 challenges. Please configure your DNS provider to add a TXT record '_acme-challenge.*.example.com' with the value provided by your ACME client, or use a non-wildcard domain",
		},
		{
			name:            "mixed domains with wildcard",
			domains:         []string{"www.example.com", "*.example.com"},
			expectedMessage: "acme: DNS-01 challenge required for wildcard domain www.example.com, but haproxy-ingress only supports HTTP-01 challenges. Please configure your DNS provider to add a TXT record '_acme-challenge.www.example.com' with the value provided by your ACME client, or use a non-wildcard domain",
		},
		{
			name:            "no HTTP-01 available",
			domains:         []string{"nohttp.example.com"},
			expectedMessage: "acme: HTTP-01 challenge not available for domain nohttp.example.com, only DNS-01 challenge is supported by the ACME server. haproxy-ingress only supports HTTP-01 challenges. Please ensure your domain is accessible via HTTP for ACME challenges",
		},
		{
			name:            "no supported challenges",
			domains:         []string{"unsupported.example.com"},
			expectedMessage: "acme: no supported challenge type available for domain unsupported.example.com. haproxy-ingress supports HTTP-01 challenges only",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup appropriate mock authorization based on domain
			var challenges []*acme.Challenge

			switch {
			case hasWildcardDomain(tc.domains):
				// Mock both HTTP-01 and DNS-01 available but wildcard triggers DNS-01 requirement
				challenges = []*acme.Challenge{
					{Type: "http-01", Token: "http-token"},
					{Type: "dns-01", Token: "dns-token"},
				}
			case tc.domains[0] == "nohttp.example.com":
				// Mock only DNS-01 available
				challenges = []*acme.Challenge{
					{Type: "dns-01", Token: "dns-token"},
				}
			case tc.domains[0] == "unsupported.example.com":
				// Mock unsupported challenge type only
				challenges = []*acme.Challenge{
					{Type: "tls-sni-01", Token: "tls-token"},
				}
			default:
				t.Skip("Skipping non-error cases in error message formatting test")
			}

			mockResolver := &mockClientResolver{}
			mockACME := &mockACMEClient{
				authorizations: map[string]*acme.Authorization{
					"auth1": {
						Identifier: acme.AuthzID{Type: "dns", Value: tc.domains[0]},
						Challenges: challenges,
					},
				},
			}

			c := &client{
				client:   mockACME,
				ctx:      context.Background(),
				logger:   types_helper.NewLoggerMock(t),
				resolver: mockResolver,
			}

			order := &acme.Order{
				Authorizations: []string{"auth1"},
			}

			err := c.authorize(tc.domains, order)

			if err == nil {
				t.Fatalf("expected error but got none")
			}

			actualMessage := err.Error()
			if actualMessage != tc.expectedMessage {
				t.Errorf("error message mismatch:\nexpected: %q\nactual:   %q", tc.expectedMessage, actualMessage)
			}
		})
	}
}

