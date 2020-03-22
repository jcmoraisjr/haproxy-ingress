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
	"testing"
	"time"

	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

const dumbcrt = `MIIC+DCCAeCgAwIBAgIBAzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdEdW1iIENBMB4XDTE5MTIwMTE2MzMxNFoXDTIwMTIwMTE2MzMxNFowEzERMA8GA1UEAwwIZDEubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZuSjOKNrlOFQ/6JCZDbh5OykiSyv/GVzEsazMeLCcvmQecI9CtqCTMLENaDpSUC4/j2b5i61CoRHoucr9EoMo4KJslWRebfBz5y8H6zbRSI9J3MskVB5oDqC4NV8LRoxQRQwsHwR1UXkdUoVMCKwVXF7JUV9vr/lyjfX7+d1XYsX4jlVQ955RfPlVod6On4IOL2GmYzKER6F/IBPLHpIpwJYAM5vmbLo8/xkVb+gHw7tnJPxiMTO+/Rqno/Tx8avLqTFfuMZwPtE/aUjEzXBoMv2gItnDCkNBUO7LZdzlkcAN1iphPGMGN1Zpbd2pRUL1zWbQM7qL+qlEWlWapk0vAgMBAAGjWDBWMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHREEFjAUgghkMS5sb2NhbIIIZDIubG9jYWwwDQYJKoZIhvcNAQELBQADggEBACeFb+foCC6SS7pu6mBC0MbyKMKcuShI0xkTjjov/Fo1kYhAIDoEs7MRCv2eyfnqoXZ0ZBJJTsTaz2ADS3lrL422wy/udwLTty8f3/hOFAl/Bp3uJ8+7y26tOU+vdLXheO5ZCMOH8H39GHFXH31c9CLqvOUL78tCrkjxxvYHGFvWciLn2/AYRfoE/WKhvrEynPmVFtJXpGfIeBWB5SL6234c8fd0RpSRXNCmRQr3Tviy86jfz5eG0Tb3131E6sK8mB/Q/x1IonfSSm094chM54/Zwhq9MWx+T0EixnGXO4z7jI14EtsdQW12tDd+ADCU75Ob/06JXF0nrxNn0ej8MJM=`

func TestNotifyVerify(t *testing.T) {
	testCases := []struct {
		input     string
		expiresIn time.Duration
		logging   string
	}{
		// 0
		{
			input:     "s1,d1.local",
			expiresIn: 10 * 24 * time.Hour,
			logging: `
INFO-V(2) acme: skipping sign, certificate is updated: secret=s1 domain(s)=d1.local`,
		},
		// 1
		{
			input:     "s1,d2.local",
			expiresIn: -10 * 24 * time.Hour,
			logging: `
INFO acme: authorizing: id=1 secret=s1 domain(s)=d2.local endpoint=https://acme-v2.local reason='certificate expires in 2020-12-01 16:33:14 +0000 UTC'
INFO acme: new certificate issued: id=1 secret=s1 domain(s)=d2.local`,
		},
		// 2
		{
			input:     "s1,d3.local",
			expiresIn: 10 * 24 * time.Hour,
			logging: `
INFO acme: authorizing: id=1 secret=s1 domain(s)=d3.local endpoint=https://acme-v2.local reason='added one or more domains to an existing certificate'
INFO acme: new certificate issued: id=1 secret=s1 domain(s)=d3.local`,
		},
		// 3
		{
			input:     "s2,d1.local",
			expiresIn: 10 * 24 * time.Hour,
			logging: `
INFO acme: authorizing: id=1 secret=s2 domain(s)=d1.local endpoint=https://acme-v2.local reason='certificate does not exist'
INFO acme: new certificate issued: id=1 secret=s2 domain(s)=d1.local`,
		},
	}
	c := setup(t)
	defer c.teardown()
	crt, _ := base64.StdEncoding.DecodeString(dumbcrt)
	x509, _ := x509.ParseCertificate(crt)
	c.cache.tlsSecret["s1"] = &TLSSecret{Crt: x509}
	for _, test := range testCases {
		signer := c.newSigner()
		signer.account.Endpoint = "https://acme-v2.local"
		signer.expiring = x509.NotAfter.Sub(time.Now().Add(test.expiresIn))
		signer.Notify(test.input)
		c.logger.CompareLogging(test.logging)
	}
}

func setup(t *testing.T) *config {
	return &config{
		t: t,
		cache: &cache{
			tlsSecret: map[string]*TLSSecret{},
		},
		logger:  types_helper.NewLoggerMock(t),
		metrics: types_helper.NewMetricsMock(),
	}
}

type config struct {
	t       *testing.T
	cache   *cache
	logger  *types_helper.LoggerMock
	metrics *types_helper.MetricsMock
}

func (c *config) teardown() {
	c.logger.CompareLogging("")
}

func (c *config) newSigner() *signer {
	signer := NewSigner(c.logger, c.cache, c.metrics).(*signer)
	signer.client = &clientMock{}
	return signer
}

type clientMock struct{}

func (c *clientMock) Sign(domains []string) (crt, key []byte, err error) {
	return nil, nil, nil
}

type cache struct {
	tlsSecret map[string]*TLSSecret
}

func (c *cache) GetKey() (crypto.Signer, error) {
	return nil, nil
}

func (c *cache) SetToken(domain string, uri, token string) error {
	return nil
}

func (c *cache) GetToken(domain, uri string) string {
	return ""
}

func (c *cache) GetTLSSecretContent(secretName string) *TLSSecret {
	tls, found := c.tlsSecret[secretName]
	if found {
		return tls
	}
	return nil
}

func (c *cache) SetTLSSecretContent(secretName string, pemCrt, pemKey []byte) error {
	return nil
}
