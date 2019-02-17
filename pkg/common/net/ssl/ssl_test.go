/*
Copyright 2015 The Kubernetes Authors.

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

package ssl

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/cert/triple"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
)

// generateRSACerts generates a self signed certificate using a self generated ca
func generateRSACerts(host string) (*triple.KeyPair, *triple.KeyPair, error) {
	ca, err := triple.NewCA("self-sign-ca")
	if err != nil {
		return nil, nil, err
	}

	key, err := certutil.NewPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a server private key: %v", err)
	}

	config := certutil.Config{
		CommonName: host,
		Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	cert, err := certutil.NewSignedCert(config, key, ca.Cert, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to sign the server certificate: %v", err)
	}

	return &triple.KeyPair{
		Key:  key,
		Cert: cert,
	}, ca, nil
}

func TestAddOrUpdateCertAndKey(t *testing.T) {
	td, err := ioutil.TempDir("", "ssl")
	if err != nil {
		t.Fatalf("Unexpected error creating temporal directory: %v", err)
	}
	ingress.DefaultSSLDirectory = td
	ingress.DefaultCACertsDirectory = td

	cert, _, err := generateRSACerts("echoheaders")
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	name := fmt.Sprintf("test-%v", time.Now().UnixNano())

	c := certutil.EncodeCertPEM(cert.Cert)
	k := certutil.EncodePrivateKeyPEM(cert.Key)

	ngxCert, err := AddOrUpdateCertAndKey(name, c, k, []byte{})
	if err != nil {
		t.Fatalf("unexpected error checking SSL certificate: %v", err)
	}

	if ngxCert.PemFileName == "" {
		t.Fatalf("expected path to pem file but returned empty")
	}

	if len(ngxCert.CN) == 0 {
		t.Fatalf("expected at least one cname but none returned")
	}

	if ngxCert.CN[0] != "echoheaders" {
		t.Fatalf("expected cname echoheaders but %v returned", ngxCert.CN[0])
	}
}

func TestCACert(t *testing.T) {
	td, err := ioutil.TempDir("", "ssl")
	if err != nil {
		t.Fatalf("Unexpected error creating temporal directory: %v", err)
	}
	ingress.DefaultSSLDirectory = td
	ingress.DefaultCACertsDirectory = td

	cert, CA, err := generateRSACerts("echoheaders")
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}

	name := fmt.Sprintf("test-%v", time.Now().UnixNano())

	c := certutil.EncodeCertPEM(cert.Cert)
	k := certutil.EncodePrivateKeyPEM(cert.Key)
	ca := certutil.EncodeCertPEM(CA.Cert)

	ngxCert, err := AddOrUpdateCertAndKey(name, c, k, ca)
	if err != nil {
		t.Fatalf("unexpected error checking SSL certificate: %v", err)
	}
	if ngxCert.CAFileName == "" {
		t.Fatalf("expected a valid CA file name")
	}
}

func TestGetFakeSSLCert(t *testing.T) {
	k, c := GetFakeSSLCert()
	if len(k) == 0 {
		t.Fatalf("expected a valid key")
	}
	if len(c) == 0 {
		t.Fatalf("expected a valid certificate")
	}
}

func TestAddCertAuthNoCRL(t *testing.T) {
	td, err := ioutil.TempDir("", "ssl")
	if err != nil {
		t.Fatalf("Unexpected error creating temporal directory: %v", err)
	}
	ingress.DefaultSSLDirectory = td
	ingress.DefaultCACertsDirectory = td

	cn := "demo-ca"
	_, ca, err := generateRSACerts(cn)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	c := certutil.EncodeCertPEM(ca.Cert)
	ic, err := AddCertAuth(cn, c, []byte{})
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	if ic.CAFileName == "" {
		t.Fatalf("expected a valid CA file name")
	}
}

func TestAddCertAuthWithCRL(t *testing.T) {
	td, err := ioutil.TempDir("", "ssl")
	if err != nil {
		t.Fatalf("Unexpected error creating temporal directory: %v", err)
	}
	ingress.DefaultSSLDirectory = td
	ingress.DefaultCACertsDirectory = td
	ingress.DefaultCrlDirectory = td

	cn := "demo-ca"
	_, ca, err := generateRSACerts(cn)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	c := certutil.EncodeCertPEM(ca.Cert)

	crl := []byte(`-----BEGIN X509 CRL-----
MIIC6jCB0wIBATANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJHQjEQMA4GA1UE
CAwHRW5nbGFuZDEWMBQGA1UECgwNRmFrZSBPcmcgTHRkLjESMBAGA1UEAwwJRmFr
ZSBSb290MSIwIAYJKoZIhvcNAQkBFhNmYWtlQHRlc3RlcnRvbnMuY29tFw0xOTAy
MTgyMjQ1NTNaFw0xOTAzMjAyMjQ1NTNaoDAwLjAfBgNVHSMEGDAWgBQaog7kJ5Yn
dBI9oD7YpFkVye9ICjALBgNVHRQEBAICEAAwDQYJKoZIhvcNAQELBQADggIBAFj7
W3twbqXOjsyPWmiw0rMBzgYqfPFVB8Ox5sItO88SjobfYdt9HMr3tn7j5X4FhKyc
HWXbclLY7vk0a8GMtxsqGgWZePFMQ5X/Af/JYz0UjBEUMLF2qqdNp9YOUZOorBTS
YVMFMPu4sHC6Ub/2q9dhegXop9rS14dC8/QfExMw0VJturWQ107hZPVF+JUwPGcA
a9WwYzPn3Tq1mIuLVo0L1nlG8L5FpkkeP27ot+K9VmfhhqKngTYZCnicoAqp9toQ
Ass1RNFxHk726yDOtfN4EjxFAYmd0BPil+lV1MwsWvanwP//HDWccfs+uhRONPEc
1qftNc+onxsFr+44PKCCwJEwhI7SDO460I1pE3FXSgSqjHrO6yb4EYmXZS1NJOqm
oNgqAVl8sHjsabXpSJxpjmauR+OJyz0eknSdqFuN+2st83lbZNOVXb4Vaxq/CB9d
ztrRPMqRjzJYKeYQOCNA7NRU8yiwO62oEMsB6EMVJJv+mWJQRWMcy1tV8l2AD6b+
G1AfFHxBSaRZSC6hGzqgqn3dUEnyeK4/4j3gWMg53NrOrh58AdIJcqFdJ3p7Ew2B
sSc/Li/1n53ehdXe5YiHk/oHrkBVWM01glk8OdREFAwpfPXguuLSi/m+r0LNZIXZ
LzIFySlMeNl9yobJQr9dRw1rYpqnUZ6VOduAvIBw
-----END X509 CRL-----`)

	ic, err := AddCertAuth(cn, c, crl)
	if err != nil {
		t.Fatalf("unexpected error creating SSL certificate: %v", err)
	}
	if ic.CAFileName == "" {
		t.Fatalf("expected a valid CA file name")
	}
	if ic.CRLFileName == "" {
		t.Fatalf("expected a valid CRL file name")
	}
}
