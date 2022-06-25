/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	api "k8s.io/api/core/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// CreateSSLCerts ...
func CreateSSLCerts(c *config.Config) *SSL {
	return &SSL{
		c: c,
	}
}

// SSL ...
type SSL struct {
	c *config.Config
}

type sslCert struct {
	Certificate *x509.Certificate
	CAFileName  string
	CRLFileName string
	PemFileName string
	PemSHA      string
}

func (s *SSL) createSelfSignedCert(cn string, org, dns []string) (crt, key []byte, err error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(2^63))
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: org,
			CommonName:   cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	dercrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	derkey, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	secp256r1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		return nil, nil, err
	}
	crt = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dercrt})
	key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derkey})
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: secp256r1})
	key = append(params, key...)
	return crt, key, nil
}

func (s *SSL) checkValidPEM(raw []byte, pemTypes ...string) ([]byte, error) {
	var der []byte
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("no valid PEM formatted block found")
		}
		var valid bool
		for _, pemType := range pemTypes {
			if block.Type == pemType {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("expected PEM type(s) '%s', found '%s'", strings.Join(pemTypes, ","), block.Type)
		}
		if der == nil {
			der = block.Bytes
		}
	}
	return der, nil
}

func (s *SSL) checkValidCertPEM(raw []byte) (*x509.Certificate, error) {
	var x509crt *x509.Certificate
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("no valid PEM formatted block found")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected PEM type 'CERTIFICATE', found '%s'", block.Type)
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if x509crt == nil {
			x509crt = crt
		}
	}
	return x509crt, nil
}

func (s *SSL) buildCertFromCrtAndKey(fileName string, crt, key, ca []byte) (*sslCert, error) {
	x509crt, err := s.checkValidCertPEM(crt)
	if err != nil {
		return nil, err
	}
	if _, err := s.checkValidPEM(key, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "EC PARAMETERS"); err != nil {
		return nil, err
	}
	if _, err := tls.X509KeyPair(crt, key); err != nil {
		return nil, err
	}
	var caFileName string
	if len(ca) > 0 {
		// common/legacy implementation adds ca in the crt+key file
		// if the ca.crt key is configured in the same secret -
		// cannot be used e.g. for mTLS.
		//
		// https://github.com/jcmoraisjr/haproxy-ingress/blob/release-0.13/pkg/common/net/ssl/ssl.go#L138
		//
		if _, err := s.checkValidCertPEM(ca); err != nil {
			return nil, err
		}
		root := x509.NewCertPool()
		intm := x509.NewCertPool()
		root.AppendCertsFromPEM(ca)
		intm.AppendCertsFromPEM(crt)
		_, err := x509crt.Verify(x509.VerifyOptions{
			Roots:         root,
			Intermediates: intm,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain: %w", err)
		}
		caFileName = fileName
		ca = append(ca, '\n')
		crt = append(crt, ca...)
	}
	crt = append(crt, '\n')
	output := append(crt, key...)
	if err := os.WriteFile(fileName, output, 0600); err != nil {
		return nil, err
	}
	pemSHA1 := sha1.Sum(output)
	return &sslCert{
		Certificate: x509crt,
		CAFileName:  caFileName,
		PemFileName: fileName,
		PemSHA:      hex.EncodeToString(pemSHA1[:]),
	}, nil
}

func (s *SSL) buildCertFromCAAndCRL(caFileName, crlFileName string, ca, crl []byte) (*sslCert, error) {
	if _, err := s.checkValidCertPEM(ca); err != nil {
		return nil, err
	}
	var pemSHA1 [sha1.Size]byte
	if len(crl) == 0 {
		crlFileName = ""
		pemSHA1 = sha1.Sum(ca)
	} else {
		if _, err := s.checkValidPEM(crl, "X509 CRL"); err != nil {
			return nil, err
		}
		if err := os.WriteFile(crlFileName, crl, 0600); err != nil {
			return nil, err
		}
		pemSHA1 = sha1.Sum(append(ca, crl...))
	}
	if err := os.WriteFile(caFileName, ca, 0600); err != nil {
		return nil, err
	}
	return &sslCert{
		CAFileName:  caFileName,
		CRLFileName: crlFileName,
		PemFileName: caFileName,
		PemSHA:      hex.EncodeToString(pemSHA1[:]),
	}, nil
}

func (s *SSL) createFakeCertAndCA() (crtFile, caFile convtypes.CrtFile, err error) {
	fakeCrt, fakeKey, err := s.createSelfSignedCert(
		"Kubernetes Ingress Controller Fake Certificate",
		[]string{"Acme Co"},
		[]string{"localhost", "ingress.local"},
	)
	if err != nil {
		return crtFile, caFile, err
	}
	fakeCA, _, err := s.createSelfSignedCert("Fake CA", nil, nil)
	if err != nil {
		return crtFile, caFile, err
	}
	crtFileName := fmt.Sprintf("%s/_fake-default.pem", s.c.DefaultDirCerts)
	sslCrt, err := s.buildCertFromCrtAndKey(crtFileName, fakeCrt, fakeKey, nil)
	if err != nil {
		return crtFile, caFile, err
	}
	caFileName := fmt.Sprintf("%s/ca__fake-default.pem", s.c.DefaultDirCACerts)
	sslCA, err := s.buildCertFromCAAndCRL(caFileName, "", fakeCA, nil)
	if err != nil {
		return crtFile, caFile, err
	}
	crtFile = convtypes.CrtFile{
		Filename:   sslCrt.PemFileName,
		SHA1Hash:   sslCrt.PemSHA,
		CommonName: sslCrt.Certificate.Subject.CommonName,
		NotAfter:   sslCrt.Certificate.NotAfter,
	}
	caFile = convtypes.CrtFile{
		Filename: sslCA.PemFileName,
		SHA1Hash: sslCA.PemSHA,
	}
	return crtFile, caFile, nil
}

func (s *SSL) getCertificate(secret *api.Secret) (*sslCert, error) {
	ns := secret.Namespace
	name := secret.Name
	crt := secret.Data[api.TLSCertKey]
	key := secret.Data[api.TLSPrivateKeyKey]
	ca := secret.Data["ca.crt"]
	if len(crt) > 0 && len(key) > 0 {
		fileName := fmt.Sprintf("%s/%s_%s.pem", s.c.DefaultDirCerts, ns, name)
		return s.buildCertFromCrtAndKey(fileName, crt, key, ca)
	}
	if len(ca) > 0 {
		caFileName := fmt.Sprintf("%s/ca_%s_%s.pem", s.c.DefaultDirCACerts, ns, name)
		crl := secret.Data["ca.crl"]
		var crlFileName string
		if len(crl) > 0 {
			crlFileName = fmt.Sprintf("%s/ca_%s_%s_crl.pem", s.c.DefaultDirCrl, ns, name)
		}
		return s.buildCertFromCAAndCRL(caFileName, crlFileName, ca, crl)
	}
	return nil, fmt.Errorf("secret '%s/%s' have neither ca.crt nor tls.crt/tls.key pair", ns, name)
}

func (s *SSL) getDHParam(secret *api.Secret) (*sslCert, error) {
	ns := secret.Namespace
	name := secret.Name
	dh := secret.Data["dhparam.pem"]
	if len(dh) == 0 {
		return nil, fmt.Errorf("secret '%s/%s' does not have key '%s'", ns, name, "dhparam.pem")
	}
	pemName := fmt.Sprintf("%s_%s", ns, name)
	if _, err := s.checkValidPEM(dh, "DH PARAMETERS"); err != nil {
		return nil, err
	}
	fileName := fmt.Sprintf("%s/%s.pem", s.c.DefaultDirDHParam, pemName)
	err := os.WriteFile(fileName, dh, 0600)
	if err != nil {
		return nil, err
	}
	pemSHA1 := sha1.Sum(dh)
	return &sslCert{
		PemFileName: fileName,
		PemSHA:      hex.EncodeToString(pemSHA1[:]),
	}, nil
}
