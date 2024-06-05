package framework

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	CertificateIssuerCN = "HAProxy Ingress issuer"
	CertificateClientCN = "HAProxy Ingress client"
)

func CreateCA(t *testing.T, dns ...string) (ca, key []byte) {
	serial, err := rand.Int(rand.Reader, big.NewInt(2^63))
	require.NoError(t, err)
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(24 * time.Hour)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: CertificateIssuerCN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dns,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cader, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyder := x509.MarshalPKCS1PrivateKey(priv)
	ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cader})
	key = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyder})
	return ca, key
}

func CreateCertificate(t *testing.T, ca, cakey []byte, dns ...string) (crt, key []byte) {
	cakeyder, _ := pem.Decode(cakey)
	cakeyrsa, err := x509.ParsePKCS1PrivateKey(cakeyder.Bytes)
	require.NoError(t, err)

	cader, _ := pem.Decode(ca)
	cax509, err := x509.ParseCertificate(cader.Bytes)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, big.NewInt(2^63))
	require.NoError(t, err)
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(24 * time.Hour)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: CertificateClientCN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  dns,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	crtder, err := x509.CreateCertificate(rand.Reader, &template, cax509, &priv.PublicKey, cakeyrsa)
	require.NoError(t, err)
	keyder := x509.MarshalPKCS1PrivateKey(priv)
	crt = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crtder})
	key = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyder})
	return crt, key
}
