package options

import (
	"crypto/tls"
	"crypto/x509"
)

type Server func(o *serverOpt)

func ServerCertificates(certs []tls.Certificate) Server {
	return func(o *serverOpt) {
		o.Certs = certs
	}
}

func ClientCACertificate(ca *x509.Certificate) Server {
	return func(o *serverOpt) {
		o.ClientCA = ca
	}
}

type serverOpt struct {
	Certs    []tls.Certificate
	ClientCA *x509.Certificate
}

func ParseServerOptions(opts ...Server) (opt serverOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
