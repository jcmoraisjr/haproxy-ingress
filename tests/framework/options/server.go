package options

import (
	"crypto/tls"
	"crypto/x509"
	"time"
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

func WebsocketMessages(ch chan<- string) Server {
	return func(o *serverOpt) {
		o.WSMessage = ch
	}
}

func ResponseDelay(delay time.Duration) Server {
	return func(o *serverOpt) {
		o.ResponseDelay = delay
	}
}

type serverOpt struct {
	Certs         []tls.Certificate
	ClientCA      *x509.Certificate
	WSMessage     chan<- string
	ResponseDelay time.Duration
}

func ParseServerOptions(opts ...Server) (opt serverOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
