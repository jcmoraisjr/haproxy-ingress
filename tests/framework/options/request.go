package options

type Request func(o *requestOpt)

func ExpectResponseCode(code int) Request {
	return func(o *requestOpt) {
		o.ExpectResponseCode = code
	}
}

func HTTPSRequest(https bool) Request {
	return func(o *requestOpt) {
		o.HTTPS = https
	}
}

func TLSSkipVerify(skipVerify bool) Request {
	return func(o *requestOpt) {
		o.TLSSkipVerify = skipVerify
	}
}

func SNI(servername string) Request {
	return func(o *requestOpt) {
		o.SNI = servername
	}
}

func ClientCertificateKeyPEM(crt, key []byte) Request {
	return func(o *requestOpt) {
		o.ClientCrtPEM = crt
		o.ClientKeyPEM = key
	}
}

type requestOpt struct {
	ExpectResponseCode int
	HTTPS              bool
	TLSSkipVerify      bool
	SNI                string
	ClientCrtPEM       []byte
	ClientKeyPEM       []byte
}

func ParseRequestOptions(opts ...Request) (opt requestOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
