package options

import "net/http"

type Request func(o *requestOpt)

func ExpectResponseCode(code int) Request {
	return func(o *requestOpt) {
		o.ExpectResponseCode = code
	}
}

func ExpectError(msg string) Request {
	return func(o *requestOpt) {
		o.ExpectError = msg
	}
}

func SetHeader(key, value string) Request {
	return func(o *requestOpt) {
		if o.ReqHeaders == nil {
			o.ReqHeaders = make(map[string]string)
		}
		o.ReqHeaders[key] = value
	}
}

func Body(body string) Request {
	return func(o *requestOpt) {
		o.Body = body
	}
}

func TLSRequest() Request {
	return func(o *requestOpt) {
		o.TLS = true
	}
}

func TLSVerify(verify bool) Request {
	return func(o *requestOpt) {
		o.TLSSkipVerify = !verify
	}
}

func TLSSkipVerify() Request {
	return func(o *requestOpt) {
		o.TLSSkipVerify = true
	}
}

func ClientCA(ca []byte) Request {
	return func(o *requestOpt) {
		o.ClientCA = ca
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

func RequestPort(port int32) Request {
	return func(o *requestOpt) {
		o.RequestPort = port
	}
}

func CustomRequest(custom CustomRequestCallback) Request {
	return func(o *requestOpt) {
		o.CustomRequest = custom
	}
}

type CustomRequestCallback func(req *http.Request)

type requestOpt struct {
	ExpectResponseCode int
	ExpectError        string
	ReqHeaders         map[string]string
	Body               string
	TLS                bool
	TLSSkipVerify      bool
	ClientCA           []byte
	SNI                string
	ClientCrtPEM       []byte
	ClientKeyPEM       []byte
	RequestPort        int32
	CustomRequest      CustomRequestCallback
}

func ParseRequestOptions(opts ...Request) (opt requestOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
