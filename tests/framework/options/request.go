package options

type Request func(o *requestOpt)

func ExpectResponseCode(code int) Request {
	return func(o *requestOpt) {
		o.ExpectResponseCode = code
	}
}

func HTTPSRequest(skipVerify bool) Request {
	return func(o *requestOpt) {
		o.HTTPS = true
		o.TLSSkipVerify = skipVerify
	}
}

type requestOpt struct {
	ExpectResponseCode int
	HTTPS              bool
	TLSSkipVerify      bool
}

func ParseRequestOptions(opts ...Request) (opt requestOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
