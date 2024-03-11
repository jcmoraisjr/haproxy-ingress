package options

type Request func(o *requestOpt)

func ExpectResponseCode(code int) Request {
	return func(o *requestOpt) {
		o.ExpectResponseCode = code
	}
}

type requestOpt struct {
	ExpectResponseCode int
}

func ParseRequestOptions(opts ...Request) (opt requestOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
