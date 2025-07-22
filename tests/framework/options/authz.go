package options

type Authz func(o *authzOpt)

func AuthzPasskey(key, value string) Authz {
	return func(o *authzOpt) {
		o.AuthzKey = key
		o.AuthzValue = value
	}
}

type authzOpt struct {
	AuthzKey   string
	AuthzValue string
}

func ParseAuthzOptions(opts ...Authz) (opt authzOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
