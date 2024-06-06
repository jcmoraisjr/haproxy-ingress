package options

type Certificate func(o *certificateOpt)

func DNS(dns ...string) Certificate {
	return func(o *certificateOpt) {
		o.DNS = dns
	}
}

func InvalidDates() Certificate {
	return func(o *certificateOpt) {
		o.InvalidDates = true
	}
}

type certificateOpt struct {
	DNS          []string
	InvalidDates bool
}

func ParseCertificateOptions(opts ...Certificate) (opt certificateOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
