package options

type Framework func(o *frameworkOpt)

func CRDs(crds ...string) Framework {
	return func(o *frameworkOpt) {
		for _, crd := range crds {
			o.CRDPaths = append(o.CRDPaths, "tests/framework/crds/"+crd+".yaml")
		}
	}
}

type frameworkOpt struct {
	CRDPaths []string
}

func ParseFrameworkOptions(opts ...Framework) (opt frameworkOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
