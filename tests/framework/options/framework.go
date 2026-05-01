package options

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
)

type Framework func(o *frameworkOpt)

func CRDs(crds ...string) Framework {
	return func(o *frameworkOpt) {
		for _, crd := range crds {
			o.CRDPaths = append(o.CRDPaths, "tests/framework/crds/"+crd+".yaml")
		}
	}
}

type OptOverrideCallback = func(opt *config.Options)

func OptOverride(optOverride OptOverrideCallback) Framework {
	return func(o *frameworkOpt) {
		o.OptOverride = optOverride
	}
}

type frameworkOpt struct {
	CRDPaths    []string
	OptOverride OptOverrideCallback
}

func ParseFrameworkOptions(opts ...Framework) (opt frameworkOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
