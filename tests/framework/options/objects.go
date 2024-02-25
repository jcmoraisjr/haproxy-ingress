package options

import "sigs.k8s.io/controller-runtime/pkg/client"

type Object func(o *objectOpt)

func AddConfigKeyAnnotations(ann map[string]string) Object {
	annprefix := "haproxy-ingress.github.io/"
	return func(o *objectOpt) {
		if o.Ann == nil {
			o.Ann = make(map[string]string)
		}
		for k, v := range ann {
			o.Ann[annprefix+k] = v
		}
	}
}

func DefaultHostTLS() Object {
	return func(o *objectOpt) {
		o.IngressOpt.DefaultTLS = true
	}
}

type objectOpt struct {
	Ann map[string]string
	IngressOpt
}

type IngressOpt struct {
	DefaultTLS bool
}

func (o *objectOpt) Apply(obj client.Object) {
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = make(map[string]string, len(o.Ann))
	}
	for k, v := range o.Ann {
		ann[k] = v
	}
	obj.SetAnnotations(ann)
}

func ParseObjectOptions(opts ...Object) (opt objectOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
