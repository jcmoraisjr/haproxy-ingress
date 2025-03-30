package options

import (
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Object func(o *objectOpt)

func AddConfigKeyAnnotation(key, value string) Object {
	return func(o *objectOpt) {
		if o.Ann == nil {
			o.Ann = make(map[string]string)
		}
		annprefix := "haproxy-ingress.github.io/"
		o.Ann[annprefix+key] = value
	}
}

func DefaultTLS() Object {
	return func(o *objectOpt) {
		o.DefaultTLS = true
	}
}

func CustomTLS(secret string) Object {
	return func(o *objectOpt) {
		o.CustomTLSSecret = secret
	}
}

func CustomHostName(hostname string) Object {
	return func(o *objectOpt) {
		o.CustomHostName = ptr.To(hostname)
	}
}
func Listener(name, proto string, port int32) Object {
	return func(o *objectOpt) {
		o.Listeners = append(o.Listeners, ListenerOpt{
			Name:  name,
			Proto: proto,
			Port:  port,
		})
	}
}
func Custom(custom CustomCallback) Object {
	return func(o *objectOpt) {
		o.custom = custom
	}
}

type CustomCallback func(client.Object)

type objectOpt struct {
	Ann map[string]string
	IngressOpt
	GatewayOpt
	custom CustomCallback
}

type IngressOpt struct {
	DefaultTLS      bool
	CustomTLSSecret string
	CustomHostName  *string
}

type GatewayOpt struct {
	Listeners []ListenerOpt
}

type ListenerOpt struct {
	Name  string
	Proto string
	Port  int32
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
	if o.custom != nil {
		o.custom(obj)
	}
}

func ParseObjectOptions(opts ...Object) (opt objectOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
