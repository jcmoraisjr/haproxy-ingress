package options

import (
	"math/rand"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Object func(o *objectOpt)

func AddConfigKeyAnnotation(key, value string) Object {
	annprefix := "haproxy-ingress.github.io/"
	return func(o *objectOpt) {
		if o.Ann == nil {
			o.Ann = make(map[string]string)
		}
		o.Ann[annprefix+key] = value
	}
}

func DefaultHostTLS() Object {
	return func(o *objectOpt) {
		o.IngressOpt.DefaultTLS = true
	}
}

func Listener(name, proto string, port int32) Object {
	return func(o *objectOpt) {
		o.GatewayOpt.Listeners = append(o.GatewayOpt.Listeners, ListenerOpt{
			Name:  name,
			Proto: proto,
			Port:  port,
		})
	}
}

func TCPListener() Object {
	return Listener("tcpservice-gw", "TCP", int32(32768+rand.Intn(32767)))
}

type objectOpt struct {
	Ann map[string]string
	IngressOpt
	GatewayOpt
}

type IngressOpt struct {
	DefaultTLS bool
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
}

func ParseObjectOptions(opts ...Object) (opt objectOpt) {
	for _, o := range opts {
		o(&opt)
	}
	return opt
}
