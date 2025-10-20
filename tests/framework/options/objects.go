package options

import (
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
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

// Listener creates a new listener on a Gateway object. certs is ignored on HTTP, TCP and UDP protos.
// HTTPS proto requires len(certs)>0. TLS proto infers Terminate mode if len(certs)>0, Passthrough is
// used otherwise.
func Listener(name gatewayv1.SectionName, proto gatewayv1.ProtocolType, port gatewayv1.PortNumber, certs []gatewayv1.SecretObjectReference) Object {
	return func(o *objectOpt) {
		o.Listeners = append(o.Listeners, ListenerOpt{
			Name:  name,
			Proto: proto,
			Port:  port,
			Certs: certs,
		})
	}
}
func CustomObject(custom CustomObjectCallback) Object {
	return func(o *objectOpt) {
		o.custom = custom
	}
}

type CustomObjectCallback func(client.Object)

type objectOpt struct {
	Ann map[string]string
	IngressOpt
	GatewayOpt
	custom CustomObjectCallback
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
	Name  gatewayv1.SectionName
	Proto gatewayv1.ProtocolType
	Port  gatewayv1.PortNumber
	Certs []gatewayv1.SecretObjectReference
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
