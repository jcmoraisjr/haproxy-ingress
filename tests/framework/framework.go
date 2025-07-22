package framework

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	ctrlconfig "github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/launch"
	"github.com/jcmoraisjr/haproxy-ingress/tests/framework/options"
)

const (
	PublishSvcName  = "default/publish"
	PublishAddress  = "10.0.1.1"
	PublishHostname = "ingress.local"

	TestPortHTTP  = 28080
	TestPortHTTPS = 28443
	TestPortStat  = 21936
)

func NewFramework(ctx context.Context, t *testing.T, o ...options.Framework) *framework {
	opt := options.ParseFrameworkOptions(o...)

	wd, err := os.Getwd()
	require.NoError(t, err)
	if filepath.Base(wd) == "integration" {
		err := os.Chdir(filepath.Join("..", ".."))
		require.NoError(t, err)
	}
	_, err = os.Stat("rootfs")
	require.NoError(t, err)

	major, minor, full := haproxyVersion(t)
	if major < 2 || (major == 2 && minor < 2) {
		require.Fail(t, "unsupported haproxy version", "need haproxy 2.2 or newer, found %s", full)
	}
	t.Logf("using haproxy %s\n", full)

	config := startApiserver(t, opt.CRDPaths)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1alpha2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1beta1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))

	cli, err := client.NewWithWatch(config, client.Options{Scheme: scheme})
	require.NoError(t, err)

	return &framework{
		scheme: scheme,
		config: config,
		cli:    cli,
	}
}

type framework struct {
	scheme *runtime.Scheme
	config *rest.Config
	cli    client.WithWatch
}

// HAProxy version 3.2-dev6-4ef6be4 2025/02/19 - https://haproxy.org/
// HAProxy version 3.1.5-076df02 2025/02/20 - https://haproxy.org/
// HAProxy version 3.0.8-6036c31 2025/01/29 - https://haproxy.org/
// HAProxy version 2.9.14-7c591d5 2025/01/29 - https://haproxy.org/
// HAProxy version 2.8.14-c23fe91 2025/01/29 - https://haproxy.org/
// HAProxy version 2.6.21-5d6f8e1 2025/01/29 - https://haproxy.org/
// HAProxy version 2.4.28-6b47cb7 2024/11/08 - https://haproxy.org/
// HA-Proxy version 2.2.33-f7cac83 2024/04/05 - https://haproxy.org/
var haproxyVersionRegex = regexp.MustCompile(`^HA-?Proxy version ([0-9]+)\.([0-9]+)([.-][dev0-9]+)`)

func haproxyVersion(t *testing.T) (major, minor int, full string) {
	cmd := exec.Command("haproxy", "-v")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "need haproxy 2.2 or newer installed")
	digits := haproxyVersionRegex.FindStringSubmatch(string(out))
	atoi := func(s string) int {
		i, err := strconv.Atoi(s)
		require.NoError(t, err)
		return i
	}
	major = atoi(digits[1])
	minor = atoi(digits[2])
	full = fmt.Sprintf("%d.%d%s", major, minor, digits[3])
	return major, minor, full
}

func startApiserver(t *testing.T, crdPaths []string) *rest.Config {
	t.Log("starting apiserver")

	e := envtest.Environment{
		// run `make setup-envtest` to download envtest binaries.
		BinaryAssetsDirectory: filepath.Join("bin", "k8s", fmt.Sprintf("1.32.0-%s-%s", goruntime.GOOS, goruntime.GOARCH)),
		CRDDirectoryPaths:     crdPaths,
		ErrorIfCRDPathMissing: true,
	}
	config, err := e.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, e.Stop())
	})
	return config
}

func (f *framework) StartController(ctx context.Context, t *testing.T) {
	t.Log("starting controller")

	err := os.RemoveAll("/tmp/haproxy-ingress")
	require.NoError(t, err)
	err = os.MkdirAll("/tmp/haproxy-ingress/etc/haproxy/lua/", 0755)
	require.NoError(t, err)
	luadir, err := os.ReadDir("rootfs/etc/lua/")
	require.NoError(t, err)
	for _, d := range luadir {
		if d.IsDir() {
			continue
		}
		f1, err := os.Open(filepath.Join("rootfs/etc/lua", d.Name()))
		require.NoError(t, err)
		f2, err := os.OpenFile(
			filepath.Join("/tmp/haproxy-ingress/etc/haproxy/lua", d.Name()),
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			0644)
		require.NoError(t, err)
		_, err = io.Copy(f2, f1)
		require.NoError(t, err)
	}

	global := corev1.ConfigMap{}
	global.Namespace = "default"
	global.Name = "ingress-controller"
	global.Data = map[string]string{
		"http-port":       strconv.Itoa(TestPortHTTP),
		"https-port":      strconv.Itoa(TestPortHTTPS),
		"stats-port":      strconv.Itoa(TestPortStat),
		"max-connections": "20",
	}
	err = f.cli.Create(ctx, &global)
	require.NoError(t, err)

	publishService := corev1.Service{}
	publishService.Namespace, publishService.Name, _ = cache.SplitMetaNamespaceKey(PublishSvcName)
	publishService.Spec.Type = corev1.ServiceTypeLoadBalancer
	publishService.Spec.Ports = []corev1.ServicePort{{Port: 80}}
	err = f.cli.Create(ctx, &publishService)
	require.NoError(t, err)
	publishService.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: PublishAddress, Hostname: PublishHostname},
	}
	err = f.cli.Status().Update(ctx, &publishService)
	require.NoError(t, err)

	opt := ctrlconfig.NewOptions()
	opt.MasterWorker = true
	opt.LocalFSPrefix = "/tmp/haproxy-ingress"
	opt.EnableEndpointSlicesAPI = true
	opt.PublishService = PublishSvcName
	opt.ConfigMap = "default/ingress-controller"
	os.Setenv("POD_NAMESPACE", "default")
	ctx, cancel := context.WithCancel(ctx)
	cfg, err := ctrlconfig.CreateWithConfig(ctx, f.config, opt)
	require.NoError(t, err)

	done := make(chan bool)
	go func() {
		err := launch.Run(cfg)
		assert.NoError(t, err)
		done <- true
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	t.Log("waiting for controller and haproxy to be ready")
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		// ensuring controller is up and running avoids all the tests to fail due to misconfiguration
		url := fmt.Sprintf("http://127.0.0.1:%d", TestPortHTTP)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if !assert.NoError(collect, err) {
			return
		}
		req.URL.Path = "/"
		_, err = http.DefaultClient.Do(req)
		assert.NoError(collect, err)
	}, 10*time.Second, time.Second)
}

type Response struct {
	HTTPResponse *http.Response
	Body         string
	EchoResponse EchoResponse
}

func (*framework) Request(ctx context.Context, t *testing.T, method, host, path string, o ...options.Request) Response {
	t.Logf("request method=%s host=%s path=%s\n", method, host, path)
	opt := options.ParseRequestOptions(o...)

	var url string
	if opt.TLS {
		url = fmt.Sprintf("https://127.0.0.1:%d", TestPortHTTPS)
	} else {
		url = fmt.Sprintf("http://127.0.0.1:%d", TestPortHTTP)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	require.NoError(t, err)
	req.Host = host
	req.URL.Path = path
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opt.TLSSkipVerify,
			ServerName:         opt.SNI,
		},
	}
	if opt.ClientCA != nil {
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(opt.ClientCA)
		require.True(t, ok)
		transport.TLSClientConfig.RootCAs = pool
	}
	if opt.ClientCrtPEM != nil && opt.ClientKeyPEM != nil {
		cert, err := tls.X509KeyPair(opt.ClientCrtPEM, opt.ClientKeyPEM)
		require.NoError(t, err)

		// transport.TLSClientConfig.Certificates is also an option, but when using it,
		// http client filters out client side certificates whose issuer's DN does not
		// match the DN from the CAs provided by the server. If any certificate matches,
		// no certificate is provided in the TLS handshake. We don't want this behavior,
		// our tests expect that the certificate is always sent when provided.
		transport.TLSClientConfig.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}
	cli := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}
	var res *http.Response
	switch {
	case opt.ExpectResponseCode > 0:
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			res, err = cli.Do(req)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, opt.ExpectResponseCode, res.StatusCode)
		}, 5*time.Second, time.Second)
	case opt.ExpectX509Error != "":
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			_, err := cli.Do(req)
			// better if matching some x509.<...>Error{} instead,
			// but error.Is() does not render to true due to the server's
			// x509 certificate attached to the error instance.
			assert.ErrorContains(collect, err, opt.ExpectX509Error)
		}, 5*time.Second, time.Second)
		return Response{EchoResponse: buildEchoResponse(t, "")}
	default:
		res, err = cli.Do(req)
		require.NoError(t, err)
	}
	require.NotNil(t, res, "request closure should reassign the response")
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	t.Logf("response body:\n%s\n", body)
	strbody := string(body)
	return Response{
		HTTPResponse: res,
		Body:         strbody,
		EchoResponse: buildEchoResponse(t, strbody),
	}
}

func (*framework) TCPRequest(ctx context.Context, t *testing.T, tcpPort int32, data string, o ...options.Request) string {
	// TODO: missing most of options.Request
	opt := options.ParseRequestOptions(o...)

	var conn net.Conn
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var err error
		if opt.TLS {
			conn, err = tls.Dial("tcp", fmt.Sprintf(":%d", tcpPort), &tls.Config{InsecureSkipVerify: true})
		} else {
			conn, err = net.Dial("tcp", fmt.Sprintf(":%d", tcpPort))
		}
		assert.NoError(collect, err)
	}, 5*time.Second, time.Second)
	defer conn.Close()
	_, err := conn.Write([]byte(data))
	require.NoError(t, err)
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return string(buf[:n])
}

func (f *framework) Client() client.WithWatch {
	return f.cli
}

func (f *framework) CreateSecret(ctx context.Context, t *testing.T, secretData map[string][]byte, o ...options.Object) *corev1.Secret {
	opt := options.ParseObjectOptions(o...)
	data := `
apiVersion: v1
kind: Secret
metadata:
  name: ""
  namespace: default
`
	name := RandomName("secret")

	secret := f.CreateObject(t, data).(*corev1.Secret)
	secret.Name = name
	secret.Data = secretData
	opt.Apply(secret)

	t.Logf("creating Secret %s/%s\n", secret.Namespace, secret.Name)

	err := f.cli.Create(ctx, secret)
	require.NoError(t, err)

	t.Cleanup(func() {
		secret := corev1.Secret{}
		secret.Namespace = "default"
		secret.Name = name
		err := f.cli.Delete(ctx, &secret)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return secret
}

func (f *framework) CreateSecretTLS(ctx context.Context, t *testing.T, crt, key []byte, o ...options.Object) *corev1.Secret {
	return f.CreateSecret(ctx, t, map[string][]byte{
		corev1.TLSCertKey:       crt,
		corev1.TLSPrivateKeyKey: key,
	})
}

func (f *framework) CreateService(ctx context.Context, t *testing.T, serverPort int32, o ...options.Object) *corev1.Service {
	opt := options.ParseObjectOptions(o...)
	data := `
apiVersion: v1
kind: Service
metadata:
  name: ""
  namespace: default
spec:
  ports:
  - port: 9999 ## meaningless, just need to match ingress' one
    targetPort: 0
`
	name := RandomName("svc")

	// we don't have real pods, so we don't have ep/eps along with the service,
	// so we need to create them manually.
	_ = f.CreateEndpoints(ctx, t, name, serverPort)
	_ = f.CreateEndpointSlice(ctx, t, name, serverPort)

	svc := f.CreateObject(t, data).(*corev1.Service)
	svc.Name = name
	svc.Spec.Ports[0].TargetPort = intstr.IntOrString{IntVal: serverPort}
	opt.Apply(svc)

	t.Logf("creating service %s/%s\n", svc.Namespace, svc.Name)

	err := f.cli.Create(ctx, svc)
	require.NoError(t, err)

	t.Cleanup(func() {
		svc := corev1.Service{}
		svc.Namespace = "default"
		svc.Name = name
		err := f.cli.Delete(ctx, &svc)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return svc
}

func (f *framework) CreateEndpoints(ctx context.Context, t *testing.T, svcname string, serverPort int32) *corev1.Endpoints {
	data := `
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    haproxy-ingress.github.io/ip-override: 127.0.0.1
  name: ""
  namespace: default
subsets:
- addresses:
  - ip: ::ffff ## will change to loopback via ip-override annotation
  ports:
  - port: 0
`

	ep := f.CreateObject(t, data).(*corev1.Endpoints)
	ep.Name = svcname
	ep.Subsets[0].Ports[0].Port = serverPort

	t.Logf("creating endpoints %s/%s\n", ep.Namespace, ep.Name)

	err := f.cli.Create(ctx, ep)
	require.NoError(t, err)

	t.Cleanup(func() {
		ep := corev1.Endpoints{}
		ep.Namespace = "default"
		ep.Name = svcname
		err := f.cli.Delete(ctx, &ep)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return ep
}

func (f *framework) CreateEndpointSlice(ctx context.Context, t *testing.T, svcname string, serverPort int32) *discoveryv1.EndpointSlice {
	data := `
kind: EndpointSlice
apiVersion: discovery.k8s.io/v1
addressType: IPv4
endpoints:
- addresses:
  - 0.0.0.255 ## will change to loopback via ip-override annotation
  conditions:
    ready: true
metadata:
  annotations:
    haproxy-ingress.github.io/ip-override: 127.0.0.1
  labels: {}
  generateName: ""
  namespace: default
ports:
- port: 0
`

	eps := f.CreateObject(t, data).(*discoveryv1.EndpointSlice)
	eps.GenerateName = svcname + "-"
	eps.Labels["kubernetes.io/service-name"] = svcname
	eps.Ports[0].Port = &serverPort

	t.Logf("creating endpointslice %s/%s\n", eps.Namespace, eps.Name)

	err := f.cli.Create(ctx, eps)
	require.NoError(t, err)
	epname := eps.Name

	t.Cleanup(func() {
		ep := discoveryv1.EndpointSlice{}
		ep.Namespace = "default"
		ep.Name = epname
		err := f.cli.Delete(ctx, &ep)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return eps
}

func (f *framework) CreateIngress(ctx context.Context, t *testing.T, svc *corev1.Service, o ...options.Object) (*networking.Ingress, string) {
	opt := options.ParseObjectOptions(o...)
	data := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: haproxy
  name: ""
  namespace: default
spec:
  rules:
  - host: ""
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ""
            port:
              number: 9999 ## meaningless, just need to match service's one
`
	name := RandomName("ing")
	var hostname string
	if opt.IngressOpt.CustomHostName != nil {
		hostname = *opt.IngressOpt.CustomHostName
	} else {
		hostname = name + ".local"
	}

	ing := f.CreateObject(t, data).(*networking.Ingress)
	ing.Name = name
	ing.Spec.Rules[0].Host = hostname
	ing.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name = svc.Name
	if opt.IngressOpt.CustomTLSSecret != "" {
		ing.Spec.TLS = []networking.IngressTLS{{
			SecretName: opt.IngressOpt.CustomTLSSecret,
		}}
	} else if opt.IngressOpt.DefaultTLS {
		ing.Spec.TLS = []networking.IngressTLS{{SecretName: ""}}
	}
	if len(ing.Spec.TLS) > 0 && hostname != "" {
		ing.Spec.TLS[0].Hosts = []string{hostname}
	}
	opt.Apply(ing)

	t.Logf("creating ingress %s/%s host=%s\n", ing.Namespace, ing.Name, ing.Spec.Rules[0].Host)

	err := f.cli.Create(ctx, ing)
	require.NoError(t, err)

	t.Cleanup(func() {
		ing := networking.Ingress{}
		ing.Namespace = "default"
		ing.Name = name
		err := f.cli.Delete(ctx, &ing)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return ing, hostname
}

func (f *framework) CreateGatewayClassA2(ctx context.Context, t *testing.T, o ...options.Object) *gatewayv1alpha2.GatewayClass {
	return f.CreateGatewayClass(ctx, t, gatewayv1alpha2.GroupVersion.Version, o...).(*gatewayv1alpha2.GatewayClass)
}

func (f *framework) CreateGatewayClassB1(ctx context.Context, t *testing.T, o ...options.Object) *gatewayv1beta1.GatewayClass {
	return f.CreateGatewayClass(ctx, t, gatewayv1beta1.GroupVersion.Version, o...).(*gatewayv1beta1.GatewayClass)
}

func (f *framework) CreateGatewayClassV1(ctx context.Context, t *testing.T, o ...options.Object) *gatewayv1.GatewayClass {
	return f.CreateGatewayClass(ctx, t, gatewayv1.GroupVersion.Version, o...).(*gatewayv1.GatewayClass)
}

func (f *framework) CreateGatewayClass(ctx context.Context, t *testing.T, version string, o ...options.Object) client.Object {
	opt := options.ParseObjectOptions(o...)
	api := v1.GroupVersion{Group: gatewayv1.GroupName, Version: version}.String()
	data := fmt.Sprintf(`
apiVersion: %s
kind: GatewayClass
metadata:
  name: ""
spec:
  controllerName: haproxy-ingress.github.io/controller
`, api)
	name := RandomName("gc")

	gc := f.CreateObject(t, data)
	gc.SetName(name)
	opt.Apply(gc)

	t.Logf("creating GatewayClass %s\n", gc.GetName())

	err := f.cli.Create(ctx, gc)
	require.NoError(t, err)

	t.Cleanup(func() {
		gc := unstructured.Unstructured{}
		gc.SetAPIVersion(api)
		gc.SetKind("GatewayClass")
		gc.SetName(name)
		err := f.cli.Delete(ctx, &gc)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return gc
}

func (f *framework) CreateGatewayA2(ctx context.Context, t *testing.T, gc *gatewayv1alpha2.GatewayClass, o ...options.Object) *gatewayv1alpha2.Gateway {
	return f.CreateGateway(ctx, t, gatewayv1alpha2.GroupVersion.Version, (*gatewayv1.GatewayClass)(gc), o...).(*gatewayv1alpha2.Gateway)
}

func (f *framework) CreateGatewayB1(ctx context.Context, t *testing.T, gc *gatewayv1beta1.GatewayClass, o ...options.Object) *gatewayv1beta1.Gateway {
	return f.CreateGateway(ctx, t, gatewayv1beta1.GroupVersion.Version, (*gatewayv1.GatewayClass)(gc), o...).(*gatewayv1beta1.Gateway)
}

func (f *framework) CreateGatewayV1(ctx context.Context, t *testing.T, gc *gatewayv1.GatewayClass, o ...options.Object) *gatewayv1.Gateway {
	return f.CreateGateway(ctx, t, gatewayv1.GroupVersion.Version, gc, o...).(*gatewayv1.Gateway)
}

func (f *framework) CreateGateway(ctx context.Context, t *testing.T, version string, gc *gatewayv1.GatewayClass, o ...options.Object) client.Object {
	opt := options.ParseObjectOptions(o...)
	if opt.Listeners == nil {
		opt.Listeners = []options.ListenerOpt{{
			Name:  "echoserver-gw",
			Port:  80,
			Proto: "HTTP",
		}}
	}

	api := v1.GroupVersion{Group: gatewayv1.GroupName, Version: version}.String()
	data := fmt.Sprintf(`
apiVersion: %s
kind: Gateway
metadata:
  name: ""
  namespace: default
spec:
  gatewayClassName: ""
`, api)
	name := RandomName("gw")

	gw := f.CreateObject(t, data)
	gw.SetName(name)
	spec := reflect.ValueOf(gw).Elem().FieldByName("Spec").Addr().Interface().(*gatewayv1.GatewaySpec)
	spec.GatewayClassName = gatewayv1.ObjectName(gc.Name)
	for _, l := range opt.Listeners {
		spec.Listeners = append(spec.Listeners, gatewayv1.Listener{
			Name:     gatewayv1.SectionName(l.Name),
			Protocol: gatewayv1.ProtocolType(l.Proto),
			Port:     gatewayv1.PortNumber(l.Port),
		})
	}
	opt.Apply(gw)

	t.Logf("creating Gateway %s/%s\n", gw.GetNamespace(), gw.GetName())

	err := f.cli.Create(ctx, gw)
	require.NoError(t, err)

	t.Cleanup(func() {
		gw := unstructured.Unstructured{}
		gw.SetAPIVersion(api)
		gw.SetKind("Gateway")
		gw.SetNamespace("default")
		gw.SetName(name)
		err := f.cli.Delete(ctx, &gw)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return gw
}

func (f *framework) CreateHTTPRouteA2(ctx context.Context, t *testing.T, gw *gatewayv1alpha2.Gateway, svc *corev1.Service, o ...options.Object) (*gatewayv1alpha2.HTTPRoute, string) {
	route, hostname := f.CreateHTTPRoute(ctx, t, gatewayv1alpha2.GroupVersion.Version, (*gatewayv1.Gateway)(gw), svc, o...)
	return route.(*gatewayv1alpha2.HTTPRoute), hostname
}

func (f *framework) CreateHTTPRouteB1(ctx context.Context, t *testing.T, gw *gatewayv1beta1.Gateway, svc *corev1.Service, o ...options.Object) (*gatewayv1beta1.HTTPRoute, string) {
	route, hostname := f.CreateHTTPRoute(ctx, t, gatewayv1beta1.GroupVersion.Version, (*gatewayv1.Gateway)(gw), svc, o...)
	return route.(*gatewayv1beta1.HTTPRoute), hostname
}

func (f *framework) CreateHTTPRouteV1(ctx context.Context, t *testing.T, gw *gatewayv1.Gateway, svc *corev1.Service, o ...options.Object) (*gatewayv1.HTTPRoute, string) {
	route, hostname := f.CreateHTTPRoute(ctx, t, gatewayv1.GroupVersion.Version, gw, svc, o...)
	return route.(*gatewayv1.HTTPRoute), hostname
}

func (f *framework) CreateHTTPRoute(ctx context.Context, t *testing.T, version string, gw *gatewayv1.Gateway, svc *corev1.Service, o ...options.Object) (client.Object, string) {
	opt := options.ParseObjectOptions(o...)
	api := v1.GroupVersion{Group: gatewayv1.GroupName, Version: version}.String()
	data := fmt.Sprintf(`
apiVersion: %s
kind: HTTPRoute
metadata:
  name: ""
  namespace: default
spec:
  parentRefs:
  - name: ""
  hostnames:
  - ""
  rules:
  - backendRefs:
    - name: ""
      port: 0
`, api)
	name := RandomName("httproute")
	hostname := name + ".local"

	route := f.CreateObject(t, data)
	route.SetName(name)
	spec := reflect.ValueOf(route).Elem().FieldByName("Spec").Addr().Interface().(*gatewayv1.HTTPRouteSpec)
	spec.ParentRefs[0].Name = gatewayv1.ObjectName(gw.Name)
	spec.Hostnames[0] = gatewayv1.Hostname(hostname)
	spec.Rules[0].BackendRefs[0].Name = gatewayv1.ObjectName(svc.Name)
	spec.Rules[0].BackendRefs[0].Port = (*gatewayv1.PortNumber)(&svc.Spec.Ports[0].Port)
	opt.Apply(route)

	t.Logf("creating HTTPRoute %s/%s\n", route.GetNamespace(), route.GetName())

	err := f.cli.Create(ctx, route)
	require.NoError(t, err)

	t.Cleanup(func() {
		route := unstructured.Unstructured{}
		route.SetAPIVersion(api)
		route.SetKind("HTTPRoute")
		route.SetNamespace("default")
		route.SetName(name)
		err := f.cli.Delete(ctx, &route)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return route, hostname
}

func (f *framework) CreateTCPRouteA2(ctx context.Context, t *testing.T, gw *gatewayv1.Gateway, svc *corev1.Service, o ...options.Object) *gatewayv1alpha2.TCPRoute {
	route := f.CreateTCPRoute(ctx, t, gatewayv1alpha2.GroupVersion.Version, gw, svc, o...)
	return route.(*gatewayv1alpha2.TCPRoute)
}

func (f *framework) CreateTCPRoute(ctx context.Context, t *testing.T, version string, gw *gatewayv1.Gateway, svc *corev1.Service, o ...options.Object) client.Object {
	opt := options.ParseObjectOptions(o...)
	api := v1.GroupVersion{Group: gatewayv1.GroupName, Version: version}.String()
	data := fmt.Sprintf(`
apiVersion: %s
kind: TCPRoute
metadata:
  name: ""
  namespace: default
spec:
  parentRefs:
  - name: ""
  hostnames:
  - ""
  rules:
  - backendRefs:
    - name: ""
      port: 0
`, api)
	name := RandomName("tcproute")

	route := f.CreateObject(t, data)
	route.SetName(name)
	spec := reflect.ValueOf(route).Elem().FieldByName("Spec").Addr().Interface().(*gatewayv1alpha2.TCPRouteSpec)
	spec.ParentRefs[0].Name = gatewayv1.ObjectName(gw.Name)
	spec.Rules[0].BackendRefs[0].Name = gatewayv1.ObjectName(svc.Name)
	spec.Rules[0].BackendRefs[0].Port = (*gatewayv1.PortNumber)(&svc.Spec.Ports[0].Port)
	opt.Apply(route)

	t.Logf("creating TCPRoute %s/%s\n", route.GetNamespace(), route.GetName())

	err := f.cli.Create(ctx, route)
	require.NoError(t, err)

	t.Cleanup(func() {
		route := unstructured.Unstructured{}
		route.SetAPIVersion(api)
		route.SetKind("TCPRoute")
		route.SetNamespace("default")
		route.SetName(name)
		err := f.cli.Delete(ctx, &route)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return route
}

func (f *framework) CreateObject(t *testing.T, data string) client.Object {
	obj, _, err := serializer.NewCodecFactory(f.scheme).UniversalDeserializer().Decode([]byte(data), nil, nil)
	require.NoError(t, err)
	return obj.(client.Object)
}

type EchoResponse struct {
	Parsed     bool
	ServerName string
	Port       int
	Path       string
	ReqHeaders map[string]string
}

func buildEchoResponse(t *testing.T, body string) EchoResponse {
	if !strings.HasPrefix(body, "echoserver: ") {
		// instantiate all pointers, so we can use assert on tests
		// without leading to nil pointer deref.
		return EchoResponse{ReqHeaders: make(map[string]string)}
	}
	lines := strings.Split(body, "\n")
	header := echoHeaderRegex.FindStringSubmatch(lines[0])
	port, err := strconv.Atoi(header[2])
	require.NoError(t, err)
	res := EchoResponse{
		Parsed:     true,
		ServerName: header[1],
		Port:       port,
		Path:       header[3],
		ReqHeaders: make(map[string]string),
	}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		eq := strings.Index(l, "=")
		k := strings.ToLower(l[:eq])
		v := l[eq+1:]
		res.ReqHeaders[k] = v
	}
	return res
}

// Example: echoserver: service-name 8080 /app
var echoHeaderRegex = regexp.MustCompile(`^echoserver: ([a-z0-9-]+) ([0-9]+) ([a-z0-9/]+)$`)

func (*framework) CreateHTTPServer(ctx context.Context, t *testing.T, serverName string) int32 {
	serverPort := RandomPort()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		content := fmt.Sprintf("echoserver: %s %d %s\n", serverName, serverPort, r.URL.Path)
		for name, values := range r.Header {
			for _, value := range values {
				content += fmt.Sprintf("%s=%s\n", name, value)
			}
		}
		_, err := w.Write([]byte(content))
		assert.NoError(t, err)
	})

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", serverPort),
		Handler: mux,
	}
	t.Logf("creating http server at :%d\n", serverPort)

	done := make(chan bool)
	go func() {
		err := server.ListenAndServe()
		assert.ErrorIs(t, err, http.ErrServerClosed)
		done <- true
	}()

	t.Cleanup(func() {
		err := server.Shutdown(context.Background())
		assert.NoError(t, err)
		<-done
	})
	return serverPort
}

func (*framework) CreateTCPServer(ctx context.Context, t *testing.T) int32 {
	serverPort := RandomPort()
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", serverPort))
	require.NoError(t, err)
	go func() {
		for {
			conn, _ := listen.Accept()
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			_, _ = conn.Write(buf[:n])
			_ = conn.Close()
		}
	}()
	return serverPort
}

func RandomName(prefix string) string {
	return fmt.Sprintf("%s-%08x", prefix, rand.Intn(1e8))
}

var currentPortOffset atomic.Int32

func RandomPort() int32 {
	return 16384 + currentPortOffset.Add(1)
}
