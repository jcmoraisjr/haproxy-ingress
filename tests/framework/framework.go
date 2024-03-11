package framework

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	ctrlconfig "github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/launch"
	"github.com/jcmoraisjr/haproxy-ingress/tests/framework/options"
)

const (
	PublishAddress = "10.0.1.1"
)

func NewFramework(ctx context.Context, t *testing.T) *framework {
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

	config := startApiserver(t)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1alpha2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1beta1.AddToScheme(scheme))
	codec := serializer.NewCodecFactory(scheme)

	cli, err := client.NewWithWatch(config, client.Options{Scheme: scheme})
	require.NoError(t, err)

	return &framework{
		scheme: scheme,
		codec:  codec,
		config: config,
		cli:    cli,
	}
}

type framework struct {
	scheme *runtime.Scheme
	codec  serializer.CodecFactory
	config *rest.Config
	cli    client.WithWatch
}

// HAProxy version 3.0-dev4-dec0175 2024/02/23 - https://haproxy.org/
// HAProxy version 2.9.5-260dbb8 2024/02/15 - https://haproxy.org/
// HAProxy version 2.8.6-f6bd011 2024/02/15 - https://haproxy.org/
// HAProxy version 2.6.16-c6a7346 2023/12/13 - https://haproxy.org/
// HAProxy version 2.4.25-6cfe787 2023/12/14 - https://haproxy.org/
// HA-Proxy version 2.2.32-4081d5a 2023/12/19 - https://haproxy.org/
// HA-Proxy version 2.0.34-868040b 2023/12/19 - https://haproxy.org/
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

func startApiserver(t *testing.T) *rest.Config {
	t.Log("starting apiserver")

	e := envtest.Environment{
		// run `make setup-envtest` to download envtest binaries.
		BinaryAssetsDirectory: filepath.Join("bin", "k8s", fmt.Sprintf("1.29.1-%s-%s", goruntime.GOOS, goruntime.GOARCH)),
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
		"http-port":  "18080",
		"https-port": "18443",
	}
	err = f.cli.Create(ctx, &global)
	require.NoError(t, err)

	opt := ctrlconfig.NewOptions()
	opt.MasterWorker = true
	opt.LocalFSPrefix = "/tmp/haproxy-ingress"
	opt.PublishAddress = PublishAddress
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
}

type Response struct {
	HTTPResponse *http.Response
	Body         string
	EchoResponse bool
	ReqHeaders   map[string]string
}

func (f *framework) Request(ctx context.Context, t *testing.T, method, host, path string, o ...options.Request) Response {
	t.Logf("request method=%s host=%s path=%s\n", method, host, path)
	opt := options.ParseRequestOptions(o...)

	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:18080", nil)
	require.NoError(t, err)
	req.Host = host
	req.URL.Path = path
	cli := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var res *http.Response
	if opt.ExpectResponseCode > 0 {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			res, err = cli.Do(req)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, opt.ExpectResponseCode, res.StatusCode)
		}, 5*time.Second, time.Second)
	} else {
		res, err = cli.Do(req)
		require.NoError(t, err)
	}
	require.NotNil(t, res, "request closure reassigned the response")
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	reqHeaders := make(map[string]string)
	t.Logf("response body:\n%s\n", body)
	strbody := string(body)
	echoResponse := strings.HasPrefix(strbody, "echoserver:\n")
	if echoResponse {
		for _, l := range strings.Split(strbody, "\n")[1:] {
			if l == "" {
				continue
			}
			eq := strings.Index(l, "=")
			k := strings.ToLower(l[:eq])
			v := l[eq+1:]
			reqHeaders[k] = v
		}
	}
	return Response{
		HTTPResponse: res,
		Body:         strbody,
		EchoResponse: echoResponse,
		ReqHeaders:   reqHeaders,
	}
}

func (f *framework) Client() client.WithWatch {
	return f.cli
}

func (f *framework) CreateService(ctx context.Context, t *testing.T, serverPort int32, o ...options.Object) *corev1.Service {
	opt := options.ParseObjectOptions(o...)
	data := `
apiVersion: v1
Kind: Service
metadata:
  name: ""
  namespace: default
spec:
  ports:
  - port: 8080
    targetPort: 0
`
	ep := f.CreateEndpoints(ctx, t, serverPort)
	name := ep.Name

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

func (f *framework) CreateEndpoints(ctx context.Context, t *testing.T, serverPort int32) *corev1.Endpoints {
	data := `
apiVersion: v1
Kind: Endpoints
metadata:
  annotations:
    haproxy-ingress.github.io/ip-override: 127.0.0.1
  name: ""
  namespace: default
subsets:
- addresses:
  - ip: ::ffff
  ports:
  - port: 0
`
	name := randomName("svc")

	ep := f.CreateObject(t, data).(*corev1.Endpoints)
	ep.Name = name
	ep.Subsets[0].Ports[0].Port = serverPort

	t.Logf("creating endpoints %s/%s\n", ep.Namespace, ep.Name)

	err := f.cli.Create(ctx, ep)
	require.NoError(t, err)

	t.Cleanup(func() {
		ep := corev1.Endpoints{}
		ep.Namespace = "default"
		ep.Name = name
		err := f.cli.Delete(ctx, &ep)
		assert.NoError(t, client.IgnoreNotFound(err))
	})
	return ep
}

func (f *framework) Host(ing *networking.Ingress, ruleId ...int) string {
	var rule int
	if len(ruleId) > 0 {
		rule = ruleId[0]
	}
	if rules := ing.Spec.Rules; len(rules) >= rule {
		return rules[rule].Host
	}
	return ""
}

func (f *framework) CreateIngress(ctx context.Context, t *testing.T, svc *corev1.Service, o ...options.Object) *networking.Ingress {
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
              number: 8080
`
	name := randomName("ing")
	hostname := name + ".local"

	ing := f.CreateObject(t, data).(*networking.Ingress)
	ing.Name = name
	ing.Spec.Rules[0].Host = hostname
	ing.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name = svc.Name
	opt.Apply(ing)
	if opt.IngressOpt.DefaultTLS {
		ing.Spec.TLS = []networking.IngressTLS{{Hosts: []string{hostname}}}
	}

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
	return ing
}

func (f *framework) CreateObject(t *testing.T, data string) runtime.Object {
	obj, _, err := f.codec.UniversalDeserializer().Decode([]byte(data), nil, nil)
	require.NoError(t, err)
	return obj
}

func (f *framework) CreateHTTPServer(ctx context.Context, t *testing.T) int32 {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		content := "echoserver:\n"
		for name, values := range r.Header {
			for _, value := range values {
				content += fmt.Sprintf("%s=%s\n", name, value)
			}
		}
		_, err := w.Write([]byte(content))
		assert.NoError(t, err)
	})

	serverPort := int32(32768 + rand.Intn(32767))
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", serverPort),
		Handler: mux,
	}
	t.Logf("creating http server at :%d\n", serverPort)

	done := make(chan bool)
	go func() {
		_ = server.ListenAndServe()
		done <- true
	}()

	t.Cleanup(func() {
		err := server.Shutdown(context.Background())
		assert.NoError(t, err)
		<-done
	})
	return serverPort
}

func randomName(prefix string) string {
	return fmt.Sprintf("%s-%08d", prefix, rand.Intn(1e8))
}
