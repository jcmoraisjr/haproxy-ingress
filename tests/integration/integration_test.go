package integration_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/tests/framework"
	"github.com/jcmoraisjr/haproxy-ingress/tests/framework/options"
)

func TestIntegrationIngress(t *testing.T) {
	ctx := context.Background()

	f := framework.NewFramework(ctx, t)
	httpServerPort := f.CreateHTTPServer(ctx, t, "default")

	lbingpre1 := "127.0.0.1"
	require.NotEqual(t, framework.PublishAddress, lbingpre1)

	svcpre1 := f.CreateService(ctx, t, httpServerPort)
	ingpre1, _ := f.CreateIngress(ctx, t, svcpre1)
	ingpre1.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: lbingpre1}}
	err := f.Client().Status().Update(ctx, ingpre1)
	require.NoError(t, err)

	caValid, cakeyValid := framework.CreateCA(t, framework.CertificateIssuerCN)
	crtValid, keyValid := framework.CreateCertificate(t, caValid, cakeyValid, framework.CertificateClientCN)
	secretCA := f.CreateSecret(ctx, t, map[string][]byte{"ca.crt": caValid})

	caFake, cakeyFake := framework.CreateCA(t, framework.CertificateIssuerCN)
	crtFake, keyFake := framework.CreateCertificate(t, caFake, cakeyFake, framework.CertificateClientCN)

	commonReqHeaders := map[string]string{
		"accept-encoding":   "gzip",
		"user-agent":        "Go-http-client/1.1",
		"x-forwarded-for":   "127.0.0.1",
		"x-forwarded-proto": "https",
		"x-real-ip":         "127.0.0.1",
	}

	f.StartController(ctx, t)

	t.Run("hello world", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse.Parsed)
		assert.Equal(t, "http", res.EchoResponse.ReqHeaders["x-forwarded-proto"])
	})

	t.Run("should not redirect to https", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.BackSSLRedirect, "false"),
		)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse.Parsed)
	})

	t.Run("should redirect to https", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.BackSSLRedirect, "true"),
		)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusFound))
		assert.False(t, res.EchoResponse.Parsed)
		assert.Equal(t, fmt.Sprintf("https://%s/", hostname), res.HTTPResponse.Header.Get("location"))
	})

	t.Run("should send default http headers on http request", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse.Parsed)
		reqHeaders := framework.AppendStringMap(commonReqHeaders, map[string]string{
			"x-forwarded-proto": "http",
		})
		assert.Equal(t, reqHeaders, res.EchoResponse.ReqHeaders)
	})

	t.Run("should send default http headers on https request", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc, options.DefaultTLS())
		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.ExpectResponseCode(http.StatusOK),
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
		)
		assert.True(t, res.EchoResponse.Parsed)
		assert.Equal(t, commonReqHeaders, res.EchoResponse.ReqHeaders)
	})

	t.Run("should redirect to https before app-root", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.BackSSLRedirect, "true"),
			options.AddConfigKeyAnnotation(ingtypes.HostAppRoot, "/app"),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.ExpectResponseCode(http.StatusFound),
		)
		assert.False(t, res.EchoResponse.Parsed)
		assert.Equal(t, fmt.Sprintf("https://%s/", hostname), res.HTTPResponse.Header.Get("location"))

		res = f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
		)
		assert.False(t, res.EchoResponse.Parsed)
		assert.Equal(t, "/app", res.HTTPResponse.Header.Get("location"))
	})

	t.Run("should fail TLS connection on default fake server crt and valid local ca", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.SNI("localhost"), // fake certificate has `localhost` in certificates's SAN
			options.ExpectX509Error("x509: certificate signed by unknown authority"),
		)
		assert.False(t, res.EchoResponse.Parsed)
	})

	t.Run("should fail TLS connection on custom server crt with invalid dates", func(t *testing.T) {
		t.Parallel()
		hostname := framework.RandomHostName()
		ca, cakey := framework.CreateCA(t, "custom CA")
		crt, key := framework.CreateCertificate(t, ca, cakey, hostname,
			options.DNS(hostname),
			options.InvalidDates(),
		)
		secret := f.CreateSecretTLS(ctx, t, crt, key)

		svc := f.CreateService(ctx, t, httpServerPort)
		_, _ = f.CreateIngress(ctx, t, svc,
			options.CustomHostName(hostname),
			options.CustomTLS(secret.Name),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.ClientCA(ca),
			options.SNI(hostname),
			options.ExpectX509Error("x509: certificate has expired or is not yet valid"),
		)
		assert.False(t, res.EchoResponse.Parsed)
	})

	t.Run("should succeed TLS connection on custom server crt and valid local ca", func(t *testing.T) {
		t.Parallel()
		hostname := framework.RandomHostName()
		ca, cakey := framework.CreateCA(t, "custom CA")
		crt, key := framework.CreateCertificate(t, ca, cakey, hostname,
			options.DNS(hostname),
		)
		secret := f.CreateSecretTLS(ctx, t, crt, key)

		svc := f.CreateService(ctx, t, httpServerPort)
		_, _ = f.CreateIngress(ctx, t, svc,
			options.CustomHostName(hostname),
			options.CustomTLS(secret.Name),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.ClientCA(ca),
			options.SNI(hostname),
			options.ExpectResponseCode(200),
		)
		assert.True(t, res.EchoResponse.Parsed)
		assert.Equal(t, commonReqHeaders, res.EchoResponse.ReqHeaders)
	})

	t.Run("should deny 496 mTLS with no client crt", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname),
			options.ExpectResponseCode(496),
		)
		assert.False(t, res.EchoResponse.Parsed)
	})

	t.Run("should deny 495 mTLS with invalid client crt", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname),
			options.ClientCertificateKeyPEM(crtFake, keyFake),
			options.ExpectResponseCode(495),
		)
		assert.False(t, res.EchoResponse.Parsed)
	})

	t.Run("should deny 495 mTLS with misconfigured ingress", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, "do not exist"),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname),
			options.ClientCertificateKeyPEM(crtValid, keyValid),
			options.ExpectResponseCode(495),
		)
		assert.False(t, res.EchoResponse.Parsed)
	})

	t.Run("should deny 421 mTLS with distinct host", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name),
		)

		res := f.Request(ctx, t, http.MethodGet, "trying-bypass.local", "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname),
			options.ClientCertificateKeyPEM(crtValid, keyValid),
			options.ExpectResponseCode(421),
		)
		assert.False(t, res.EchoResponse.Parsed)
	})

	t.Run("should allow mTLS without an optional crt", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSVerifyClient, "optional"),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname),
			options.ExpectResponseCode(200),
		)
		assert.True(t, res.EchoResponse.Parsed)
		reqHeaders := framework.AppendStringMap(commonReqHeaders, map[string]string{
			"x-ssl-client-cn":   "",
			"x-ssl-client-dn":   "",
			"x-ssl-client-sha1": "",
		})
		assert.Equal(t, reqHeaders, res.EchoResponse.ReqHeaders)
	})

	t.Run("should allow mTLS with valid crt", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultTLS(),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.HTTPSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname),
			options.ClientCertificateKeyPEM(crtValid, keyValid),
			options.ExpectResponseCode(200),
		)
		assert.True(t, res.EchoResponse.Parsed)
		crtder, _ := pem.Decode(crtValid)
		sha1sum := sha1.Sum(crtder.Bytes)
		reqHeaders := framework.AppendStringMap(commonReqHeaders, map[string]string{
			"x-ssl-client-cn":   framework.CertificateClientCN,
			"x-ssl-client-dn":   "/CN=" + framework.CertificateClientCN,
			"x-ssl-client-sha1": strings.ToUpper(hex.EncodeToString(sha1sum[:])),
		})
		assert.Equal(t, reqHeaders, res.EchoResponse.ReqHeaders)
	})

	t.Run("should take leader", func(t *testing.T) {
		t.Parallel()
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			events := corev1.EventList{}
			err := f.Client().List(ctx, &events)
			if !assert.NoError(collect, err) {
				return
			}
			for _, event := range events.Items {
				lease := event.InvolvedObject
				t.Logf("lease: %+v message: %s", lease, event.Message)
				if lease.Kind == "Lease" && lease.Namespace == "default" && lease.Name == "class-haproxy.haproxy-ingress.github.io" {
					assert.Regexp(collect, `became leader$`, event.Message)
					return
				}
			}
			assert.Fail(collect, "lease event not found")
		}, 10*time.Second, time.Second)
	})

	expectedIngressStatus := networkingv1.IngressStatus{
		LoadBalancer: networkingv1.IngressLoadBalancerStatus{
			Ingress: []networkingv1.IngressLoadBalancerIngress{
				{IP: framework.PublishAddress, Hostname: framework.PublishHostname},
			},
		},
	}

	t.Run("should update ingress status", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)

		ing1, _ := f.CreateIngress(ctx, t, svc)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			err := f.Client().Get(ctx, client.ObjectKeyFromObject(ing1), ing1)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, expectedIngressStatus, ing1.Status)
		}, 5*time.Second, time.Second)

		// testing two consecutive syncs
		ing2, _ := f.CreateIngress(ctx, t, svc)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			err := f.Client().Get(ctx, client.ObjectKeyFromObject(ing2), ing2)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, expectedIngressStatus, ing2.Status)
		}, 5*time.Second, time.Second)
	})

	t.Run("should sync ingress status from publish service", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		ing, _ := f.CreateIngress(ctx, t, svc)

		// check initial status
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			err := f.Client().Get(ctx, client.ObjectKeyFromObject(ing), ing)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, expectedIngressStatus, ing.Status)
		}, 5*time.Second, time.Second)

		tmpChangingIP := "127.0.0.1"
		require.NotEqual(t, framework.PublishAddress, tmpChangingIP)

		// read and update publish svc status
		svcpub := corev1.Service{}
		svcpub.Namespace, svcpub.Name, _ = cache.SplitMetaNamespaceKey(framework.PublishSvcName)
		err = f.Client().Get(ctx, client.ObjectKeyFromObject(&svcpub), &svcpub)
		require.NoError(t, err)
		svcpublb := svcpub.Status.LoadBalancer.Ingress
		svcpub.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: tmpChangingIP}}
		err = f.Client().Status().Update(ctx, &svcpub)
		require.NoError(t, err)

		// check changed svc status
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			err := f.Client().Get(ctx, client.ObjectKeyFromObject(ing), ing)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, networkingv1.IngressStatus{
				LoadBalancer: networkingv1.IngressLoadBalancerStatus{
					Ingress: []networkingv1.IngressLoadBalancerIngress{
						{IP: tmpChangingIP},
					},
				},
			}, ing.Status)
		}, 5*time.Second, time.Second)

		// recover initial svc status
		svcpub.Status.LoadBalancer.Ingress = svcpublb
		err = f.Client().Status().Update(ctx, &svcpub)
		require.NoError(t, err)

		// check recovered svc status
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			err := f.Client().Get(ctx, client.ObjectKeyFromObject(ing), ing)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, expectedIngressStatus, ing.Status)
		}, 5*time.Second, time.Second)
	})

	t.Run("should override old status", func(t *testing.T) {
		t.Parallel()
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			err := f.Client().Get(ctx, client.ObjectKeyFromObject(ingpre1), ingpre1)
			if !assert.NoError(collect, err) {
				return
			}
			assert.Equal(collect, expectedIngressStatus, ingpre1.Status)
		}, 5*time.Second, time.Second)
	})

	// should update status on class update

	// should limit read and update when watching namespace

	// should sync status on new leader
}

func TestIntegrationGateway(t *testing.T) {
	ctx := context.Background()

	t.Run("v1alpha2", func(t *testing.T) {
		f := framework.NewFramework(ctx, t, options.CRDs("gateway-api-v040-v1alpha2"))
		f.StartController(ctx, t)
		httpServerPort := f.CreateHTTPServer(ctx, t, "gw-v1alpha2")
		gc := f.CreateGatewayClassA2(ctx, t)

		t.Run("hello world", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayA2(ctx, t, gc)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, hostname := f.CreateHTTPRouteA2(ctx, t, gw, svc)
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			assert.True(t, res.EchoResponse.Parsed)
			assert.Equal(t, "http", res.EchoResponse.ReqHeaders["x-forwarded-proto"])
		})
	})

	t.Run("v1beta1", func(t *testing.T) {
		f := framework.NewFramework(ctx, t, options.CRDs("gateway-api-v050-v1beta1-experimental"))
		f.StartController(ctx, t)
		httpServerPort := f.CreateHTTPServer(ctx, t, "gw-v1beta1")
		gc := f.CreateGatewayClassB1(ctx, t)

		t.Run("hello world", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayB1(ctx, t, gc)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, hostname := f.CreateHTTPRouteB1(ctx, t, gw, svc)
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			assert.True(t, res.EchoResponse.Parsed)
			assert.Equal(t, "http", res.EchoResponse.ReqHeaders["x-forwarded-proto"])
		})
	})

	t.Run("v1", func(t *testing.T) {
		f := framework.NewFramework(ctx, t, options.CRDs("gateway-api-v100-v1-experimental"))
		f.StartController(ctx, t)
		httpServerPort := f.CreateHTTPServer(ctx, t, "gw-v1")
		tcpServerPort := f.CreateTCPServer(ctx, t)
		gc := f.CreateGatewayClassV1(ctx, t)

		t.Run("hello world", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayV1(ctx, t, gc)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, hostname := f.CreateHTTPRouteV1(ctx, t, gw, svc)
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			assert.True(t, res.EchoResponse.Parsed)
			assert.Equal(t, "http", res.EchoResponse.ReqHeaders["x-forwarded-proto"])
		})

		t.Run("expose TCPRoute", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayV1(ctx, t, gc, options.Listener("pgserver", "TCP", framework.TestPortTCPService))
			svc := f.CreateService(ctx, t, tcpServerPort)
			_ = f.CreateTCPRouteA2(ctx, t, gw, svc)
			res1 := f.TCPRequest(ctx, t, framework.TestPortTCPService, "ping")
			assert.Equal(t, "ping", res1)
			res2 := f.TCPRequest(ctx, t, framework.TestPortTCPService, "reply")
			assert.Equal(t, "reply", res2)
		})
	})
}
