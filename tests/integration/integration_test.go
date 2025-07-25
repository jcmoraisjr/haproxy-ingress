package integration_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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
			options.TLSRequest(),
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

	t.Run("should authorize request", func(t *testing.T) {
		t.Parallel()

		svc := f.CreateService(ctx, t, httpServerPort)
		authzPort := f.CreateAuthzServer(ctx, t,
			options.AuthzPasskey("x-token", "123"),
		)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.BackAuthURL, fmt.Sprintf("http://127.0.0.1:%d", authzPort)),
		)

		req := func(tokenValue string, authorized bool) framework.Response {
			expcode := http.StatusOK
			if !authorized {
				expcode = http.StatusUnauthorized
			}
			res := f.Request(ctx, t, http.MethodGet, hostname, "/",
				options.ExpectResponseCode(expcode),
				options.CustomRequest(func(req *http.Request) {
					req.Header.Set("x-token", tokenValue)
				}),
			)
			if authorized {
				for _, key := range []string{"date", "connection", "accept-encoding", "user-agent", "x-forwarded-for", "x-forwarded-proto", "x-real-ip"} {
					delete(res.EchoResponse.ReqHeaders, key)
				}
				assert.True(t, res.EchoResponse.Parsed)
			} else {
				assert.False(t, res.EchoResponse.Parsed)
			}
			return res
		}

		// invalid token, forbidden
		_ = req("132", false)

		// valid token, authorized
		res := req("123", true)
		assert.Equal(t, map[string]string{"x-token": "123", "x-authz": "Authorized"}, res.EchoResponse.ReqHeaders)
	})

	t.Run("should authorize websocket", func(t *testing.T) {
		t.Parallel()

		// configure ws backend, along with a service and ingress
		svc := f.CreateService(ctx, t, httpServerPort)
		authzPort := f.CreateAuthzServer(ctx, t,
			options.AuthzPasskey("x-token", "123"),
		)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.BackAuthURL, fmt.Sprintf("http://127.0.0.1:%d", authzPort)),
		)

		// wait controller to synchronize ingress configuration
		_ = f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusUnauthorized))

		// configure ws client, missing authz token
		header := make(http.Header)
		header.Set("Host", hostname)
		_, _, err := websocket.DefaultDialer.DialContext(ctx, fmt.Sprintf("ws://127.0.0.1:%d/echo", framework.TestPortHTTP), header)
		require.EqualError(t, err, "websocket: bad handshake")

		// configure ws client
		header.Set("x-token", "123")
		ws, _, err := websocket.DefaultDialer.DialContext(ctx, fmt.Sprintf("ws://127.0.0.1:%d/echo", framework.TestPortHTTP), header)
		require.NoError(t, err)
		defer ws.Close()

		// read from server
		var messages []string
		done := make(chan struct{})
		go func() {
			for {
				typ, msg, err := ws.ReadMessage()
				if err != nil {
					t.Logf("error reading message: %s", err.Error())
					close(done)
					break
				}
				t.Logf("client read socket / message (%d): %s", typ, msg)
				messages = append(messages, string(msg))
			}
		}()

		// write to server
		err = ws.WriteMessage(websocket.TextMessage, []byte("message 1"))
		require.NoError(t, err)
		err = ws.WriteMessage(websocket.TextMessage, []byte("message 2"))
		require.NoError(t, err)
		err = ws.WriteMessage(websocket.TextMessage, []byte("message 3"))
		require.NoError(t, err)
		err = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		require.NoError(t, err)

		// wait reader to consume all messages
		<-done

		expected := []string{
			"message 1",
			"message 2",
			"message 3",
		}
		assert.Equal(t, expected, messages)
	})

	// should match wildcard host
	// should match domain conflicting with wildcard host

	t.Run("should give priority on specific domains over wildcard", func(t *testing.T) {
		t.Parallel()
		hostname := framework.RandomHostName()
		hostSubdomain := "sub." + hostname
		hostWildcard := "*." + hostname

		backend1 := f.CreateHTTPServer(ctx, t, "backend1")
		svc1 := f.CreateService(ctx, t, backend1)
		backend2 := f.CreateHTTPServer(ctx, t, "backend2")
		svc2 := f.CreateService(ctx, t, backend2)

		_, _ = f.CreateIngress(ctx, t, svc1,
			options.DefaultTLS(),
			options.CustomHostName(hostSubdomain),
			options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name),
		)
		_, _ = f.CreateIngress(ctx, t, svc2,
			options.DefaultTLS(),
			options.CustomHostName(hostWildcard),
		)

		res := f.Request(ctx, t, http.MethodGet, hostSubdomain, "/",
			options.TLSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostSubdomain),
			options.ExpectResponseCode(496),
		)
		assert.False(t, res.EchoResponse.Parsed)

		res = f.Request(ctx, t, http.MethodGet, hostSubdomain, "/",
			options.TLSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostSubdomain),
			options.ClientCertificateKeyPEM(crtValid, keyValid),
			options.ExpectResponseCode(200),
		)
		assert.True(t, res.EchoResponse.Parsed)
		assert.Equal(t, "backend1", res.EchoResponse.ServerName)

		res = f.Request(ctx, t, http.MethodGet, "another."+hostname, "/",
			options.TLSRequest(),
			options.TLSSkipVerify(),
			options.ExpectResponseCode(200),
		)
		assert.True(t, res.EchoResponse.Parsed)
		assert.Equal(t, "backend2", res.EchoResponse.ServerName)

		res = f.Request(ctx, t, http.MethodGet, hostname, "/",
			options.TLSRequest(),
			options.TLSSkipVerify(),
			options.ExpectResponseCode(404),
		)
		assert.False(t, res.EchoResponse.Parsed)
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
		// t.Parallel() // non parallel, since it changes global config and could affect other tests
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

	t.Run("should connect on TCP service", func(t *testing.T) {
		t.Parallel()
		tcpServerPort := f.CreateTCPServer(ctx, t)
		tcpIngressPort := framework.RandomPort()
		svc := f.CreateService(ctx, t, tcpServerPort)
		_, _ = f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.TCPTCPServicePort, strconv.Itoa(int(tcpIngressPort))),
			options.CustomHostName(""),
		)
		res := f.TCPRequest(ctx, t, tcpIngressPort, "ping")
		assert.Equal(t, "ping", res)
	})

	t.Run("should connect on TLS TCP service", func(t *testing.T) {
		t.Parallel()
		tcpServerPort := f.CreateTCPServer(ctx, t)
		tcpIngressPort := framework.RandomPort()
		svc := f.CreateService(ctx, t, tcpServerPort)
		_, _ = f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.TCPTCPServicePort, strconv.Itoa(int(tcpIngressPort))),
			options.CustomHostName(""),
			options.DefaultTLS(),
		)
		res := f.TCPRequest(ctx, t, tcpIngressPort, "ping", options.TLSRequest())
		assert.Equal(t, "ping", res)
	})

	t.Run("should connect on hostnamed TLS TCP service", func(t *testing.T) {
		t.SkipNow() // TODO: TLS server
		t.Parallel()
		tcpServerPort := f.CreateTCPServer(ctx, t)
		tcpIngressPort := framework.RandomPort()
		svc := f.CreateService(ctx, t, tcpServerPort)
		_, _ = f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.TCPTCPServicePort, strconv.Itoa(int(tcpIngressPort))),
			options.DefaultTLS(),
		)
		res := f.TCPRequest(ctx, t, tcpIngressPort, "ping", options.TLSRequest())
		assert.Equal(t, "ping", res)
	})

	t.Run("should select the correct certificate on TLS TCP service", func(t *testing.T) {
		t.Parallel()
		tcpServerPort := f.CreateTCPServer(ctx, t)
		tcpIngressPort := framework.RandomPort()
		crt0, key0 := framework.CreateCertificate(t, caValid, cakeyValid, "tcphost0")
		crt1, key1 := framework.CreateCertificate(t, caValid, cakeyValid, "tcphost1")
		secret0 := f.CreateSecretTLS(ctx, t, crt0, key0)
		secret1 := f.CreateSecretTLS(ctx, t, crt1, key1)
		svc := f.CreateService(ctx, t, tcpServerPort)
		_, _ = f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.TCPTCPServicePort, strconv.Itoa(int(tcpIngressPort))),
			options.CustomObject(func(o client.Object) {
				ing := o.(*networkingv1.Ingress)
				rule0 := ing.Spec.Rules[0].DeepCopy()
				rule1 := rule0.DeepCopy()
				rule0.Host = "tcphost0.local"
				rule1.Host = "tcphost1.local"
				ing.Spec.Rules = []networkingv1.IngressRule{*rule0, *rule1}
				ing.Spec.TLS = []networkingv1.IngressTLS{{
					Hosts:      []string{"tcphost0.local"},
					SecretName: secret0.Name,
				}, {
					Hosts:      []string{"tcphost1.local"},
					SecretName: secret1.Name,
				}}
			}),
		)

		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			_ = framework.TLSConnection(collect, "localhost", tcpIngressPort)
		}, 5*time.Second, time.Second)

		conn := framework.TLSConnection(t, "localhost", tcpIngressPort)
		require.NotNil(t, conn)
		assert.Equal(t, "tcphost0", conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
		require.NoError(t, conn.Close())

		conn0 := framework.TLSConnection(t, "tcphost0.local", tcpIngressPort)
		require.NotNil(t, conn0)
		assert.Equal(t, "tcphost0", conn0.ConnectionState().PeerCertificates[0].Subject.CommonName)
		require.NoError(t, conn0.Close())

		conn1 := framework.TLSConnection(t, "tcphost1.local", tcpIngressPort)
		require.NotNil(t, conn1)
		assert.Equal(t, "tcphost1", conn1.ConnectionState().PeerCertificates[0].Subject.CommonName)
		require.NoError(t, conn1.Close())
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
			listenerPort := framework.RandomPort()
			gw := f.CreateGatewayV1(ctx, t, gc, options.Listener("tcpserver", "TCP", listenerPort))
			svc := f.CreateService(ctx, t, tcpServerPort)
			_ = f.CreateTCPRouteA2(ctx, t, gw, svc)
			res1 := f.TCPRequest(ctx, t, listenerPort, "ping")
			assert.Equal(t, "ping", res1)
			res2 := f.TCPRequest(ctx, t, listenerPort, "reply")
			assert.Equal(t, "reply", res2)
		})

		t.Run("multi certificates on listener", func(t *testing.T) {
			t.Parallel()
			caCrt, caKey := framework.CreateCA(t, framework.CertificateIssuerCN)
			crt1, key1 := framework.CreateCertificate(t, caCrt, caKey, "host1", options.DNS("host1.local"))
			crt2, key2 := framework.CreateCertificate(t, caCrt, caKey, "host2", options.DNS("host2.local"))
			secret1 := f.CreateSecretTLS(ctx, t, crt1, key1)
			secret2 := f.CreateSecretTLS(ctx, t, crt2, key2)
			gw := f.CreateGatewayV1(ctx, t, gc,
				options.CustomObject(func(o client.Object) {
					g := o.(*gatewayv1.Gateway)
					g.Spec.Listeners = []gatewayv1.Listener{{
						Name:     "l1",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						TLS: &gatewayv1.GatewayTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: gatewayv1.ObjectName(secret1.Name)},
								{Name: gatewayv1.ObjectName(secret2.Name)},
							},
						},
					}}
				}),
			)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, _ = f.CreateHTTPRouteV1(ctx, t, gw, svc,
				options.CustomObject(func(o client.Object) {
					h := o.(*gatewayv1.HTTPRoute)
					h.Spec.Hostnames = []gatewayv1.Hostname{
						"host1.local",
						"host2.local",
						"host3.local",
					}
				}),
			)
			hostsExpectedCN := map[string]string{
				"host1.local": "host1",
				"host2.local": "host2",
				"host3.local": "host1",
			}
			for h, expCN := range hostsExpectedCN {
				res := f.Request(ctx, t, http.MethodGet, h, "/",
					options.TLSRequest(),
					options.ClientCA(caCrt),
					options.SNI(h),
					options.TLSVerify(h != "host3.local"), // host3.local uses an invalid crt
					options.ExpectResponseCode(http.StatusOK),
				)
				assert.True(t, res.EchoResponse.Parsed)
				assert.Equal(t, "https", res.EchoResponse.ReqHeaders["x-forwarded-proto"])

				conn := framework.TLSConnection(t, h, framework.TestPortHTTPS)
				require.NotNil(t, conn)
				assert.Equal(t, expCN, conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
				require.NoError(t, conn.Close())
			}
		})
	})
}
