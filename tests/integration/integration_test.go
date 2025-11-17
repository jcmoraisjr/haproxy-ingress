package integration_test

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	caValidKeyPair, err := tls.X509KeyPair(caValid, cakeyValid)
	require.NoError(t, err)
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

	t.Run("bare", func(t *testing.T) {
		t.Parallel()
		res := f.Request(ctx, t, http.MethodGet, "", "/healthz",
			options.RequestPort(framework.TestPortHealthz),
			options.ExpectResponseCode(http.StatusOK),
		)
		assert.Contains(t, res.Body, "Service ready")
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
			options.ExpectError("x509: certificate signed by unknown authority"),
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
			options.ExpectError("x509: certificate has expired or is not yet valid"),
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

	t.Run("should override lua and host based http response", func(t *testing.T) {
		t.Parallel()

		req := func(body string, o ...options.Object) {
			svc := f.CreateService(ctx, t, httpServerPort)
			o = append(o, options.DefaultTLS(), options.AddConfigKeyAnnotation(ingtypes.HostAuthTLSSecret, secretCA.Name))
			_, hostname := f.CreateIngress(ctx, t, svc, o...)
			_, _ = f.CreateIngress(ctx, t, svc, o...) // second ingress adds an `elseif`, using another part of the Lua template
			res := f.Request(ctx, t, http.MethodGet, hostname, "/",
				options.TLSRequest(),
				options.SNI(hostname),
				options.TLSSkipVerify(),
				options.ExpectResponseCode(496),
			)
			assert.False(t, res.EchoResponse.Parsed)
			assert.Equal(t, strings.TrimSpace(body), strings.TrimSpace(res.Body))
		}

		req(`
<html><body><h1>496 SSL Certificate Required</h1>
A client certificate must be provided.
</body></html>
`)
		req("here 496",
			options.AddConfigKeyAnnotation(ingtypes.HostHTTPResponse496, "content-type: text/plain\n\nhere 496"),
		)
	})

	t.Run("should override lua and backend based http response", func(t *testing.T) {
		t.Parallel()

		req := func(body string, o ...options.Object) {
			svc1 := f.CreateService(ctx, t, httpServerPort)
			svc2 := f.CreateService(ctx, t, httpServerPort) // second service adds an `elseif`, using another part of the Lua template
			o = append(o, options.AddConfigKeyAnnotation(ingtypes.BackProxyBodySize, "5"))
			_, hostname := f.CreateIngress(ctx, t, svc1, o...)
			_, _ = f.CreateIngress(ctx, t, svc2, o...)
			_ = f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			res := f.Request(ctx, t, http.MethodPost, hostname, "/",
				options.ExpectResponseCode(http.StatusRequestEntityTooLarge),
				options.Body("not-that-long"),
				options.CustomRequest(func(req *http.Request) {
					req.Header.Set("content-type", "text/plain")
				}),
			)
			assert.False(t, res.EchoResponse.Parsed)
			assert.Equal(t, strings.TrimSpace(body), strings.TrimSpace(res.Body))
		}

		req(`
<html><body><h1>413 Request Entity Too Large</h1>
The request is too large.
</body></html>
`)
		req("here 413",
			options.AddConfigKeyAnnotation(ingtypes.BackHTTPResponse413, "content-type: text/plain\n\nhere 413"),
		)
	})

	t.Run("should override haproxy based http response", func(t *testing.T) {
		t.Parallel()

		req := func(body string, o ...options.Object) {
			svc := f.CreateService(ctx, t, httpServerPort)
			o = append(o, options.AddConfigKeyAnnotation(ingtypes.BackAllowlistSourceRange, "1.1.1.1/32"))
			_, hostname := f.CreateIngress(ctx, t, svc, o...)
			res := f.Request(ctx, t, http.MethodPost, hostname, "/",
				options.ExpectResponseCode(http.StatusForbidden),
			)
			assert.False(t, res.EchoResponse.Parsed)
			assert.Equal(t, strings.TrimSpace(body), strings.TrimSpace(res.Body))
		}

		req(`
<html><body><h1>403 Forbidden</h1>
Request forbidden by administrative rules.
</body></html>
`)
		req("here 403",
			options.AddConfigKeyAnnotation(ingtypes.BackHTTPResponse403, "content-type: text/plain\n\nhere 403"),
		)
	})

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

	t.Run("should coexist regular and fronting-proxy http frontends", func(t *testing.T) {
		t.Parallel()

		port := framework.RandomPort()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hproxy := f.CreateIngress(ctx, t, svc)
		_, fproxy := f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.FrontFrontingProxyPort, strconv.Itoa(int(port))),
		)

		hres := f.Request(ctx, t, http.MethodGet, hproxy, "/",
			options.ExpectResponseCode(http.StatusOK),
		)
		assert.True(t, hres.EchoResponse.Parsed)

		fres := f.Request(ctx, t, http.MethodGet, fproxy, "/",
			options.RequestPort(port),
			options.CustomRequest(func(req *http.Request) {
				req.Header.Set("X-Forwarded-Proto", "https")
			}),
			options.ExpectResponseCode(http.StatusOK),
		)
		assert.True(t, fres.EchoResponse.Parsed)
	})

	t.Run("should handle proto header on fronting proxy", func(t *testing.T) {
		t.Parallel()

		const xfp = "X-Forwarded-Proto"
		const reqredir = "<redir>"
		testCases := []struct {
			useXFPHeader bool
			xfpContent   string
			expRecHeader string
		}{
			{useXFPHeader: false, xfpContent: "", expRecHeader: ""},
			{useXFPHeader: false, xfpContent: "http", expRecHeader: "http"},
			{useXFPHeader: false, xfpContent: "https", expRecHeader: "https"},
			{useXFPHeader: true, xfpContent: "", expRecHeader: reqredir},
			{useXFPHeader: true, xfpContent: "http", expRecHeader: reqredir},
			{useXFPHeader: true, xfpContent: "https", expRecHeader: "https"},
		}
		should := map[bool]string{false: "false", true: "true"}
		reqHeaders := map[string]string{
			"x-ssl-client-cn":   "localhost",
			"x-ssl-client-dn":   "/CN=localhost",
			"x-ssl-client-sha1": "abc123",
			"x-ssl-client-sha2": "abcd1234",
			"x-ssl-client-cert": "LS0tLS1CRUdJT...",
		}
		for _, test := range testCases {
			reqxfp := "missing"
			if test.xfpContent != "" {
				reqxfp = test.xfpContent
			}
			name := fmt.Sprintf("usexfp=%t reqxfp=%s", test.useXFPHeader, reqxfp)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				port := framework.RandomPort()
				svc := f.CreateService(ctx, t, httpServerPort)
				_, hostname := f.CreateIngress(ctx, t, svc,
					options.AddConfigKeyAnnotation(ingtypes.FrontFrontingProxyPort, strconv.Itoa(int(port))),
					options.AddConfigKeyAnnotation(ingtypes.FrontUseForwardedProto, should[test.useXFPHeader]),
				)
				expcode := http.StatusOK
				if test.expRecHeader == reqredir {
					expcode = http.StatusFound
				}
				res := f.Request(ctx, t, http.MethodGet, hostname, "/",
					options.RequestPort(port),
					options.CustomRequest(func(req *http.Request) {
						for h, v := range reqHeaders {
							req.Header.Set(h, v)
						}
						if test.xfpContent != "" {
							req.Header.Set(xfp, test.xfpContent)
						}
					}),
					options.ExpectResponseCode(expcode),
				)
				if test.expRecHeader != reqredir {
					assert.True(t, res.EchoResponse.Parsed)
					assert.Equal(t, test.expRecHeader, res.EchoResponse.ReqHeaders[strings.ToLower(xfp)])
					for header, value := range reqHeaders {
						assert.Equal(t, value, res.EchoResponse.ReqHeaders[header])
					}
				} else {
					assert.False(t, res.EchoResponse.Parsed)
				}
			})
		}
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

	t.Run("should configure TLS backend using crt files", func(t *testing.T) {
		t.Parallel()
		crtPem, keyPem := framework.CreateCertificate(t, caValid, cakeyValid, "localhost")
		crt, err := tls.X509KeyPair(crtPem, keyPem)
		require.NoError(t, err)
		port := f.CreateHTTPServer(ctx, t, "https1",
			options.ClientCACertificate(caValidKeyPair.Leaf),
			options.ServerCertificates([]tls.Certificate{crt}),
		)

		fileCA, err := os.CreateTemp(framework.LocalFSPrefix, "ca")
		require.NoError(t, err)
		err = os.WriteFile(fileCA.Name(), caValid, 0644)
		require.NoError(t, err)

		fileCrt, err := os.CreateTemp(framework.LocalFSPrefix, "crt")
		require.NoError(t, err)
		err = os.WriteFile(fileCrt.Name(), append(crtPem, keyPem...), 0644)
		require.NoError(t, err)

		svc := f.CreateService(ctx, t, port)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.AddConfigKeyAnnotation(ingtypes.BackBackendProtocol, "https"),
			options.AddConfigKeyAnnotation(ingtypes.BackSecureCrtSecret, "file://"+fileCrt.Name()),
			options.AddConfigKeyAnnotation(ingtypes.BackSecureVerifyCASecret, "file://"+fileCA.Name()),
		)

		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse.Parsed)
		assert.Equal(t, "https1", res.EchoResponse.ServerName)
	})

	t.Run("should ssl-passthrough", func(t *testing.T) {
		t.Parallel()

		serverCrtPem, serverKeyPem := framework.CreateCertificate(t, caValid, cakeyValid, "localhost")
		serverCrt, err := tls.X509KeyPair(serverCrtPem, serverKeyPem)
		require.NoError(t, err)
		httpsServer1Port := f.CreateHTTPServer(ctx, t, "https-server1",
			options.ServerCertificates([]tls.Certificate{serverCrt}),
		)
		httpsServer2Port := f.CreateHTTPServer(ctx, t, "https-server2",
			options.ServerCertificates([]tls.Certificate{serverCrt}),
		)

		svc1 := f.CreateService(ctx, t, httpsServer1Port)
		svc2 := f.CreateService(ctx, t, httpsServer2Port, options.CustomObject(func(o client.Object) {
			svc := o.(*corev1.Service)
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
				Name:       "port2",
				Port:       8080,
				TargetPort: intstr.IntOrString{IntVal: httpServerPort},
			})
		}))
		_, hostname1 := f.CreateIngress(ctx, t, svc1,
			options.AddConfigKeyAnnotation(ingtypes.HostSSLPassthrough, "True"),
		)

		_, hostname2 := f.CreateIngress(ctx, t, svc2,
			options.AddConfigKeyAnnotation(ingtypes.HostSSLPassthrough, "True"),
			options.AddConfigKeyAnnotation(ingtypes.HostSSLPassthroughHTTPPort, strconv.Itoa(int(httpServerPort))),
		)

		res1http := f.Request(ctx, t, http.MethodGet, hostname1, "/", options.ExpectResponseCode(http.StatusFound))
		assert.False(t, res1http.EchoResponse.Parsed)

		res1https := f.Request(ctx, t, http.MethodGet, hostname1, "/",
			options.TLSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname1),
			options.ExpectResponseCode(http.StatusOK),
		)
		assert.True(t, res1https.EchoResponse.Parsed)
		assert.Equal(t, "https-server1", res1https.EchoResponse.ServerName)

		res2http := f.Request(ctx, t, http.MethodGet, hostname2, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res2http.EchoResponse.Parsed)
		assert.Equal(t, "default", res2http.EchoResponse.ServerName)

		res2https := f.Request(ctx, t, http.MethodGet, hostname2, "/",
			options.TLSRequest(),
			options.TLSSkipVerify(),
			options.SNI(hostname2),
			options.ExpectResponseCode(http.StatusOK),
		)
		assert.True(t, res2https.EchoResponse.Parsed)
		assert.Equal(t, "https-server2", res2https.EchoResponse.ServerName)
	})

	t.Run("should distinguish same hostname and path from distinct frontends", func(t *testing.T) {
		t.Parallel()

		hostname := framework.RandomHostName()
		svc := f.CreateService(ctx, t, httpServerPort)
		ing := func(httpport, httpsport int32, location string) {
			_, _ = f.CreateIngress(ctx, t, svc,
				options.DefaultTLS(),
				options.CustomHostName(hostname),
				options.AddConfigKeyAnnotation(ingtypes.FrontHTTPPort, strconv.Itoa(int(httpport))),
				options.AddConfigKeyAnnotation(ingtypes.FrontHTTPSPort, strconv.Itoa(int(httpsport))),
				options.AddConfigKeyAnnotation(ingtypes.BackSSLRedirect, "false"),
				options.AddConfigKeyAnnotation(ingtypes.BackRewriteTarget, location),
			)
		}
		req := func(port int32, ssl bool, location string) {
			opt := []options.Request{
				options.RequestPort(port),
				options.ExpectResponseCode(http.StatusOK),
			}
			if ssl {
				opt = append(opt,
					options.TLSRequest(),
					options.TLSSkipVerify(),
				)
			}
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", opt...)
			assert.True(t, res.EchoResponse.Parsed)
			assert.Equal(t, location, res.EchoResponse.Path)
		}

		http1 := framework.RandomPort()
		https1 := framework.RandomPort()
		http2 := framework.RandomPort()
		https2 := framework.RandomPort()

		ing(http1, https1, "/api1")
		ing(http2, https2, "/api2")

		req(http1, false, "/api1/")
		req(https1, true, "/api1/")
		req(http2, false, "/api2/")
		req(https2, true, "/api2/")
	})

	// should match wildcard host

	// should match domain conflicting with wildcard host

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

		httpServerPort := f.CreateHTTPServer(ctx, t, "gw-v1-http")
		tcpServerPort := f.CreateTCPServer(ctx, t)
		gc := f.CreateGatewayClassV1(ctx, t)

		caValid, cakeyValid := framework.CreateCA(t, framework.CertificateIssuerCN)
		crtValidPem, keyValidPem := framework.CreateCertificate(t, caValid, cakeyValid, framework.CertificateClientCN)

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
			gw := f.CreateGatewayV1(ctx, t, gc, options.Listener("tcpserver", gatewayv1.TCPProtocolType, gatewayv1.PortNumber(listenerPort), nil))
			svc := f.CreateService(ctx, t, tcpServerPort)
			_ = f.CreateTCPRouteA2(ctx, t, gw, svc)
			res1 := f.TCPRequest(ctx, t, listenerPort, "ping")
			assert.Equal(t, "ping", res1)
			res2 := f.TCPRequest(ctx, t, listenerPort, "reply")
			assert.Equal(t, "reply", res2)
		})

		t.Run("expose TLSRoute", func(t *testing.T) {
			t.Parallel()
			secret := f.CreateSecretTLS(ctx, t, crtValidPem, keyValidPem)
			certs := []gatewayv1.SecretObjectReference{{Name: gatewayv1.ObjectName(secret.Name)}}
			listenerPort := framework.RandomPort()
			gw := f.CreateGatewayV1(ctx, t, gc, options.Listener("tlsserver", gatewayv1.TLSProtocolType, gatewayv1.PortNumber(listenerPort), certs))
			svc := f.CreateService(ctx, t, tcpServerPort)
			_ = f.CreateTLSRouteA2(ctx, t, gw, svc)
			res1 := f.TCPRequest(ctx, t, listenerPort, "ping", options.TLSRequest())
			assert.Equal(t, "ping", res1)
			res2 := f.TCPRequest(ctx, t, listenerPort, "reply", options.TLSRequest())
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
						Port:     framework.TestPortHTTPS,
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

		t.Run("should ssl-passthrough", func(t *testing.T) {
			t.Parallel()

			hostnamehttp := framework.RandomName("httproute") + ".local"
			hostnametls := framework.RandomName("tlsroute") + ".local"
			crtPem, keyPem := framework.CreateCertificate(t, caValid, cakeyValid, "localhost", options.DNS(hostnamehttp, hostnametls))
			crt, err := tls.X509KeyPair(crtPem, keyPem)
			require.NoError(t, err)
			httpsServerPort := f.CreateHTTPServer(ctx, t, "gw-v1-https",
				options.ServerCertificates([]tls.Certificate{crt}),
			)

			// configure ssl offload ...
			secret := f.CreateSecretTLS(ctx, t, crtPem, keyPem)
			certs := []gatewayv1.SecretObjectReference{{Name: gatewayv1.ObjectName(secret.Name)}}
			gwhttp := f.CreateGatewayV1(ctx, t, gc,
				options.Listener("gw-https", gatewayv1.HTTPSProtocolType, framework.TestPortHTTPS, certs),
			)
			svchttp := f.CreateService(ctx, t, httpServerPort)
			_, _ = f.CreateHTTPRouteV1(ctx, t, gwhttp, svchttp, options.CustomHostName(hostnamehttp))

			// ... along with ssl passthrough
			gwtls := f.CreateGatewayV1(ctx, t, gc,
				options.Listener("gw-passthrough", gatewayv1.TLSProtocolType, framework.TestPortHTTPS, nil),
			)
			svctls := f.CreateService(ctx, t, httpsServerPort)
			_ = f.CreateTLSRouteA2(ctx, t, gwtls, svctls,
				options.CustomHostName(hostnametls),
			)

			// TLS request on both hostnames
			req := func(hostname string) framework.Response {
				res := f.Request(ctx, t, http.MethodGet, hostname, "/",
					options.TLSRequest(),
					options.TLSVerify(true),
					options.ClientCA(caValid),
					options.SNI(hostname),
					options.ExpectResponseCode(http.StatusOK),
				)
				assert.True(t, res.EchoResponse.Parsed)
				return res
			}

			reshttp := req(hostnamehttp)
			assert.Equal(t, "https", reshttp.EchoResponse.ReqHeaders["x-forwarded-proto"])
			assert.Equal(t, "gw-v1-http", reshttp.EchoResponse.ServerName)

			restls := req(hostnametls)
			assert.Equal(t, "gw-v1-https", restls.EchoResponse.ServerName)
		})
	})
}
