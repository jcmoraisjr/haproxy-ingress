package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/tests/framework"
	"github.com/jcmoraisjr/haproxy-ingress/tests/framework/options"
)

func TestIntegration(t *testing.T) {
	ctx := context.Background()

	f := framework.NewFramework(ctx, t)
	httpPort := f.CreateHTTPServer(ctx, t)

	t.Run("hello world", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpPort)
		ing := f.CreateIngress(ctx, t, svc)
		res := f.Request(ctx, t, http.MethodGet, f.Host(ing), "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse)
		assert.Equal(t, "http", res.ReqHeaders["x-forwarded-proto"])
	})

	t.Run("should not redirect to https", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpPort)
		ing := f.CreateIngress(ctx, t, svc,
			options.DefaultHostTLS(),
			options.AddConfigKeyAnnotations(map[string]string{ingtypes.BackSSLRedirect: "false"}),
		)
		res := f.Request(ctx, t, http.MethodGet, f.Host(ing), "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse)
	})

	t.Run("should redirect to https", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpPort)
		ing := f.CreateIngress(ctx, t, svc,
			options.DefaultHostTLS(),
			options.AddConfigKeyAnnotations(map[string]string{ingtypes.BackSSLRedirect: "true"}),
		)
		res := f.Request(ctx, t, http.MethodGet, f.Host(ing), "/", options.ExpectResponseCode(http.StatusFound))
		assert.False(t, res.EchoResponse)
		assert.Equal(t, fmt.Sprintf("https://%s/", f.Host(ing)), res.HTTPResponse.Header.Get("location"))
	})
}
