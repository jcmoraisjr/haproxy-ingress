package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

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
}
