package integration_test

import (
	"context"
	"fmt"
	"net/http"
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
	httpServerPort := f.CreateHTTPServer(ctx, t)

	lbingpre1 := "127.0.0.1"
	require.NotEqual(t, framework.PublishAddress, lbingpre1)

	svcpre1 := f.CreateService(ctx, t, httpServerPort)
	ingpre1, _ := f.CreateIngress(ctx, t, svcpre1)
	ingpre1.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: lbingpre1}}
	err := f.Client().Status().Update(ctx, ingpre1)
	require.NoError(t, err)

	f.StartController(ctx, t)

	t.Run("hello world", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse)
		assert.Equal(t, "http", res.ReqHeaders["x-forwarded-proto"])
	})

	t.Run("should not redirect to https", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultHostTLS(),
			options.AddConfigKeyAnnotations(map[string]string{ingtypes.BackSSLRedirect: "false"}),
		)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
		assert.True(t, res.EchoResponse)
	})

	t.Run("should redirect to https", func(t *testing.T) {
		t.Parallel()
		svc := f.CreateService(ctx, t, httpServerPort)
		_, hostname := f.CreateIngress(ctx, t, svc,
			options.DefaultHostTLS(),
			options.AddConfigKeyAnnotations(map[string]string{ingtypes.BackSSLRedirect: "true"}),
		)
		res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusFound))
		assert.False(t, res.EchoResponse)
		assert.Equal(t, fmt.Sprintf("https://%s/", hostname), res.HTTPResponse.Header.Get("location"))
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
		httpServerPort := f.CreateHTTPServer(ctx, t)
		gc := f.CreateGatewayClassA2(ctx, t)

		t.Run("hello world", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayA2(ctx, t, gc)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, hostname := f.CreateHTTPRouteA2(ctx, t, gw, svc)
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			assert.True(t, res.EchoResponse)
			assert.Equal(t, "http", res.ReqHeaders["x-forwarded-proto"])
		})
	})

	t.Run("v1beta1", func(t *testing.T) {
		f := framework.NewFramework(ctx, t, options.CRDs("gateway-api-v050-v1beta1-experimental"))
		f.StartController(ctx, t)
		httpServerPort := f.CreateHTTPServer(ctx, t)
		gc := f.CreateGatewayClassB1(ctx, t)

		t.Run("hello world", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayB1(ctx, t, gc)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, hostname := f.CreateHTTPRouteB1(ctx, t, gw, svc)
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			assert.True(t, res.EchoResponse)
			assert.Equal(t, "http", res.ReqHeaders["x-forwarded-proto"])
		})
	})

	t.Run("v1", func(t *testing.T) {
		f := framework.NewFramework(ctx, t, options.CRDs("gateway-api-v100-v1-experimental"))
		f.StartController(ctx, t)
		httpServerPort := f.CreateHTTPServer(ctx, t)
		tcpServerPort := f.CreateTCPServer(ctx, t)
		gc := f.CreateGatewayClassV1(ctx, t)

		t.Run("hello world", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayV1(ctx, t, gc)
			svc := f.CreateService(ctx, t, httpServerPort)
			_, hostname := f.CreateHTTPRouteV1(ctx, t, gw, svc)
			res := f.Request(ctx, t, http.MethodGet, hostname, "/", options.ExpectResponseCode(http.StatusOK))
			assert.True(t, res.EchoResponse)
			assert.Equal(t, "http", res.ReqHeaders["x-forwarded-proto"])
		})

		t.Run("expose TCPRoute", func(t *testing.T) {
			t.Parallel()
			gw := f.CreateGatewayV1(ctx, t, gc, options.Listener("pgserver", "TCP", 15432))
			svc := f.CreateService(ctx, t, tcpServerPort)
			_ = f.CreateTCPRouteA2(ctx, t, gw, svc)
			res1 := f.TCPRequest(ctx, t, 15432, "ping")
			assert.Equal(t, "ping", res1)
			res2 := f.TCPRequest(ctx, t, 15432, "reply")
			assert.Equal(t, "reply", res2)
		})
	})
}
