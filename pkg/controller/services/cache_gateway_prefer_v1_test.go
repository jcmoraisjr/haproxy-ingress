package services

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
)

func TestGatewayAccessorsPreferV1WhenBothVersionsAreEnabled(t *testing.T) {
	t.Parallel()

	t.Run("GetGatewayClassMap prefers v1", func(t *testing.T) {
		t.Parallel()

		cache := newGatewayCacheForTest(t,
			&gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "v1-class"},
				Spec: gatewayv1.GatewayClassSpec{
					ControllerName: gatewayv1.GatewayController("example.com/controller"),
				},
			},
			&gatewayv1beta1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "beta-class"},
				Spec: gatewayv1beta1.GatewayClassSpec{
					ControllerName: gatewayv1beta1.GatewayController("example.com/controller"),
				},
			},
		)

		classes, err := cache.GetGatewayClassMap()
		require.NoError(t, err)
		require.Len(t, classes, 1)
		require.Contains(t, classes, gatewayv1.ObjectName("v1-class"))
	})

	t.Run("GetHTTPRouteList prefers v1", func(t *testing.T) {
		t.Parallel()

		cache := newGatewayCacheForTest(t,
			&gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "v1-route", Namespace: "default"},
			},
			&gatewayv1beta1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "beta-route", Namespace: "default"},
			},
		)

		routes, err := cache.GetHTTPRouteList()
		require.NoError(t, err)
		require.Len(t, routes, 1)
		require.Equal(t, "v1-route", routes[0].Name)
	})
}

func newGatewayCacheForTest(t *testing.T, objs ...client.Object) *c {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.AddToScheme(scheme))
	require.NoError(t, gatewayv1beta1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &c{
		ctx:    context.Background(),
		log:    logr.Discard(),
		config: &config.Config{HasGatewayV1: true, HasGatewayB1: true, ControllerName: "example.com/controller"},
		client: fakeClient,
	}
}
