/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"os"
	"testing"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/store"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/k8s"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/task"

	"github.com/stretchr/testify/assert"
	apiv1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	testclient "k8s.io/client-go/kubernetes/fake"
)

func buildLoadBalancerIngressByIP() []apiv1.LoadBalancerIngress {
	return []apiv1.LoadBalancerIngress{
		{
			IP:       "10.0.0.1",
			Hostname: "foo1",
		},
		{
			IP:       "10.0.0.2",
			Hostname: "foo2",
		},
		{
			IP:       "10.0.0.3",
			Hostname: "",
		},
		{
			IP:       "",
			Hostname: "foo4",
		},
	}
}

func buildSimpleClientSet() *testclient.Clientset {
	return testclient.NewSimpleClientset(
		&apiv1.PodList{Items: []apiv1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo1",
					Namespace: apiv1.NamespaceDefault,
					Labels: map[string]string{
						"lable_sig": "foo_pod",
					},
				},
				Spec: apiv1.PodSpec{
					NodeName: "foo_node_2",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo2",
					Namespace: apiv1.NamespaceDefault,
					Labels: map[string]string{
						"lable_sig": "foo_no",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo3",
					Namespace: "kube-system",
					Labels: map[string]string{
						"lable_sig": "foo_pod",
					},
				},
				Spec: apiv1.PodSpec{
					NodeName: "foo_node_2",
				},
			},
		}},
		&apiv1.ServiceList{Items: []apiv1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: apiv1.NamespaceDefault,
				},
				Status: apiv1.ServiceStatus{
					LoadBalancer: apiv1.LoadBalancerStatus{
						Ingress: buildLoadBalancerIngressByIP(),
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo_non_exist",
					Namespace: apiv1.NamespaceDefault,
				},
			},
		}},
		&apiv1.NodeList{Items: []apiv1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo_node_1",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						}, {
							Type:    apiv1.NodeExternalIP,
							Address: "10.0.0.2",
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo_node_2",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "11.0.0.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "11.0.0.2",
						},
					},
				},
			},
		}},
		&apiv1.EndpointsList{Items: []apiv1.Endpoints{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-controller-leader",
					Namespace: apiv1.NamespaceDefault,
				},
			}}},
		&extensions.IngressList{Items: buildExtensionsIngresses()},
	)
}

func fakeSynFn(interface{}) error {
	return nil
}

func buildExtensionsIngresses() []extensions.Ingress {
	return []extensions.Ingress{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo_ingress_1",
				Namespace: apiv1.NamespaceDefault,
			},
			Status: extensions.IngressStatus{
				LoadBalancer: apiv1.LoadBalancerStatus{
					Ingress: []apiv1.LoadBalancerIngress{
						{
							IP:       "10.0.0.1",
							Hostname: "foo1",
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "foo_ingress_different_class",
				Namespace:   apiv1.NamespaceDefault,
				Annotations: map[string]string{
					// class.IngressKey: "no-nginx",
				},
			},
			Status: extensions.IngressStatus{
				LoadBalancer: apiv1.LoadBalancerStatus{
					Ingress: []apiv1.LoadBalancerIngress{
						{
							IP:       "0.0.0.0",
							Hostname: "foo.bar.com",
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo_ingress_2",
				Namespace: apiv1.NamespaceDefault,
			},
			Status: extensions.IngressStatus{
				LoadBalancer: apiv1.LoadBalancerStatus{
					Ingress: []apiv1.LoadBalancerIngress{},
				},
			},
		},
	}
}

func buildStatusSync() statusSync {
	cs := buildSimpleClientSet()
	return statusSync{
		pod: &k8s.PodInfo{
			Name:      "foo_base_pod",
			Namespace: apiv1.NamespaceDefault,
			Labels: map[string]string{
				"lable_sig": "foo_pod",
			},
		},
		syncQueue: task.NewTaskQueue(fakeSynFn),
		ic: &GenericController{
			listers: &ingress.StoreLister{
				Ingress: newIngressListenerForStatus(cs, buildExtensionsIngresses()...),
			},
			cfg: &Configuration{
				Client:         cs,
				PublishService: apiv1.NamespaceDefault + "/" + "foo",
			},
		},
	}
}

func newIngressListenerForStatus(cs *testclient.Clientset, ingresses ...extensions.Ingress) store.IngressLister {
	ii := informers.NewSharedInformerFactory(cs, 0).Extensions().V1beta1().Ingresses()
	i := ii.Informer()
	for _, s := range ingresses {
		_ = i.GetStore().Add(s)
	}
	go i.Run(make(chan struct{}))
	return store.IngressLister{
		Lister: ii.Lister(),
	}
}

func TestStatusActions(t *testing.T) {
	// make sure election can be created
	_ = os.Setenv("POD_NAME", "foo1")
	_ = os.Setenv("POD_NAMESPACE", apiv1.NamespaceDefault)
	// create object
	cs := buildSimpleClientSet()
	ic := &GenericController{
		listers: &ingress.StoreLister{
			Ingress: newIngressListenerForBackendSSL(cs),
		},
		cfg: &Configuration{
			Client:                 buildSimpleClientSet(),
			UpdateStatusOnShutdown: true,
		},
	}
	fkSync := NewStatusSyncer(ic)
	assert.NotNil(t, fkSync, "expected a valid Sync")

	fk := fkSync.(statusSync)

	ns := make(chan struct{})
	// start it and wait for the election and syn actions
	go fk.Run(ns)
	//  wait for the election
	time.Sleep(100 * time.Millisecond)
	// execute sync
	_ = fk.sync("just-test")
	// PublishService is empty, so the running address is: ["11.0.0.2"]
	// after updated, the ingress's ip should only be "11.0.0.2"
	newIPs := []apiv1.LoadBalancerIngress{{
		IP: "11.0.0.2",
	}}
	fooIngress1, err1 := fk.ic.cfg.Client.ExtensionsV1beta1().Ingresses(apiv1.NamespaceDefault).Get("foo_ingress_1", metav1.GetOptions{})
	assert.Nil(t, err1)
	fooIngress1CurIPs := fooIngress1.Status.LoadBalancer.Ingress
	if !ingressSliceEqual(fooIngress1CurIPs, newIPs) {
		assert.Fail(t, "returned %v but expected %v", fooIngress1CurIPs, newIPs)
	}

	// execute shutdown
	fk.Shutdown()
	// ingress should be empty
	newIPs2 := []apiv1.LoadBalancerIngress{}
	fooIngress2, err2 := fk.ic.cfg.Client.ExtensionsV1beta1().Ingresses(apiv1.NamespaceDefault).Get("foo_ingress_1", metav1.GetOptions{})
	assert.Nil(t, err2)
	fooIngress2CurIPs := fooIngress2.Status.LoadBalancer.Ingress
	if !ingressSliceEqual(fooIngress2CurIPs, newIPs2) {
		assert.Fail(t, "returned %v but expected %v", fooIngress2CurIPs, newIPs2)
	}

	oic, err := fk.ic.listers.Ingress.Lister.Ingresses(apiv1.NamespaceDefault).Get("foo_ingress_different_class")
	assert.Nil(t, err)

	if oic.Status.LoadBalancer.Ingress[0].IP != "0.0.0.0" && oic.Status.LoadBalancer.Ingress[0].Hostname != "foo.bar.com" {
		assert.Fail(t, "invalid ingress status for rule with different class")
	}

	// end test
	ns <- struct{}{}
}

func TestCallback(t *testing.T) {
	buildStatusSync()
}

func TestKeyfunc(t *testing.T) {
	fk := buildStatusSync()
	i := "foo_base_pod"
	r, err := fk.keyfunc(i)
	assert.Nil(t, err)
	assert.Equal(t, r, i, "returned %v but expected %v", r, i)
}

func TestRunningAddresessWithPublishService(t *testing.T) {
	fk := buildStatusSync()
	r, err := fk.runningAddresses()
	assert.Nil(t, err)
	assert.Len(t, r, 4)
}

func TestRunningAddresessWithPods(t *testing.T) {
	fk := buildStatusSync()
	fk.ic.cfg.PublishService = ""
	r, err := fk.runningAddresses()
	assert.Nil(t, err)
	assert.Len(t, r, 1)
	assert.Equal(t, "11.0.0.2", r[0])
}

/*
TODO: this test requires a refactoring
func TestUpdateStatus(t *testing.T) {
	fk := buildStatusSync()
	newIPs := buildLoadBalancerIngressByIP()
	fk.updateStatus(newIPs)

	fooIngress1, err1 := fk.Client.Extensions().Ingresses(apiv1.NamespaceDefault).Get("foo_ingress_1", metav1.GetOptions{})
	if err1 != nil {
		t.Fatalf("unexpected error")
	}
	fooIngress1CurIPs := fooIngress1.Status.LoadBalancer.Ingress
	if !ingressSliceEqual(fooIngress1CurIPs, newIPs) {
		t.Fatalf("returned %v but expected %v", fooIngress1CurIPs, newIPs)
	}

	fooIngress2, err2 := fk.Client.Extensions().Ingresses(apiv1.NamespaceDefault).Get("foo_ingress_2", metav1.GetOptions{})
	if err2 != nil {
		t.Fatalf("unexpected error")
	}
	fooIngress2CurIPs := fooIngress2.Status.LoadBalancer.Ingress
	if !ingressSliceEqual(fooIngress2CurIPs, []apiv1.LoadBalancerIngress{}) {
		t.Fatalf("returned %v but expected %v", fooIngress2CurIPs, []apiv1.LoadBalancerIngress{})
	}
}
*/
func TestSliceToStatus(t *testing.T) {
	fkEndpoints := []string{
		"10.0.0.1",
		"2001:db8::68",
		"opensource-k8s-ingress",
	}

	r := sliceToStatus(fkEndpoints)
	assert.NotNil(t, r, "returned nil but expected a valid []apiv1.LoadBalancerIngress")
	assert.Len(t, r, 3)
	assert.Equal(t, "opensource-k8s-ingress", r[0].Hostname)
	assert.Equal(t, "10.0.0.1", r[1].IP)
	assert.Equal(t, "2001:db8::68", r[2].IP)
}

func TestIngressSliceEqual(t *testing.T) {
	fk1 := buildLoadBalancerIngressByIP()
	fk2 := append(buildLoadBalancerIngressByIP(), apiv1.LoadBalancerIngress{
		IP:       "10.0.0.5",
		Hostname: "foo5",
	})
	fk3 := buildLoadBalancerIngressByIP()
	fk3[0].Hostname = "foo_no_01"
	fk4 := buildLoadBalancerIngressByIP()
	fk4[2].IP = "11.0.0.3"

	cases := []struct {
		lhs []apiv1.LoadBalancerIngress
		rhs []apiv1.LoadBalancerIngress
		err bool
	}{
		{fk1, fk1, true},
		{fk2, fk1, false},
		{fk3, fk1, false},
		{fk4, fk1, false},
		{fk1, nil, false},
		{nil, nil, true},
		{[]apiv1.LoadBalancerIngress{}, []apiv1.LoadBalancerIngress{}, true},
	}

	for _, c := range cases {
		r := ingressSliceEqual(c.lhs, c.rhs)
		assert.Equal(t, c.err, r)
	}
}
