/*
Copyright 2019 The HAProxy Ingress Controller Authors.

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

package utils

import (
	"net"
	"reflect"
	"testing"

	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
)

func TestCreateEndpointsExternalName(t *testing.T) {
	c := setup(t)
	defer c.teardown()

	svc, _, _ := helper_test.CreateService("default/echo", "8080", "")
	svc.Spec.Type = api.ServiceTypeExternalName
	svc.Spec.ExternalName = "domain.local"
	cache := helper_test.NewCacheMock(nil)
	cache.LookupList["domain.local"] = []net.IP{net.ParseIP("10.0.1.10"), net.ParseIP("10.0.1.11")}
	svcPort := FindServicePort(svc, "8080")
	ready, notReady, err := CreateEndpoints(cache, svc, svcPort, true)
	expected := []*Endpoint{
		{
			IP:   "10.0.1.10",
			Port: 8080,
		},
		{
			IP:   "10.0.1.11",
			Port: 8080,
		},
	}
	if !reflect.DeepEqual(ready, expected) {
		t.Errorf("'ready' endpoints differ -- expected: %+v -- actual: %+v", expected, ready)
	}
	if len(notReady) > 0 {
		t.Errorf("'notReady' is not empty: %+v", notReady)
	}
	if err != nil {
		t.Errorf("CreateEndpoints raised an unexpected error: %v", err)
	}
}

func TestCreateEndpoints(t *testing.T) {
	testCases := []struct {
		endpoints   string
		declarePort string
		findPort    string
		expected    []*Endpoint
	}{
		// 0
		{
			endpoints:   "172.17.0.11,172.17.0.12",
			declarePort: "svcport:8080:http",
			findPort:    "8080",
			expected: []*Endpoint{
				{IP: "172.17.0.11", Port: 8080},
				{IP: "172.17.0.12", Port: 8080},
			},
		},
		// 1
		{
			endpoints:   "172.17.0.11",
			declarePort: "svcport:8080:http",
			findPort:    "svcport",
			expected: []*Endpoint{
				{IP: "172.17.0.11", Port: 8080},
			},
		},
		// 2
		{
			endpoints:   "172.17.0.12",
			declarePort: "svcport:8000:http",
			findPort:    "http",
			expected: []*Endpoint{
				{IP: "172.17.0.12", Port: 8000},
			},
		},
	}
	for _, test := range testCases {
		c := setup(t)
		svc, ep, eps := helper_test.CreateService("default/echo", test.declarePort, test.endpoints)
		for _, ss := range ep.Subsets {
			for i := range ss.Addresses {
				ss.Addresses[i].TargetRef = nil
			}
			for i := range ss.NotReadyAddresses {
				ss.NotReadyAddresses[i].TargetRef = nil
			}
		}
		cache := &helper_test.CacheMock{
			SvcList: []*api.Service{svc},
			EpList:  map[string]*api.Endpoints{"default/echo": ep},
			EpsList: map[string][]*discoveryv1.EndpointSlice{"default/echo": eps},
		}
		port := FindServicePort(svc, test.findPort)
		var endpoints []*Endpoint

		// Test with Endpoints API
		endpoints, _, _ = CreateEndpoints(cache, svc, port, false)
		if !reflect.DeepEqual(endpoints, test.expected) {
			t.Errorf("endpoints differ: expected=%+v actual=%+v", test.expected, endpoints)
		}

		// Test with EndpointSlice API
		endpoints, _, _ = CreateEndpoints(cache, svc, port, true)
		if !reflect.DeepEqual(endpoints, test.expected) {
			t.Errorf("endpoints differ: expected=%+v actual=%+v", test.expected, endpoints)
		}
		c.teardown()
	}
}

type config struct {
	t *testing.T
}

func setup(t *testing.T) *config {
	return &config{
		t: t,
	}
}

func (c *config) teardown() {}
