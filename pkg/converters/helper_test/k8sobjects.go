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

package helper_test

import (
	"strings"

	"gopkg.in/yaml.v2"
	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

// CreateService ...
func CreateService(name, port, endpoints string) (*api.Service, *api.Endpoints, []*discoveryv1.EndpointSlice) {
	sname := strings.Split(name, "/") // namespace/name of the service
	sport := strings.Split(port, ":") // numeric-port -or- name:numeric-port -or- name:numeric-port:named-port
	if len(sport) < 2 {
		sport = []string{"", port, port}
	} else if len(sport) < 3 {
		sport = []string{sport[0], sport[1], sport[1]}
	}

	namespace := sname[0]
	metaName := sname[1]
	portName := sport[0]
	portNumber := sport[1]
	targetRef := sport[2]

	svc := CreateObject(`
apiVersion: v1
kind: Service
metadata:
  name: ` + metaName + `
  namespace: ` + namespace + `
spec:
  ports:
  - name: ` + portName + `
    port: ` + portNumber + `
    targetPort: ` + targetRef).(*api.Service)

	ep := CreateObject(`
apiVersion: v1
kind: Endpoints
metadata:
  name: ` + metaName + `
  namespace: ` + namespace + `
subsets:
- addresses: []
  ports:
  - name: ` + portName + `
    port: ` + portNumber + `
    protocol: TCP`).(*api.Endpoints)

	addr := []api.EndpointAddress{}
	for _, e := range strings.Split(endpoints, ",") {
		if e != "" {
			target := &api.ObjectReference{
				Kind:      "Pod",
				Name:      metaName + "-xxxxx",
				Namespace: namespace,
			}
			addr = append(addr, api.EndpointAddress{IP: e, TargetRef: target})
		}
	}
	ep.Subsets[0].Addresses = addr
	eps := []*discoveryv1.EndpointSlice{}
	if len(endpoints) > 0 {
		eps = createEndpointSlices(metaName, namespace, portName, portNumber, endpoints)
	}

	return svc, ep, eps
}

// CreateSecret ...
func CreateSecret(secretName string) *api.Secret {
	sname := strings.Split(secretName, "/")
	return CreateObject(`
apiVersion: v1
kind: Secret
metadata:
  name: ` + sname[1] + `
  namespace: ` + sname[0]).(*api.Secret)
}

// CreateObject ...
func CreateObject(cfg string) runtime.Object {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode([]byte(cfg), nil, nil)
	if err != nil {
		return nil
	}
	return obj
}

func createEndpointSlices(metaName, namespace, portName, portNumber, endpoints string) []*discoveryv1.EndpointSlice {
	sliceEndpoints := []discoveryv1.Endpoint{}
	for _, e := range strings.Split(endpoints, ",") {
		if e != "" {
			target := &api.ObjectReference{
				Kind:      "Pod",
				Name:      metaName + "-xxxxx",
				Namespace: namespace,
			}
			sliceEndpoints = append(sliceEndpoints, discoveryv1.Endpoint{
				Addresses: []string{e},
				TargetRef: target,
			})
		}
	}
	yamelled, _ := yaml.Marshal(sliceEndpoints)

	eps := CreateObject(`
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
addressType: IPv4
endpoints:
` + string(yamelled) + `
metadata:
  name: ` + metaName + `
  namespace: ` + namespace + `
ports:
- name: ` + portName + `
  port: ` + portNumber + `
  protocol: TCP`).(*discoveryv1.EndpointSlice)

	return []*discoveryv1.EndpointSlice{eps}
}
