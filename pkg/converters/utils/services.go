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
	"fmt"
	"net"
	"strconv"

	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// FindServicePort ...
func FindServicePort(svc *api.Service, servicePort string) intstr.IntOrString {
	for _, port := range svc.Spec.Ports {
		if port.Name == servicePort {
			return port.TargetPort
		}
	}
	for _, port := range svc.Spec.Ports {
		if port.TargetPort.String() == servicePort {
			return port.TargetPort
		}
	}
	svcPortNumber, err := strconv.ParseInt(servicePort, 10, 0)
	if err != nil {
		return intstr.FromString("")
	}
	for _, port := range svc.Spec.Ports {
		if port.Port == int32(svcPortNumber) {
			return port.TargetPort
		}
	}
	return intstr.FromString("")
}

// Endpoint ...
type Endpoint struct {
	IP        string
	Port      int
	TargetRef string
}

// CreateEndpoints ...
func CreateEndpoints(cache types.Cache, svc *api.Service, svcPort intstr.IntOrString) (ready, notReady []*Endpoint, err error) {
	if svc.Spec.Type == api.ServiceTypeExternalName {
		ready, err := createEndpointsExternalName(svc, svcPort)
		return ready, nil, err
	}
	endpoints, err := cache.GetEndpoints(svc)
	if err != nil {
		return nil, nil, err
	}
	ready, notReady = createEndpointsService(endpoints, svcPort)
	return ready, notReady, nil
}

// CreateSvcEndpoint ...
func CreateSvcEndpoint(svc *api.Service, svcPort intstr.IntOrString) (endpoint *Endpoint, err error) {
	port := svcPort.IntValue()
	if port <= 0 {
		return nil, fmt.Errorf("invalid port number: %s", svcPort.String())
	}
	return newEndpointIP(svc.Spec.ClusterIP, port), nil
}

func createEndpointsService(endpoints *api.Endpoints, svcPort intstr.IntOrString) (ready, notReady []*Endpoint) {
	// TODO svcPort.IntValue() doesn't work if svc.targetPort is a pod's named port
	for _, subset := range endpoints.Subsets {
		for _, port := range subset.Ports {
			ssport := int(port.Port)
			if ssport == svcPort.IntValue() && port.Protocol == api.ProtocolTCP {
				for _, addr := range subset.Addresses {
					ready = append(ready, newEndpointAddr(&addr, ssport))
				}
				for _, addr := range subset.NotReadyAddresses {
					notReady = append(notReady, newEndpointAddr(&addr, ssport))
				}
			}
		}
	}
	return ready, notReady
}

var lookup = net.LookupIP

func createEndpointsExternalName(svc *api.Service, svcPort intstr.IntOrString) (endpoints []*Endpoint, err error) {
	port := svcPort.IntValue()
	if port <= 0 {
		return nil, fmt.Errorf("invalid port number: %s", svcPort.String())
	}
	addr, err := lookup(svc.Spec.ExternalName)
	if err != nil {
		return nil, err
	}
	endpoints = make([]*Endpoint, len(addr))
	for i, ip := range addr {
		endpoints[i] = newEndpointIP(ip.String(), port)
	}
	return endpoints, nil
}

func newEndpointAddr(addr *api.EndpointAddress, port int) *Endpoint {
	return &Endpoint{
		IP:        addr.IP,
		Port:      port,
		TargetRef: fmt.Sprintf("%s/%s", addr.TargetRef.Namespace, addr.TargetRef.Name),
	}
}

func newEndpointIP(ip string, port int) *Endpoint {
	return &Endpoint{
		IP:   ip,
		Port: port,
	}
}

func (e *Endpoint) String() string {
	return fmt.Sprintf("%+v", *e)
}
