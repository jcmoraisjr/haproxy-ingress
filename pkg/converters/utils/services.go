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
	"sort"
	"strconv"

	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// FindServicePort ...
func FindServicePort(svc *api.Service, servicePort string) *api.ServicePort {
	for _, port := range svc.Spec.Ports {
		if port.Name == servicePort || port.TargetPort.String() == servicePort {
			return &port
		}
	}
	svcPortNumber, err := strconv.ParseInt(servicePort, 10, 0)
	if err != nil {
		return nil
	}
	svcPort := int32(svcPortNumber)
	for _, port := range svc.Spec.Ports {
		if port.Port == svcPort {
			return &port
		}
	}
	return nil
}

// FindContainerPort Find the container's port number of a known servicePort
// Search criteria:
// 1. svcPort.TargetPort is a number: this is the right container's port
// 2. svcPort.TargetPort is a named port (not a number): find a container's port with that name and use its ContainerPort
// If targetPort is neither a valid port number nor a declared named port, return zero which means that the port was not found
func FindContainerPort(pod *api.Pod, svcPort *api.ServicePort) int {
	if targetPort := svcPort.TargetPort.IntValue(); targetPort > 0 {
		return targetPort
	}
	portName := svcPort.TargetPort.String()
	for _, c := range pod.Spec.Containers {
		for _, port := range c.Ports {
			if port.Protocol == svcPort.Protocol && port.Name == portName {
				return int(port.ContainerPort)
			}
		}
	}
	return 0
}

// Endpoint ...
type Endpoint struct {
	IP        string
	Port      int
	Target    string
	TargetRef string
}

func createEndpoints(endpoints *api.Endpoints, svcPort *api.ServicePort) (ready, notReady []*Endpoint, err error) {
	for _, subset := range endpoints.Subsets {
		for _, epPort := range subset.Ports {
			if matchPort(svcPort, &epPort) {
				port := int(epPort.Port)
				for _, addr := range subset.Addresses {
					ready = append(ready, newEndpoint(resolveIP(endpoints, addr.IP), port, addr.TargetRef))
				}
				for _, addr := range subset.NotReadyAddresses {
					notReady = append(notReady, newEndpoint(resolveIP(endpoints, addr.IP), port, addr.TargetRef))
				}
			}
		}
	}
	return ready, notReady, nil
}

func createEndpointSlices(endpointSlices []*discoveryv1.EndpointSlice, svcPort *api.ServicePort) (ready, notReady []*Endpoint, err error) {
	for _, endpointSlice := range endpointSlices {
		for _, epPort := range endpointSlice.Ports {
			// A pod corresponding to an endpoint slice can expose multiple ports.
			// In current case we are only interested in those ports in which the
			// service is interested in. Service's interest is reflected by svcPort.

			// Protocols must match. Example, no point routing UDP traffic to TCP port.
			svcPortProtocol := api.ProtocolTCP
			if svcPort.Protocol != "" {
				svcPortProtocol = svcPort.Protocol
			}
			if svcPortProtocol != *epPort.Protocol {
				continue
			}

			// From the docs of core.v1.ServicePort:
			//
			// When considering the endpoints for a Service, this [Name field of service]
			// must match the 'name' field in the EndpointPort.
			if svcPort.Name != "" && svcPort.Name != *epPort.Name {
				continue
			}

			for _, endpoint := range endpointSlice.Endpoints {
				// kube-proxy also consults the first address in the Endpoint.
				// https://github.com/kubernetes/kubernetes/issues/106267
				// Using that as an argument to justify why we are using first
				// address here.
				domainEndpoint := newEndpoint(resolveIP(endpointSlice, endpoint.Addresses[0]), int(*epPort.Port), endpoint.TargetRef)

				// From the API docs of EndpointConditions:
				//
				// "ready indicates that this endpoint is prepared to receive traffic,
				// according to whatever system is managing the endpoint. A nil value
				// indicates an unknown state. In most cases consumers should interpret this
				// unknown state as ready. For compatibility reasons, ready should never be
				// "true" for terminating endpoints."
				if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
					ready = append(ready, domainEndpoint)
				} else {
					// https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/
					// Default EndpointSliceTerminatingCondition is false in 1.21
					// Default EndpointSliceTerminatingCondition is true in 1.22
					notReady = append(notReady, domainEndpoint)
				}
			}
		}
	}
	return ready, notReady, nil
}

func resolveIP(ep metav1.Object, configuredIPAddress string) string {
	if ann := ep.GetAnnotations(); ann != nil {
		if ipOverride := ann["haproxy-ingress.github.io/ip-override"]; ipOverride != "" {
			return ipOverride
		}
	}
	return configuredIPAddress
}

// CreateEndpoints ...
func CreateEndpoints(cache types.Cache, svc *api.Service, svcPort *api.ServicePort, useEndpointSlices bool) (ready, notReady []*Endpoint, err error) {
	switch {
	case svc.Spec.Type == api.ServiceTypeExternalName:
		ready, err = createEndpointsExternalName(cache, svc, svcPort)
	case useEndpointSlices:
		endpoints, err1 := cache.GetEndpointSlices(svc)
		if err1 != nil {
			return nil, nil, err1
		}
		ready, notReady, err = createEndpointSlices(endpoints, svcPort)
	default:
		endpoints, err1 := cache.GetEndpoints(svc)
		if err1 != nil {
			return nil, nil, err1
		}
		ready, notReady, err = createEndpoints(endpoints, svcPort)
	}
	// ensures predictable result, allowing to compare old and new states
	sort.Slice(ready, func(i, j int) bool {
		return ready[i].Target < ready[j].Target
	})
	sort.Slice(notReady, func(i, j int) bool {
		return notReady[i].Target < notReady[j].Target
	})
	return ready, notReady, err
}

func matchPort(svcPort *api.ServicePort, epPort *api.EndpointPort) bool {
	if epPort.Protocol != api.ProtocolTCP {
		return false
	}
	return svcPort.Name == "" || svcPort.Name == epPort.Name
}

// CreateSvcEndpoint ...
func CreateSvcEndpoint(svc *api.Service, svcPort *api.ServicePort) (endpoint *Endpoint, err error) {
	port := svcPort.Port
	if port <= 0 {
		return nil, fmt.Errorf("invalid port number: %d", port)
	}
	return newEndpoint(svc.Spec.ClusterIP, int(port), nil), nil
}

func createEndpointsExternalName(cache types.Cache, svc *api.Service, svcPort *api.ServicePort) (endpoints []*Endpoint, err error) {
	port := int(svcPort.Port)
	if port <= 0 {
		return nil, fmt.Errorf("invalid port number: %d", port)
	}
	addr, err := cache.ExternalNameLookup(svc.Spec.ExternalName)
	if err != nil {
		return nil, err
	}
	endpoints = make([]*Endpoint, len(addr))
	for i, ip := range addr {
		endpoints[i] = newEndpoint(ip.String(), port, nil)
	}
	return endpoints, nil
}

func newEndpoint(ip string, port int, targetRef *api.ObjectReference) *Endpoint {
	var targetRefStr string
	if targetRef != nil {
		targetRefStr = fmt.Sprintf("%s/%s", targetRef.Namespace, targetRef.Name)

	}
	return &Endpoint{
		IP:        ip,
		Port:      port,
		Target:    ip + ":" + strconv.Itoa(port),
		TargetRef: targetRefStr,
	}
}

func (e *Endpoint) String() string {
	return fmt.Sprintf("%+v", *e)
}
