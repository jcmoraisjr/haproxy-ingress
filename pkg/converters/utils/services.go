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
	"strconv"

	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	IP         string
	Port       int
	TargetNS   string
	TargetName string
}

// FindEndpoints ...
func FindEndpoints(endpoints *api.Endpoints, svcPort intstr.IntOrString) (ready, notReady []*Endpoint) {
	// TODO ServiceTypeExternalName
	// TODO ServiceUpstream - annotation nao documentada
	// TODO svcPort.IntValue() doesn't work if svc.targetPort is a pod's named port
	for _, subset := range endpoints.Subsets {
		for _, port := range subset.Ports {
			ssport := int(port.Port)
			if ssport == svcPort.IntValue() && port.Protocol == api.ProtocolTCP {
				for _, addr := range subset.Addresses {
					ready = append(ready, newEndpoint(&addr, ssport))
				}
				for _, addr := range subset.NotReadyAddresses {
					notReady = append(notReady, newEndpoint(&addr, ssport))
				}
			}
		}
	}
	return ready, notReady
}

func newEndpoint(addr *api.EndpointAddress, port int) *Endpoint {
	return &Endpoint{
		IP:         addr.IP,
		Port:       port,
		TargetNS:   addr.TargetRef.Namespace,
		TargetName: addr.TargetRef.Name,
	}
}
