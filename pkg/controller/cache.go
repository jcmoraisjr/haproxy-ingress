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

package controller

import (
	"fmt"
	"strings"

	api "k8s.io/api/core/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
)

type cache struct {
	listers *ingress.StoreLister
}

func (c *cache) GetService(serviceName string) (*api.Service, error) {
	return c.listers.Service.GetByName(serviceName)
}

func (c *cache) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	ep, err := c.listers.Endpoint.GetServiceEndpoints(service)
	return &ep, err
}

func (c *cache) GetPod(podName string) (*api.Pod, error) {
	sname := strings.Split(podName, "/")
	if len(sname) != 2 {
		return nil, fmt.Errorf("invalid pod name: '%s'", podName)
	}
	return c.listers.Pod.GetPod(sname[0], sname[1])
}

func (c *cache) GetTLSSecretPath(secretName string) (string, error) {
	return "", fmt.Errorf("implement")
}

func (c *cache) GetCASecretPath(secretName string) (string, error) {
	return "", fmt.Errorf("implement")
}

func (c *cache) GetSecretContent(secretName, keyName string) ([]byte, error) {
	return []byte{}, fmt.Errorf("implement")
}
