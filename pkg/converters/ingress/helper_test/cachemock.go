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
	"fmt"
	"strings"

	api "k8s.io/api/core/v1"
)

// SecretContent ...
type SecretContent map[string]map[string][]byte

// CacheMock ...
type CacheMock struct {
	SvcList       []*api.Service
	EpList        map[string]*api.Endpoints
	PodList       map[string]*api.Pod
	SecretTLSPath map[string]string
	SecretCAPath  map[string]string
	SecretDHPath  map[string]string
	SecretContent SecretContent
}

// GetService ...
func (c *CacheMock) GetService(serviceName string) (*api.Service, error) {
	sname := strings.Split(serviceName, "/")
	if len(sname) == 2 {
		for _, svc := range c.SvcList {
			if svc.Namespace == sname[0] && svc.Name == sname[1] {
				return svc, nil
			}
		}
	}
	return nil, fmt.Errorf("service not found: '%s'", serviceName)
}

// GetEndpoints ...
func (c *CacheMock) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	serviceName := service.Namespace + "/" + service.Name
	if ep, found := c.EpList[serviceName]; found {
		return ep, nil
	}
	return nil, fmt.Errorf("could not find endpoints for service '%s'", serviceName)
}

// GetPod ...
func (c *CacheMock) GetPod(podName string) (*api.Pod, error) {
	if pod, found := c.PodList[podName]; found {
		return pod, nil
	}
	return nil, fmt.Errorf("pod not found: '%s'", podName)
}

// GetTLSSecretPath ...
func (c *CacheMock) GetTLSSecretPath(secretName string) (string, error) {
	if path, found := c.SecretTLSPath[secretName]; found {
		return path, nil
	}
	return "", fmt.Errorf("secret not found: '%s'", secretName)
}

// GetCASecretPath ...
func (c *CacheMock) GetCASecretPath(secretName string) (string, error) {
	if path, found := c.SecretCAPath[secretName]; found {
		return path, nil
	}
	return "", fmt.Errorf("secret not found: '%s'", secretName)
}

// GetDHSecretPath ...
func (c *CacheMock) GetDHSecretPath(secretName string) (string, error) {
	if path, found := c.SecretDHPath[secretName]; found {
		return path, nil
	}
	return "", fmt.Errorf("secret not found: '%s'", secretName)
}

// GetSecretContent ...
func (c *CacheMock) GetSecretContent(secretName, keyName string) ([]byte, error) {
	if content, found := c.SecretContent[secretName]; found {
		if val, found := content[keyName]; found {
			return val, nil
		}
		return nil, fmt.Errorf("secret '%s' does not have file/key '%s'", secretName, keyName)
	}
	return nil, fmt.Errorf("secret not found: '%s'", secretName)
}
