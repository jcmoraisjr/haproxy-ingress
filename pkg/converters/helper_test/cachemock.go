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
	"crypto/sha1"
	"fmt"
	"strings"
	"time"

	api "k8s.io/api/core/v1"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// SecretContent ...
type SecretContent map[string]map[string][]byte

// CacheMock ...
type CacheMock struct {
	SvcList       []*api.Service
	EpList        map[string]*api.Endpoints
	TermPodList   map[string][]*api.Pod
	PodList       map[string]*api.Pod
	SecretTLSPath map[string]string
	SecretCAPath  map[string]string
	SecretCRLPath map[string]string
	SecretDHPath  map[string]string
	SecretContent SecretContent
}

// NewCacheMock ...
func NewCacheMock() *CacheMock {
	return &CacheMock{
		SvcList:     []*api.Service{},
		EpList:      map[string]*api.Endpoints{},
		TermPodList: map[string][]*api.Pod{},
		SecretTLSPath: map[string]string{
			"system/ingress-default": "/tls/tls-default.pem",
		},
	}
}

func (c *CacheMock) buildSecretName(defaultNamespace, secretName string) string {
	if defaultNamespace == "" || strings.Index(secretName, "/") >= 0 {
		return secretName
	}
	return defaultNamespace + "/" + secretName
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

// GetTerminatingPods ...
func (c *CacheMock) GetTerminatingPods(service *api.Service) ([]*api.Pod, error) {
	serviceName := service.Namespace + "/" + service.Name
	if pods, found := c.TermPodList[serviceName]; found {
		return pods, nil
	}
	return []*api.Pod{}, nil
}

// GetPod ...
func (c *CacheMock) GetPod(podName string) (*api.Pod, error) {
	if pod, found := c.PodList[podName]; found {
		return pod, nil
	}
	return nil, fmt.Errorf("pod not found: '%s'", podName)
}

// GetTLSSecretPath ...
func (c *CacheMock) GetTLSSecretPath(defaultNamespace, secretName string) (convtypes.CrtFile, error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if path, found := c.SecretTLSPath[fullname]; found {
		return convtypes.CrtFile{
			Filename:   path,
			SHA1Hash:   fmt.Sprintf("%x", sha1.Sum([]byte(path))),
			CommonName: "localhost.localdomain",
			NotAfter:   time.Now().AddDate(0, 0, 30),
		}, nil
	}
	return convtypes.CrtFile{}, fmt.Errorf("secret not found: '%s'", fullname)
}

// GetCASecretPath ...
func (c *CacheMock) GetCASecretPath(defaultNamespace, secretName string) (ca, crl convtypes.File, err error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if path, found := c.SecretCAPath[fullname]; found {
		ca = convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}
	} else {
		return ca, crl, fmt.Errorf("secret not found: '%s'", fullname)
	}
	if path, found := c.SecretCRLPath[fullname]; found {
		crl = convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}
	}
	return ca, crl, nil
}

// GetDHSecretPath ...
func (c *CacheMock) GetDHSecretPath(defaultNamespace, secretName string) (convtypes.File, error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if path, found := c.SecretDHPath[fullname]; found {
		return convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}, nil
	}
	return convtypes.File{}, fmt.Errorf("secret not found: '%s'", fullname)
}

// GetSecretContent ...
func (c *CacheMock) GetSecretContent(defaultNamespace, secretName, keyName string) ([]byte, error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if content, found := c.SecretContent[fullname]; found {
		if val, found := content[keyName]; found {
			return val, nil
		}
		return nil, fmt.Errorf("secret '%s' does not have file/key '%s'", fullname, keyName)
	}
	return nil, fmt.Errorf("secret not found: '%s'", fullname)
}
