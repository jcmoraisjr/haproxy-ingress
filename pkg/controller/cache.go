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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/file"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
)

type cache struct {
	listers    *ingress.StoreLister
	controller *controller.GenericController
}

func newCache(listers *ingress.StoreLister, controller *controller.GenericController) *cache {
	return &cache{
		listers:    listers,
		controller: controller,
	}
}

func (c *cache) GetService(serviceName string) (*api.Service, error) {
	return c.listers.Service.GetByName(serviceName)
}

func (c *cache) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	ep, err := c.listers.Endpoint.GetServiceEndpoints(service)
	return &ep, err
}

func (c *cache) GetTerminatingPods(service *api.Service) ([]*api.Pod, error) {
	pods, err := c.listers.Pod.GetTerminatingServicePods(service)
	if err != nil {
		return []*api.Pod{}, err
	}
	podRef := make([]*api.Pod, len(pods))
	for i := range pods {
		podRef[i] = &pods[i]
	}
	return podRef, err
}

func (c *cache) GetPod(podName string) (*api.Pod, error) {
	sname := strings.Split(podName, "/")
	if len(sname) != 2 {
		return nil, fmt.Errorf("invalid pod name: '%s'", podName)
	}
	return c.listers.Pod.GetPod(sname[0], sname[1])
}

func (c *cache) GetTLSSecretPath(secretName string) (ingtypes.File, error) {
	sslCert, err := c.controller.GetCertificate(secretName)
	if err != nil {
		return ingtypes.File{}, err
	}
	if sslCert.PemFileName == "" {
		return ingtypes.File{}, fmt.Errorf("secret '%s' does not have keys 'tls.crt' and 'tls.key'", secretName)
	}
	return ingtypes.File{
		Filename: sslCert.PemFileName,
		SHA1Hash: sslCert.PemSHA,
	}, nil
}

func (c *cache) GetCASecretPath(secretName string) (ingtypes.File, error) {
	sslCert, err := c.controller.GetCertificate(secretName)
	if err != nil {
		return ingtypes.File{}, err
	}
	if sslCert.CAFileName == "" {
		return ingtypes.File{}, fmt.Errorf("secret '%s' does not have key 'ca.crt'", secretName)
	}
	return ingtypes.File{
		Filename: sslCert.CAFileName,
		SHA1Hash: sslCert.PemSHA,
	}, nil
}

func (c *cache) GetDHSecretPath(secretName string) (ingtypes.File, error) {
	secret, err := c.listers.Secret.GetByName(secretName)
	if err != nil {
		return ingtypes.File{}, err
	}
	dh, found := secret.Data[dhparamFilename]
	if !found {
		return ingtypes.File{}, fmt.Errorf("secret '%s' does not have key '%s'", secretName, dhparamFilename)
	}
	pem := strings.Replace(secretName, "/", "_", -1)
	pemFileName, err := ssl.AddOrUpdateDHParam(pem, dh)
	if err != nil {
		return ingtypes.File{}, fmt.Errorf("error creating dh-param file '%s': %v", pem, err)
	}
	return ingtypes.File{
		Filename: pemFileName,
		SHA1Hash: file.SHA1(pemFileName),
	}, nil
}

func (c *cache) GetSecretContent(secretName, keyName string) ([]byte, error) {
	secret, err := c.listers.Secret.GetByName(secretName)
	if err != nil {
		return nil, err
	}
	data, found := secret.Data[keyName]
	if !found {
		return nil, fmt.Errorf("secret '%s' does not have key '%s'", secretName, keyName)
	}
	return data, nil
}
