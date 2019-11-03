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

	cfile "github.com/jcmoraisjr/haproxy-ingress/pkg/common/file"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

type cache struct {
	listers    *ingress.StoreLister
	controller *controller.GenericController
	crossNS    bool
}

func newCache(listers *ingress.StoreLister, controller *controller.GenericController) *cache {
	return &cache{
		listers:    listers,
		controller: controller,
		crossNS:    controller.GetConfig().AllowCrossNamespace,
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

func (c *cache) buildSecretName(defaultNamespace, secretName string) (string, error) {
	if defaultNamespace == "" {
		return secretName, nil
	}
	if strings.Index(secretName, "/") < 0 {
		return defaultNamespace + "/" + secretName, nil
	}
	if c.crossNS || strings.HasPrefix(secretName, defaultNamespace+"/") {
		return secretName, nil
	}
	return "", fmt.Errorf(
		"trying to read secret '%s' from namespace '%s', but cross-namespace reading is disabled; use --allow-cross-namespace to enable",
		secretName, defaultNamespace,
	)
}

func (c *cache) GetTLSSecretPath(defaultNamespace, secretName string) (file convtypes.File, err error) {
	fullname, err := c.buildSecretName(defaultNamespace, secretName)
	if err != nil {
		return file, err
	}
	sslCert, err := c.controller.GetCertificate(fullname)
	if err != nil {
		return file, err
	}
	if sslCert.PemFileName == "" {
		return file, fmt.Errorf("secret '%s' does not have keys 'tls.crt' and 'tls.key'", fullname)
	}
	file = convtypes.File{
		Filename: sslCert.PemFileName,
		SHA1Hash: sslCert.PemSHA,
	}
	return file, nil
}

func (c *cache) GetCASecretPath(defaultNamespace, secretName string) (file convtypes.File, err error) {
	fullname, err := c.buildSecretName(defaultNamespace, secretName)
	if err != nil {
		return file, err
	}
	sslCert, err := c.controller.GetCertificate(fullname)
	if err != nil {
		return file, err
	}
	if sslCert.CAFileName == "" {
		return file, fmt.Errorf("secret '%s' does not have key 'ca.crt'", fullname)
	}
	return convtypes.File{
		Filename: sslCert.CAFileName,
		SHA1Hash: sslCert.PemSHA,
	}, nil
}

func (c *cache) GetDHSecretPath(defaultNamespace, secretName string) (file convtypes.File, err error) {
	fullname, err := c.buildSecretName(defaultNamespace, secretName)
	if err != nil {
		return file, nil
	}
	secret, err := c.listers.Secret.GetByName(fullname)
	if err != nil {
		return file, err
	}
	dh, found := secret.Data[dhparamFilename]
	if !found {
		return file, fmt.Errorf("secret '%s' does not have key '%s'", fullname, dhparamFilename)
	}
	pem := strings.Replace(fullname, "/", "_", -1)
	pemFileName, err := ssl.AddOrUpdateDHParam(pem, dh)
	if err != nil {
		return file, fmt.Errorf("error creating dh-param file '%s': %v", pem, err)
	}
	file = convtypes.File{
		Filename: pemFileName,
		SHA1Hash: cfile.SHA1(pemFileName),
	}
	return file, nil
}

func (c *cache) GetSecretContent(defaultNamespace, secretName, keyName string) ([]byte, error) {
	fullname, err := c.buildSecretName(defaultNamespace, secretName)
	if err != nil {
		return nil, err
	}
	secret, err := c.listers.Secret.GetByName(fullname)
	if err != nil {
		return nil, err
	}
	data, found := secret.Data[keyName]
	if !found {
		return nil, fmt.Errorf("secret '%s' does not have key '%s'", fullname, keyName)
	}
	return data, nil
}
