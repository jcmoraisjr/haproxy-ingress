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
	networking "k8s.io/api/networking/v1beta1"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// SecretContent ...
type SecretContent map[string]map[string][]byte

// CacheMock ...
type CacheMock struct {
	tracker       convtypes.Tracker
	Changed       *convtypes.ChangedObjects
	IngList       []*networking.Ingress
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
func NewCacheMock(tracker convtypes.Tracker) *CacheMock {
	return &CacheMock{
		tracker:     tracker,
		Changed:     &convtypes.ChangedObjects{},
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

// GetIngress ...
func (c *CacheMock) GetIngress(ingressName string) (*networking.Ingress, error) {
	for _, ing := range c.IngList {
		if ing.Namespace+"/"+ing.Name == ingressName {
			return ing, nil
		}
	}
	return nil, fmt.Errorf("ingress not found: %s", ingressName)
}

// GetIngressList ...
func (c *CacheMock) GetIngressList() ([]*networking.Ingress, error) {
	return c.IngList, nil
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
func (c *CacheMock) GetTerminatingPods(service *api.Service, track convtypes.TrackingTarget) ([]*api.Pod, error) {
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
func (c *CacheMock) GetTLSSecretPath(defaultNamespace, secretName string, track convtypes.TrackingTarget) (convtypes.CrtFile, error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if path, found := c.SecretTLSPath[fullname]; found {
		c.tracker.Track(false, track, convtypes.SecretType, fullname)
		return convtypes.CrtFile{
			Filename:   path,
			SHA1Hash:   fmt.Sprintf("%x", sha1.Sum([]byte(path))),
			CommonName: "localhost.localdomain",
			NotAfter:   time.Now().AddDate(0, 0, 30),
		}, nil
	}
	c.tracker.Track(true, track, convtypes.SecretType, fullname)
	return convtypes.CrtFile{}, fmt.Errorf("secret not found: '%s'", fullname)
}

// GetCASecretPath ...
func (c *CacheMock) GetCASecretPath(defaultNamespace, secretName string, track convtypes.TrackingTarget) (ca, crl convtypes.File, err error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if path, found := c.SecretCAPath[fullname]; found {
		ca = convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}
	} else {
		c.tracker.Track(true, track, convtypes.SecretType, fullname)
		return ca, crl, fmt.Errorf("secret not found: '%s'", fullname)
	}
	if path, found := c.SecretCRLPath[fullname]; found {
		crl = convtypes.File{
			Filename: path,
			SHA1Hash: fmt.Sprintf("%x", sha1.Sum([]byte(path))),
		}
	}
	c.tracker.Track(false, track, convtypes.SecretType, fullname)
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
func (c *CacheMock) GetSecretContent(defaultNamespace, secretName, keyName string, track convtypes.TrackingTarget) ([]byte, error) {
	fullname := c.buildSecretName(defaultNamespace, secretName)
	if content, found := c.SecretContent[fullname]; found {
		if val, found := content[keyName]; found {
			c.tracker.Track(false, track, convtypes.SecretType, fullname)
			return val, nil
		}
		c.tracker.Track(true, track, convtypes.SecretType, fullname)
		return nil, fmt.Errorf("secret '%s' does not have file/key '%s'", fullname, keyName)
	}
	c.tracker.Track(true, track, convtypes.SecretType, fullname)
	return nil, fmt.Errorf("secret not found: '%s'", fullname)
}

// SwapChangedObjects ...
func (c *CacheMock) SwapChangedObjects() *convtypes.ChangedObjects {
	changed := c.Changed
	c.Changed = &convtypes.ChangedObjects{
		GlobalCur:       changed.GlobalNew,
		TCPConfigMapCur: changed.TCPConfigMapNew,
	}
	// update c.IngList based on notifications
	for i, ing := range c.IngList {
		for _, ingUpd := range changed.IngressesUpd {
			if ing.Namespace == ingUpd.Namespace && ing.Name == ingUpd.Name {
				c.IngList[i] = ingUpd
			}
		}
		for j, ingDel := range changed.IngressesDel {
			if ing.Namespace == ingDel.Namespace && ing.Name == ingDel.Name {
				c.IngList[i] = c.IngList[len(c.IngList)-j-1]
			}
		}
	}
	c.IngList = c.IngList[:len(c.IngList)-len(changed.IngressesDel)]
	for _, ingAdd := range changed.IngressesAdd {
		c.IngList = append(c.IngList, ingAdd)
	}
	// update c.SvcList based on notifications
	for i, svc := range c.SvcList {
		for _, svcUpd := range changed.ServicesUpd {
			if svc.Namespace == svcUpd.Namespace && svc.Name == svcUpd.Name {
				c.SvcList[i] = svcUpd
			}
		}
		for j, svcDel := range changed.ServicesDel {
			if svc.Namespace == svcDel.Namespace && svc.Name == svcDel.Name {
				c.SvcList[i] = c.SvcList[len(c.SvcList)-j-1]
				delete(c.EpList, svc.Namespace+"/"+svc.Name)
			}
		}
	}
	// update c.SecretList based on notification
	for _, secret := range changed.SecretsDel {
		delete(c.SecretTLSPath, secret.Namespace+"/"+secret.Name)
	}
	for _, secret := range changed.SecretsAdd {
		name := secret.Namespace + "/" + secret.Name
		c.SecretTLSPath[name] = "/tls/" + name + ".pem"
	}
	// update c.EpList based on notifications
	for _, ep := range changed.Endpoints {
		c.EpList[ep.Namespace+"/"+ep.Name] = ep
	}
	c.SvcList = c.SvcList[:len(c.SvcList)-len(changed.ServicesDel)]
	for _, svcAdd := range changed.ServicesAdd {
		c.SvcList = append(c.SvcList, svcAdd)
	}
	return changed
}

// NeedFullSync ...
func (c *CacheMock) NeedFullSync() bool {
	return false
}
