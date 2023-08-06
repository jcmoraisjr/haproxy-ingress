/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package services

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/go-logr/logr"
	api "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	clientcache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

func createCacheFacade(ctx context.Context, client client.Client, config *config.Config, tracker convtypes.Tracker, sslCerts *SSL, dynconfig *convtypes.DynamicConfig, status svcStatusUpdateFnc) *c {
	return &c{
		ctx:       ctx,
		log:       logr.FromContextOrDiscard(ctx).WithName("cache"),
		config:    config,
		client:    client,
		tracker:   tracker,
		sslCerts:  sslCerts,
		dynconfig: dynconfig,
		status:    status,
	}
}

type c struct {
	ctx       context.Context
	log       logr.Logger
	config    *config.Config
	client    client.Client
	tracker   convtypes.Tracker
	sslCerts  *SSL
	dynconfig *convtypes.DynamicConfig
	status    svcStatusUpdateFnc
}

var errGatewayA2Disabled = fmt.Errorf("Gateway API v1alpha2 wasn't initialized")
var errGatewayB1Disabled = fmt.Errorf("Gateway API v1beta1 wasn't initialized")

func (c *c) get(key string, obj client.Object) error {
	ns, n, err := clientcache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	return c.client.Get(c.ctx, types.NamespacedName{Namespace: ns, Name: n}, obj)
}

func (c *c) createOrUpdate(obj client.Object) error {
	if err := c.client.Update(c.ctx, obj); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		if err := c.client.Create(c.ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

func buildResourceName(defaultNamespace, kind, resourceName string, allowCrossNamespace bool) (string, string, error) {
	ns, name, err := clientcache.SplitMetaNamespaceKey(resourceName)
	if err != nil {
		return "", "", err
	}
	if defaultNamespace == "" {
		return ns, name, nil
	}
	if ns == "" {
		return defaultNamespace, name, nil
	}
	if allowCrossNamespace || ns == defaultNamespace {
		return ns, name, nil
	}
	return "", "", fmt.Errorf(
		"trying to read %s '%s' cross namespaces '%s' and '%s', but cross-namespace reading is disabled",
		kind, resourceName, ns, defaultNamespace,
	)
}

func (c *c) getCertificate(namespace, secretName string) (*sslCert, error) {
	secret := api.Secret{}
	err := c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &secret)
	if err != nil {
		return nil, err
	}
	return c.sslCerts.getCertificate(&secret)
}

func (c *c) IsValidIngress(ing *networking.Ingress) bool {
	// check if ingress `hasAnn` and, if so, if it's valid `fromAnn` perspective
	var hasAnn, fromAnn bool
	var ann string
	ann, hasAnn = ing.Annotations["kubernetes.io/ingress.class"]
	if c.config.WatchIngressWithoutClass {
		fromAnn = !hasAnn || ann == c.config.IngressClass
	} else {
		fromAnn = hasAnn && ann == c.config.IngressClass
	}

	// check if ingress `hasClass` and, if so, if it's valid `fromClass` perspective
	var hasClass, fromClass bool
	if className := ing.Spec.IngressClassName; className != nil {
		hasClass = true
		if ingClass, err := c.GetIngressClass(*className); ingClass != nil {
			fromClass = c.IsValidIngressClass(ingClass)
		} else if err != nil {
			c.log.Error(err, "error reading IngressClass", "ingressclass", *className)
		} else {
			c.log.Info("IngressClass not found", "ingressclass", *className)
		}
	}

	// annotation has precedence by default,
	// c.config.IngressClassPrecedence as `true` gives precedence to IngressClass
	// if both class and annotation are configured and they conflict
	if hasAnn {
		if hasClass && fromAnn != fromClass {
			if c.config.IngressClassPrecedence {
				c.log.Error(nil, "ingress has conflicting ingress class configuration, "+
					"using ingress class reference because of --ingress-class-precedence enabled",
					"ingress", ing.Namespace+"/"+ing.Name, "use-ingress", fromClass)
				return fromClass
			}
			c.log.Error(nil, "ingress has conflicting ingress class configuration, using annotation reference",
				"ingress", ing.Namespace+"/"+ing.Name, "use-ingress", fromAnn)
		}
		return fromAnn
	}
	if hasClass {
		return fromClass
	}
	return fromAnn
}

func (c *c) IsValidIngressClass(ingressClass *networking.IngressClass) bool {
	return ingressClass.Spec.Controller == c.config.ControllerName
}

func (c *c) IsValidGatewayA2(gw *gatewayv1alpha2.Gateway) bool {
	className := gw.Spec.GatewayClassName
	gwClass, err := c.getGatewayClassA2(string(className))
	if err != nil {
		c.log.Error(err, "error reading GatewayClass v1alpha2", "classname", className)
		return false
	} else if gwClass == nil {
		c.log.Error(nil, "GatewayClass v1alpha2 not found", "classname", className)
		return false
	}
	return c.IsValidGatewayClassA2(gwClass)
}

func (c *c) IsValidGatewayB1(gw *gatewayv1beta1.Gateway) bool {
	className := gw.Spec.GatewayClassName
	gwClass, err := c.getGatewayClassB1(string(className))
	if err != nil {
		c.log.Error(err, "error reading GatewayClass v1beta1", "classname", className)
		return false
	} else if gwClass == nil {
		c.log.Error(nil, "GatewayClass v1beta1 not found", "classname", className)
		return false
	}
	return c.IsValidGatewayClassB1(gwClass)
}

func (c *c) IsValidGatewayClassA2(gwClass *gatewayv1alpha2.GatewayClass) bool {
	return gwClass.Spec.ControllerName == gatewayv1alpha2.GatewayController(c.config.ControllerName)
}

func (c *c) IsValidGatewayClassB1(gwClass *gatewayv1beta1.GatewayClass) bool {
	return gwClass.Spec.ControllerName == gatewayv1beta1.GatewayController(c.config.ControllerName)
}

func (c *c) getGatewayClassA2(className string) (*gatewayv1alpha2.GatewayClass, error) {
	if !c.config.HasGatewayA2 {
		return nil, errGatewayA2Disabled
	}
	class := gatewayv1alpha2.GatewayClass{}
	err := c.get(className, &class)
	return &class, err
}

func (c *c) getGatewayClassB1(className string) (*gatewayv1beta1.GatewayClass, error) {
	if !c.config.HasGatewayB1 {
		return nil, errGatewayB1Disabled
	}
	class := gatewayv1beta1.GatewayClass{}
	err := c.get(className, &class)
	return &class, err
}

func (c *c) ExternalNameLookup(externalName string) ([]net.IP, error) {
	if c.config.DisableExternalName {
		return nil, fmt.Errorf("external name lookup is disabled")
	}
	return net.LookupIP(externalName)
}

func (c *c) GetIngress(ingressName string) (*networking.Ingress, error) {
	ing := networking.Ingress{}
	err := c.get(ingressName, &ing)
	if err == nil && !c.IsValidIngress(&ing) {
		return nil, fmt.Errorf("ingress class does not match")
	}
	return &ing, err
}

func (c *c) GetIngressList() ([]*networking.Ingress, error) {
	list := networking.IngressList{}
	if err := c.client.List(c.ctx, &list); err != nil {
		return nil, err
	}
	items := make([]*networking.Ingress, len(list.Items))
	var i int
	for j := range list.Items {
		ing := &list.Items[j]
		if c.IsValidIngress(ing) {
			items[i] = ing
			i++
		}
	}
	return items[:i], nil
}

func (c *c) GetIngressClass(className string) (*networking.IngressClass, error) {
	class := networking.IngressClass{}
	err := c.get(className, &class)
	return &class, err
}

func buildLabelSelector(match map[string]string) (labels.Selector, error) {
	list := make([]string, 0, len(match))
	for k, v := range match {
		list = append(list, k+"="+v)
	}
	return labels.Parse(strings.Join(list, ","))
}

func (c *c) GetGatewayA2Map() (map[string]*gatewayv1alpha2.Gateway, error) {
	if !c.config.HasGatewayA2 {
		return nil, errGatewayA2Disabled
	}
	list := gatewayv1alpha2.GatewayList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	validList := make(map[string]*gatewayv1alpha2.Gateway, len(list.Items))
	for i := range list.Items {
		gw := &list.Items[i]
		if c.IsValidGatewayA2(gw) {
			validList[gw.Namespace+"/"+gw.Name] = gw
		}
	}
	return validList, nil
}

func (c *c) GetGatewayB1Map() (map[string]*gatewayv1beta1.Gateway, error) {
	if !c.config.HasGatewayB1 {
		return nil, errGatewayB1Disabled
	}
	list := gatewayv1beta1.GatewayList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	validList := make(map[string]*gatewayv1beta1.Gateway, len(list.Items))
	for i := range list.Items {
		gw := &list.Items[i]
		if c.IsValidGatewayB1(gw) {
			validList[gw.Namespace+"/"+gw.Name] = gw
		}
	}
	return validList, nil
}

func (c *c) GetHTTPRouteA2List() ([]*gatewayv1alpha2.HTTPRoute, error) {
	if !c.config.HasGatewayA2 {
		return nil, errGatewayA2Disabled
	}
	list := gatewayv1alpha2.HTTPRouteList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	refList := make([]*gatewayv1alpha2.HTTPRoute, len(list.Items))
	for i := range list.Items {
		refList[i] = &list.Items[i]
	}
	return refList, nil
}

func (c *c) GetHTTPRouteB1List() ([]*gatewayv1beta1.HTTPRoute, error) {
	if !c.config.HasGatewayB1 {
		return nil, errGatewayB1Disabled
	}
	list := gatewayv1beta1.HTTPRouteList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	refList := make([]*gatewayv1beta1.HTTPRoute, len(list.Items))
	for i := range list.Items {
		refList[i] = &list.Items[i]
	}
	return refList, nil
}

func (c *c) GetService(defaultNamespace, serviceName string) (*api.Service, error) {
	namespace, name, err := buildResourceName(defaultNamespace, "service", serviceName, c.dynconfig.CrossNamespaceServices)
	if err != nil {
		return nil, err
	}
	service := api.Service{}
	err = c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &service)
	return &service, err

}

func (c *c) GetEndpointSlices(service *api.Service) ([]*discoveryv1.EndpointSlice, error) {
	// TODO: endpoint slices to be implemented for new controller runtime. For now
	// only exists in legacy controller.
	return nil, nil
}

func (c *c) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	ep := api.Endpoints{}
	err := c.client.Get(c.ctx, types.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}, &ep)
	return &ep, err
}

func (c *c) GetConfigMap(configMapName string) (*api.ConfigMap, error) {
	cm := api.ConfigMap{}
	err := c.get(configMapName, &cm)
	return &cm, err
}

func (c *c) GetNamespace(name string) (*api.Namespace, error) {
	ns := api.Namespace{}
	err := c.get(name, &ns)
	return &ns, err
}

func isTerminatingPod(svc *api.Service, pod *api.Pod) bool {
	if svc.GetNamespace() != pod.GetNamespace() {
		return false
	}
	for selectorLabel, selectorValue := range svc.Spec.Selector {
		if labelValue, present := pod.Labels[selectorLabel]; !present || selectorValue != labelValue {
			return false
		}
	}
	if pod.DeletionTimestamp != nil && pod.Status.Reason != "NodeLost" && pod.Status.PodIP != "" {
		return true
	}
	return false
}

func (c *c) GetTerminatingPods(service *api.Service, track []convtypes.TrackingRef) ([]*api.Pod, error) {
	selector, err := buildLabelSelector(service.Spec.Selector)
	if err != nil {
		return nil, err
	}
	list := api.PodList{}
	err = c.client.List(c.ctx, &list, &client.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	refList := make([]*api.Pod, len(list.Items))
	var j int
	for i := range list.Items {
		pod := &list.Items[i]
		// all pods need to be tracked despite of the terminating status
		c.tracker.TrackRefName(track, convtypes.ResourcePod, pod.Namespace+"/"+pod.Name)
		if isTerminatingPod(service, pod) {
			refList[j] = pod
			j++
		}
	}
	return refList[:j], nil
}

func (c *c) GetPod(podName string) (*api.Pod, error) {
	pod := api.Pod{}
	err := c.get(podName, &pod)
	return &pod, err
}

func (c *c) GetPodNamespace() string {
	return c.config.ElectionNamespace
}

var contentProtocolRegex = regexp.MustCompile(`^([a-z]+)://(.*)$`)

func getContentProtocol(input string) (proto, content string) {
	data := contentProtocolRegex.FindStringSubmatch(input)
	if len(data) < 3 {
		return "secret", input
	}
	return data[1], data[2]
}

func (c *c) GetTLSSecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (file convtypes.CrtFile, err error) {
	proto, content := getContentProtocol(secretName)
	if proto == "file" {
		if _, err := os.Stat(content); err != nil {
			return file, err
		}
		return convtypes.CrtFile{
			Filename: content,
			SHA1Hash: "-",
		}, nil
	} else if proto != "secret" {
		return file, fmt.Errorf("unsupported protocol: %s", proto)
	}
	namespace, name, err := buildResourceName(defaultNamespace, "secret", content, c.dynconfig.CrossNamespaceSecretCertificate)
	if err != nil {
		return file, err
	}
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, namespace+"/"+name)
	sslCert, err := c.getCertificate(namespace, name)
	if err != nil {
		return file, err
	}
	if sslCert.PemFileName == "" || sslCert.Certificate == nil {
		return file, fmt.Errorf("secret '%s/%s' does not have keys 'tls.crt' and 'tls.key'", namespace, name)
	}
	file = convtypes.CrtFile{
		Filename:   sslCert.PemFileName,
		SHA1Hash:   sslCert.PemSHA,
		CommonName: sslCert.Certificate.Subject.CommonName,
		NotAfter:   sslCert.Certificate.NotAfter,
	}
	return file, nil
}

func (c *c) GetCASecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (ca, crl convtypes.File, err error) {
	proto, content := getContentProtocol(secretName)
	if proto == "file" {
		if content == "" {
			return ca, crl, fmt.Errorf("empty file name")
		}
		files := strings.Split(content, ",")
		if len(files) > 2 {
			return ca, crl, fmt.Errorf("only one or two filenames should be used")
		}
		if _, err := os.Stat(files[0]); err != nil {
			return ca, crl, err
		}
		ca = convtypes.File{
			Filename: files[0],
			SHA1Hash: "-",
		}
		if len(files) == 2 {
			if _, err := os.Stat(files[1]); err != nil {
				return ca, crl, err
			}
			crl = convtypes.File{
				Filename: files[1],
				SHA1Hash: "-",
			}
		}
		return ca, crl, nil
	} else if proto != "secret" {
		return ca, crl, fmt.Errorf("unsupported protocol: %s", proto)
	}
	namespace, name, err := buildResourceName(defaultNamespace, "secret", content, c.dynconfig.CrossNamespaceSecretCA)
	if err != nil {
		return ca, crl, err
	}
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, namespace+"/"+name)
	sslCert, err := c.getCertificate(namespace, name)
	if err != nil {
		return ca, crl, err
	}
	if sslCert.CAFileName == "" {
		return ca, crl, fmt.Errorf("secret '%s/%s' does not have key 'ca.crt'", namespace, name)
	}
	ca = convtypes.File{
		Filename: sslCert.CAFileName,
		SHA1Hash: sslCert.PemSHA,
	}
	if sslCert.CRLFileName != "" {
		crl = convtypes.File{
			Filename: sslCert.CRLFileName,
			SHA1Hash: sslCert.PemSHA,
		}
	}
	return ca, crl, nil
}

func (c *c) GetDHSecretPath(defaultNamespace, secretName string) (file convtypes.File, err error) {
	proto, content := getContentProtocol(secretName)
	if proto == "file" {
		if _, err := os.Stat(content); err != nil {
			return file, err
		}
		return convtypes.File{
			Filename: content,
			SHA1Hash: "-",
		}, nil
	} else if proto != "secret" {
		return file, fmt.Errorf("unsupported protocol: %s", proto)
	}
	namespace, name, err := buildResourceName(defaultNamespace, "secret", content, true)
	if err != nil {
		return file, err
	}
	secret := api.Secret{}
	err = c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret)
	if err != nil {
		return file, err
	}
	dhParam, err := c.sslCerts.getDHParam(&secret)
	if err != nil {
		return file, fmt.Errorf("error creating dh-param file: %w", err)
	}
	file = convtypes.File{
		Filename: dhParam.PemFileName,
		SHA1Hash: dhParam.PemSHA,
	}
	return file, nil
}

func (c *c) GetPasswdSecretContent(defaultNamespace, secretName string, track []convtypes.TrackingRef) ([]byte, error) {
	proto, content := getContentProtocol(secretName)
	if proto == "file" {
		return os.ReadFile(content)
	} else if proto != "secret" {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
	namespace, name, err := buildResourceName(defaultNamespace, "secret", content, c.dynconfig.CrossNamespaceSecretPasswd)
	if err != nil {
		return nil, err
	}
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, namespace+"/"+name)
	secret := api.Secret{}
	err = c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret)
	if err != nil {
		return nil, err
	}
	keyName := "auth"
	data, found := secret.Data[keyName]
	if !found {
		return nil, fmt.Errorf("secret '%s/%s' does not have key '%s'", namespace, name, keyName)
	}
	return data, nil
}

func (c *c) SwapChangedObjects() *convtypes.ChangedObjects {
	// deprecated func
	// converter is adapted to not call this facade
	// when using the new controller
	return nil
}

func (c *c) UpdateStatus(obj client.Object) {
	c.status(obj)
}

//
// Starting acme.Cache implementation
//

// implements acme.Cache
func (c *c) GetKey() (crypto.Signer, error) {
	secretName := c.config.AcmeSecretKeyName
	secret := api.Secret{}
	err := c.get(secretName, &secret)
	var key *rsa.PrivateKey
	if err == nil {
		pemKey, found := secret.Data[api.TLSPrivateKeyKey]
		if !found {
			return nil, fmt.Errorf("secret '%s' does not have a private key", secretName)
		}
		der, err := c.sslCerts.checkValidPEM(pemKey, "RSA PRIVATE KEY")
		if err != nil {
			return nil, err
		}
		key, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, err
		}
	}
	if key == nil {
		namespace, name, err := cache.SplitMetaNamespaceKey(secretName)
		if err != nil {
			return nil, err
		}
		pemEncode, err := c.sslCerts.createPKCS1PrivateKey(2048)
		if err != nil {
			return nil, err
		}
		newSecret := api.Secret{}
		newSecret.Namespace = namespace
		newSecret.Name = name
		newSecret.Data = map[string][]byte{api.TLSPrivateKeyKey: pemEncode}
		if err := c.createOrUpdate(&newSecret); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// implements acme.Cache
func (c *c) SetToken(domain string, uri, token string) error {
	namespace, name, err := clientcache.SplitMetaNamespaceKey(c.config.AcmeTokenConfigMapName)
	if err != nil {
		return err
	}
	config := api.ConfigMap{}
	err = c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &config)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		config.Namespace = namespace
		config.Name = name
	}
	if config.Data == nil {
		config.Data = make(map[string]string, 1)
	}
	if token != "" {
		config.Data[domain] = uri + "=" + token
	} else {
		delete(config.Data, domain)
	}
	return c.createOrUpdate(&config)
}

// implements acme.Cache
func (c *c) GetToken(domain, uri string) string {
	config := api.ConfigMap{}
	err := c.get(c.config.AcmeTokenConfigMapName, &config)
	if err != nil {
		return ""
	}
	data, found := config.Data[domain]
	if !found {
		return ""
	}
	prefix := uri + "="
	if !strings.HasPrefix(data, prefix) {
		return ""
	}
	return strings.TrimPrefix(data, prefix)
}

// implements acme.Cache
func (c *c) GetTLSSecretContent(secretName string) (*acme.TLSSecret, error) {
	secret := api.Secret{}
	err := c.get(secretName, &secret)
	if err != nil {
		return nil, err
	}
	pemCrt, foundCrt := secret.Data[api.TLSCertKey]
	if !foundCrt {
		return nil, fmt.Errorf("secret '%s' does not have '%s' key", secretName, api.TLSCertKey)
	}
	x509, err := c.sslCerts.checkValidCertPEM(pemCrt)
	if err != nil {
		return nil, fmt.Errorf("error validating x509 certificate: %w", err)
	}
	return &acme.TLSSecret{
		Crt: x509,
	}, nil
}

// implements acme.Cache
func (c *c) SetTLSSecretContent(secretName string, pemCrt, pemKey []byte) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(secretName)
	if err != nil {
		return err
	}
	secret := api.Secret{}
	secret.Namespace = namespace
	secret.Name = name
	secret.Type = api.SecretTypeTLS
	secret.Data = map[string][]byte{
		api.TLSCertKey:       pemCrt,
		api.TLSPrivateKeyKey: pemKey,
	}
	return c.createOrUpdate(&secret)
}
