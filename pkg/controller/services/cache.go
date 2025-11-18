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
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
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

var errGatewayA2Disabled = fmt.Errorf("gateway API v1alpha2 wasn't initialized")
var errGatewayB1Disabled = fmt.Errorf("gateway API v1beta1 wasn't initialized")
var errGatewayV1Disabled = fmt.Errorf("gateway API v1 wasn't initialized")
var errTCPRouteA2Disabled = fmt.Errorf("TCPRoute API v1alpha2 wasn't initialized")
var errTLSRouteA2Disabled = fmt.Errorf("TLSRoute API v1alpha2 wasn't initialized")

func (c *c) get(key string, obj client.Object) error {
	ns, n, err := cache.SplitMetaNamespaceKey(key)
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
	ns, name, err := cache.SplitMetaNamespaceKey(resourceName)
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
		if c.config.DisableIngressClassAPI {
			c.log.Info("ignored ingress validation using IngressClass: IngressClass API is disabled", "ingress", ing.Namespace+"/"+ing.Name, "ingressclass", *className)
		} else {
			hasClass = true
			if ingClass, err := c.GetIngressClass(*className); ingClass != nil {
				fromClass = c.IsValidIngressClass(ingClass)
			} else if err != nil {
				c.log.Error(err, "error reading IngressClass", "ingressclass", *className)
			} else {
				c.log.Info("IngressClass not found", "ingressclass", *className)
			}
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

func (c *c) validateGatewayAPI(api string) error {
	switch api {
	case gatewayv1alpha2.GroupVersion.Version:
		if !c.config.HasGatewayA2 {
			return errGatewayA2Disabled
		}
	case gatewayv1beta1.GroupVersion.Version:
		if !c.config.HasGatewayB1 {
			return errGatewayB1Disabled
		}
	case gatewayv1.GroupVersion.Version:
		if !c.config.HasGatewayV1 {
			return errGatewayV1Disabled
		}
	default:
		return fmt.Errorf("unsupported gateway api version: %s", api)
	}
	return nil
}

func (c *c) getGatewayClass(api, className string) (class *gatewayv1.GatewayClass, err error) {
	if err := c.validateGatewayAPI(api); err != nil {
		return nil, err
	}
	switch api {
	case gatewayv1alpha2.GroupVersion.Version:
		cl := gatewayv1alpha2.GatewayClass{}
		err = c.get(className, &cl)
		class = (*gatewayv1.GatewayClass)(&cl)
	case gatewayv1beta1.GroupVersion.Version:
		cl := gatewayv1beta1.GatewayClass{}
		err = c.get(className, &cl)
		class = (*gatewayv1.GatewayClass)(&cl)
	default:
		cl := gatewayv1.GatewayClass{}
		err = c.get(className, &cl)
		class = &cl
	}
	return class, err
}

func (c *c) IsValidGatewayA2(gw *gatewayv1alpha2.Gateway) bool {
	return c.isValidGateway(gatewayv1alpha2.GroupVersion.Version, (*gatewayv1.Gateway)(gw))
}

func (c *c) IsValidGatewayB1(gw *gatewayv1beta1.Gateway) bool {
	return c.isValidGateway(gatewayv1beta1.GroupVersion.Version, (*gatewayv1.Gateway)(gw))
}

func (c *c) IsValidGateway(gw *gatewayv1.Gateway) bool {
	return c.isValidGateway(gatewayv1.GroupVersion.Version, gw)
}

func (c *c) isValidGateway(api string, gw *gatewayv1.Gateway) bool {
	className := gw.Spec.GatewayClassName
	gwClass, err := c.getGatewayClass(api, string(className))
	if client.IgnoreNotFound(err) != nil {
		c.log.Error(err, "error reading GatewayClass", "api", api, "classname", className)
		return false
	} else if err != nil {
		c.log.Error(nil, "GatewayClass not found", "api", api, "classname", className)
		return false
	}
	return c.IsValidGatewayClass(gwClass)
}

func (c *c) IsValidGatewayClassA2(gwClass *gatewayv1alpha2.GatewayClass) bool {
	return gwClass.Spec.ControllerName == gatewayv1alpha2.GatewayController(c.config.ControllerName)
}

func (c *c) IsValidGatewayClassB1(gwClass *gatewayv1beta1.GatewayClass) bool {
	return gwClass.Spec.ControllerName == gatewayv1beta1.GatewayController(c.config.ControllerName)
}

func (c *c) IsValidGatewayClass(gwClass *gatewayv1.GatewayClass) bool {
	return gwClass.Spec.ControllerName == gatewayv1.GatewayController(c.config.ControllerName)
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

func (c *c) GetGatewayA2(namespace, name string) (*gatewayv1alpha2.Gateway, error) {
	if !c.config.HasGatewayA2 {
		return nil, errGatewayA2Disabled
	}
	gw := gatewayv1alpha2.Gateway{}
	err := c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &gw)
	if err == nil && !c.IsValidGatewayA2(&gw) {
		return nil, nil
	}
	return &gw, err
}

func (c *c) GetGatewayB1(namespace, name string) (*gatewayv1beta1.Gateway, error) {
	if !c.config.HasGatewayB1 {
		return nil, errGatewayB1Disabled
	}
	gw := gatewayv1beta1.Gateway{}
	err := c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &gw)
	if err == nil && !c.IsValidGatewayB1(&gw) {
		return nil, nil
	}
	return &gw, err
}

func (c *c) GetGateway(namespace, name string) (*gatewayv1.Gateway, error) {
	if !c.config.HasGatewayV1 {
		return nil, errGatewayV1Disabled
	}
	gw := gatewayv1.Gateway{}
	err := c.client.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: name}, &gw)
	if err == nil && !c.IsValidGateway(&gw) {
		return nil, nil
	}
	return &gw, err
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

func (c *c) GetHTTPRouteList() ([]*gatewayv1.HTTPRoute, error) {
	if !c.config.HasGatewayV1 {
		return nil, errGatewayV1Disabled
	}
	list := gatewayv1.HTTPRouteList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	rlist := make([]*gatewayv1.HTTPRoute, len(list.Items))
	for i := range list.Items {
		rlist[i] = &list.Items[i]
	}
	return rlist, nil
}

func (c *c) GetTCPRouteList() ([]*gatewayv1alpha2.TCPRoute, error) {
	if !c.config.HasTCPRouteA2 {
		return nil, errTCPRouteA2Disabled
	}
	list := gatewayv1alpha2.TCPRouteList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	rlist := make([]*gatewayv1alpha2.TCPRoute, len(list.Items))
	for i := range list.Items {
		rlist[i] = &list.Items[i]
	}
	return rlist, nil
}

func (c *c) GetTLSRouteList() ([]*gatewayv1alpha2.TLSRoute, error) {
	if !c.config.HasTLSRouteA2 {
		return nil, errTLSRouteA2Disabled
	}
	list := gatewayv1alpha2.TLSRouteList{}
	err := c.client.List(c.ctx, &list)
	if err != nil {
		return nil, err
	}
	rlist := make([]*gatewayv1alpha2.TLSRoute, len(list.Items))
	for i := range list.Items {
		rlist[i] = &list.Items[i]
	}
	return rlist, nil
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
	eplist := discoveryv1.EndpointSliceList{}
	serviceSelector := labels.SelectorFromSet(map[string]string{"kubernetes.io/service-name": service.Name})
	err := c.client.List(c.ctx, &eplist,
		client.InNamespace(service.Namespace),
		client.MatchingLabelsSelector{Selector: serviceSelector},
	)
	if err != nil {
		return nil, err
	}

	var eps []*discoveryv1.EndpointSlice
	for i := range eplist.Items {
		eps = append(eps, &eplist.Items[i])
	}
	return eps, err
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

func (c *c) GetControllerPodList() ([]api.Pod, error) {
	if c.config.ControllerPodSelector == nil {
		// POD_NAME envvar is a prerequisite for pod selector
		return nil, fmt.Errorf("cannot list controller pods, POD_NAME envvar was not configured")
	}

	// read all controller's pod
	podList := api.PodList{}
	if err := c.client.List(c.ctx, &podList, &client.ListOptions{
		LabelSelector: c.config.ControllerPodSelector,
		Namespace:     c.config.ControllerPod.Namespace,
	}); err != nil {
		return nil, err
	}
	return podList.Items, nil
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

func (c *c) GetControllerPod() types.NamespacedName {
	return c.config.ControllerPod
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
		Filename:    sslCert.PemFileName,
		SHA1Hash:    sslCert.PemSHA,
		Certificate: sslCert.Certificate,
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
	namespace, name, err := cache.SplitMetaNamespaceKey(c.config.AcmeTokenConfigMapName)
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
