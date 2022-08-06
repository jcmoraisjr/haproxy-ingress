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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	gatewayv1alpha1 "sigs.k8s.io/gateway-api/apis/v1alpha1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	cfile "github.com/jcmoraisjr/haproxy-ingress/pkg/common/file"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

const dhparamFilename = "dhparam.pem"

type k8scache struct {
	ctx                    context.Context
	client                 types.Client
	logger                 types.Logger
	listers                *listers
	controller             *controller.GenericController
	cfg                    *controller.Configuration
	tracker                convtypes.Tracker
	dynamicConfig          *convtypes.DynamicConfig
	podNamespace           string
	globalConfigMapKey     string
	tcpConfigMapKey        string
	acmeSecretKeyName      string
	acmeTokenConfigmapName string
	//
	changed convtypes.ChangedObjects
	//
	updateQueue      utils.Queue
	stateMutex       sync.RWMutex
	waitBeforeUpdate time.Duration
	clear            bool
	//
}

func createCache(
	logger types.Logger,
	controller *controller.GenericController,
	tracker convtypes.Tracker,
	configOptions *convtypes.DynamicConfig,
	updateQueue utils.Queue,
) *k8scache {
	podNamespace := os.Getenv("POD_NAMESPACE")
	if podNamespace == "" {
		// TODO implement a smart fallback or error checking
		// Fallback to a valid name if envvar is not provided. Should never be used because:
		// - `namespace` is only used in `acme*`
		// - `acme*` is only used by acme client and server
		// - acme client and server are only used if leader elector is enabled
		// - leader elector will panic if this envvar is not provided
		podNamespace = "default"
	}
	cfg := controller.GetConfig()
	acmeSecretKeyName := cfg.AcmeSecretKeyName
	if !strings.Contains(acmeSecretKeyName, "/") {
		acmeSecretKeyName = podNamespace + "/" + acmeSecretKeyName
	}
	acmeTokenConfigmapName := cfg.AcmeTokenConfigmapName
	if !strings.Contains(acmeTokenConfigmapName, "/") {
		acmeTokenConfigmapName = podNamespace + "/" + acmeTokenConfigmapName
	}
	globalConfigMapName := cfg.ConfigMapName
	tcpConfigMapName := cfg.TCPConfigMapName
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logger.Info)
	eventBroadcaster.StartRecordingToSink(&typedv1.EventSinkImpl{
		Interface: cfg.Client.CoreV1().Events(cfg.WatchNamespace),
	})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, api.EventSource{
		Component: "ingress-controller",
	})
	cache := &k8scache{
		ctx:                    context.Background(),
		client:                 cfg.Client,
		logger:                 logger,
		controller:             controller,
		cfg:                    cfg,
		tracker:                tracker,
		dynamicConfig:          configOptions,
		podNamespace:           podNamespace,
		globalConfigMapKey:     globalConfigMapName,
		tcpConfigMapKey:        tcpConfigMapName,
		acmeSecretKeyName:      acmeSecretKeyName,
		acmeTokenConfigmapName: acmeTokenConfigmapName,
		stateMutex:             sync.RWMutex{},
		updateQueue:            updateQueue,
		waitBeforeUpdate:       cfg.WaitBeforeUpdate,
		clear:                  true,
	}
	// TODO I'm a circular reference, can you fix me?
	cache.listers = createListers(
		cache,
		logger,
		recorder,
		cfg.Client,
		cfg.WatchGateway,
		cfg.WatchNamespace,
		cfg.ForceNamespaceIsolation,
		!cfg.DisablePodList,
		cfg.ResyncPeriod,
	)
	return cache
}

func (c *k8scache) RunAsync(stopCh <-chan struct{}) {
	c.listers.RunAsync(stopCh)
}

func (c *k8scache) ExternalNameLookup(externalName string) ([]net.IP, error) {
	if c.cfg.DisableExternalName {
		return nil, fmt.Errorf("external name lookup is disabled")
	}
	return net.LookupIP(externalName)
}

func (c *k8scache) GetIngressPodName() (namespace, podname string, err error) {
	namespace = os.Getenv("POD_NAMESPACE")
	podname = os.Getenv("POD_NAME")
	if namespace == "" || podname == "" {
		return "", "", fmt.Errorf("missing POD_NAMESPACE or POD_NAME envvar")
	}
	if pod, _ := c.client.CoreV1().Pods(namespace).Get(c.ctx, podname, metav1.GetOptions{}); pod == nil {
		return "", "", fmt.Errorf("ingress controller pod was not found: %s/%s", namespace, podname)
	}
	return namespace, podname, nil
}

func (c *k8scache) GetIngress(ingressName string) (*networking.Ingress, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(ingressName)
	if err != nil {
		return nil, err
	}
	ing, err := c.listers.ingressLister.Ingresses(namespace).Get(name)
	if ing != nil && !c.IsValidIngress(ing) {
		return nil, fmt.Errorf("ingress class does not match")
	}
	return ing, err
}

func (c *k8scache) GetIngressList() ([]*networking.Ingress, error) {
	ingList, err := c.listers.ingressLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	validIngList := make([]*networking.Ingress, len(ingList))
	var i int
	for _, ing := range ingList {
		if c.IsValidIngress(ing) {
			validIngList[i] = ing
			i++
		}
	}
	return validIngList[:i], nil
}

func (c *k8scache) GetIngressClass(className string) (*networking.IngressClass, error) {
	return c.listers.ingressClassLister.Get(className)
}

func (c *k8scache) hasGatewayA1() bool {
	return c.listers.gatewayClassA1Lister != nil
}

func (c *k8scache) hasGateway() bool {
	return c.listers.gatewayClassLister != nil
}

var errGatewayA1Disabled = fmt.Errorf("Gateway API v1alpha1 wasn't initialized")
var errGatewayA2Disabled = fmt.Errorf("Gateway API v1alpha2 wasn't initialized")

func (c *k8scache) GetGatewayA1(gatewayName string) (*gatewayv1alpha1.Gateway, error) {
	if !c.hasGatewayA1() {
		return nil, errGatewayA1Disabled
	}
	namespace, name, err := cache.SplitMetaNamespaceKey(gatewayName)
	if err != nil {
		return nil, err
	}
	gateway, err := c.listers.gatewayA1Lister.Gateways(namespace).Get(name)
	if gateway != nil && !c.IsValidGatewayA1(gateway) {
		return nil, fmt.Errorf("gateway class does not match")
	}
	return gateway, err
}

func (c *k8scache) GetGatewayA1List() ([]*gatewayv1alpha1.Gateway, error) {
	if !c.hasGatewayA1() {
		return nil, errGatewayA1Disabled
	}
	gwList, err := c.listers.gatewayA1Lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	validGwList := make([]*gatewayv1alpha1.Gateway, len(gwList))
	var i int
	for _, gw := range gwList {
		if c.IsValidGatewayA1(gw) {
			validGwList[i] = gw
			i++
		}
	}
	return validGwList[:i], nil
}

func (c *k8scache) GetGatewayMap() (map[string]*gatewayv1alpha2.Gateway, error) {
	if !c.hasGateway() {
		return nil, errGatewayA2Disabled
	}
	gwList, err := c.listers.gatewayLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	validGwList := make(map[string]*gatewayv1alpha2.Gateway, len(gwList))
	for _, gw := range gwList {
		if c.IsValidGateway(gw) {
			validGwList[gw.Namespace+"/"+gw.Name] = gw
		}
	}
	return validGwList, nil
}

func (c *k8scache) GetGatewayClassA1(className string) (*gatewayv1alpha1.GatewayClass, error) {
	if !c.hasGatewayA1() {
		return nil, errGatewayA1Disabled
	}
	return c.listers.gatewayClassA1Lister.Get(className)
}

func (c *k8scache) GetGatewayClass(className string) (*gatewayv1alpha2.GatewayClass, error) {
	if !c.hasGateway() {
		return nil, errGatewayA2Disabled
	}
	return c.listers.gatewayClassLister.Get(className)
}

func buildLabelSelector(match map[string]string) (labels.Selector, error) {
	list := make([]string, 0, len(match))
	for k, v := range match {
		list = append(list, k+"="+v)
	}
	return labels.Parse(strings.Join(list, ","))
}

func (c *k8scache) GetHTTPRouteA1List(namespace string, match map[string]string) ([]*gatewayv1alpha1.HTTPRoute, error) {
	if !c.hasGatewayA1() {
		return nil, errGatewayA1Disabled
	}
	selector, err := buildLabelSelector(match)
	if err != nil {
		return nil, err
	}
	if namespace != "" {
		return c.listers.httpRouteA1Lister.HTTPRoutes(namespace).List(selector)
	}
	return c.listers.httpRouteA1Lister.List(selector)
}

func (c *k8scache) GetHTTPRouteList() ([]*gatewayv1alpha2.HTTPRoute, error) {
	if !c.hasGateway() {
		return nil, errGatewayA2Disabled
	}
	return c.listers.httpRouteLister.List(labels.Everything())
}

func (c *k8scache) GetService(defaultNamespace, serviceName string) (*api.Service, error) {
	namespace, name, err := c.buildResourceName(defaultNamespace, "service", serviceName, c.dynamicConfig.CrossNamespaceServices)
	if err != nil {
		return nil, err
	}
	return c.listers.serviceLister.Services(namespace).Get(name)
}

func (c *k8scache) GetSecret(secretName string) (*api.Secret, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(secretName)
	if err != nil {
		return nil, err
	}
	if c.listers.running {
		return c.listers.secretLister.Secrets(namespace).Get(name)
	}
	return c.client.CoreV1().Secrets(namespace).Get(c.ctx, name, metav1.GetOptions{})
}

func (c *k8scache) GetConfigMap(configMapName string) (*api.ConfigMap, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(configMapName)
	if err != nil {
		return nil, err
	}
	return c.listers.configMapLister.ConfigMaps(namespace).Get(name)
}

func (c *k8scache) GetNamespace(name string) (*api.Namespace, error) {
	return c.client.CoreV1().Namespaces().Get(c.ctx, name, metav1.GetOptions{})
}

func (c *k8scache) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	return c.listers.endpointLister.Endpoints(service.Namespace).Get(service.Name)
}

// GetTerminatingPods returns the pods that are terminating and belong
// (based on the Spec.Selector) to the supplied service.
func (c *k8scache) GetTerminatingPods(service *api.Service, track []convtypes.TrackingRef) (pl []*api.Pod, err error) {
	if !c.listers.hasPodLister {
		return nil, fmt.Errorf("pod lister wasn't started, remove --disable-pod-list command-line option to enable it")
	}
	l, err := buildLabelSelector(service.Spec.Selector)
	if err != nil {
		return nil, err
	}
	list, err := c.listers.podLister.Pods(service.Namespace).List(l)
	if err != nil {
		return nil, err
	}
	for _, p := range list {
		// all pods need to be tracked despite of the terminating status
		c.tracker.TrackRefName(track, convtypes.ResourcePod, p.Namespace+"/"+p.Name)
		if isTerminatingPod(service, p) {
			pl = append(pl, p)
		}
	}
	return pl, nil
}

// isTerminatingPod Indicates whether or not pod belongs to svc, and is in the process of terminating
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

func (c *k8scache) GetPod(podName string) (*api.Pod, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(podName)
	if err != nil {
		return nil, err
	}
	if c.listers.hasPodLister {
		return c.listers.podLister.Pods(namespace).Get(name)
	}
	// A fallback just in case --disable-pod-list is configured.
	return c.client.CoreV1().Pods(namespace).Get(c.ctx, name, metav1.GetOptions{})
}

func (c *k8scache) GetPodNamespace() string {
	return c.podNamespace
}

var contentProtocolRegex = regexp.MustCompile(`^([a-z]+)://(.*)$`)

func getContentProtocol(input string) (proto, content string) {
	data := contentProtocolRegex.FindStringSubmatch(input)
	if len(data) < 3 {
		return "secret", input
	}
	return data[1], data[2]
}

func (c *k8scache) buildResourceName(defaultNamespace, kind, resourceName string, allowCrossNamespace bool) (string, string, error) {
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

func (c *k8scache) GetTLSSecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (file convtypes.CrtFile, err error) {
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
	namespace, name, err := c.buildResourceName(defaultNamespace, "secret", content, c.dynamicConfig.CrossNamespaceSecretCertificate)
	if err != nil {
		return file, err
	}
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, namespace+"/"+name)
	sslCert, err := c.controller.GetCertificate(namespace, name)
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

func (c *k8scache) GetCASecretPath(defaultNamespace, secretName string, track []convtypes.TrackingRef) (ca, crl convtypes.File, err error) {
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
	namespace, name, err := c.buildResourceName(defaultNamespace, "secret", content, c.dynamicConfig.CrossNamespaceSecretCA)
	if err != nil {
		return ca, crl, err
	}
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, namespace+"/"+name)
	sslCert, err := c.controller.GetCertificate(namespace, name)
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
		// ssl.AddCertAuth concatenates the hash of CA and CRL into the same attribute
		crl = convtypes.File{
			Filename: sslCert.CRLFileName,
			SHA1Hash: sslCert.PemSHA,
		}
	}
	return ca, crl, nil
}

func (c *k8scache) GetDHSecretPath(defaultNamespace, secretName string) (file convtypes.File, err error) {
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
	namespace, name, err := c.buildResourceName(defaultNamespace, "secret", content, true)
	if err != nil {
		return file, err
	}
	secret, err := c.listers.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return file, err
	}
	dh, found := secret.Data[dhparamFilename]
	if !found {
		return file, fmt.Errorf("secret '%s/%s' does not have key '%s'", namespace, name, dhparamFilename)
	}
	pem := fmt.Sprintf("%s_%s", namespace, name)
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

func (c *k8scache) GetPasswdSecretContent(defaultNamespace, secretName string, track []convtypes.TrackingRef) ([]byte, error) {
	proto, content := getContentProtocol(secretName)
	if proto == "file" {
		return os.ReadFile(content)
	} else if proto != "secret" {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
	namespace, name, err := c.buildResourceName(defaultNamespace, "secret", content, c.dynamicConfig.CrossNamespaceSecretPasswd)
	if err != nil {
		return nil, err
	}
	c.tracker.TrackRefName(track, convtypes.ResourceSecret, namespace+"/"+name)
	secret, err := c.listers.secretLister.Secrets(namespace).Get(name)
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

// Implements acme.ClientResolver
func (c *k8scache) GetKey() (crypto.Signer, error) {
	secret, err := c.GetSecret(c.acmeSecretKeyName)
	var key *rsa.PrivateKey
	if err == nil {
		pemKey, found := secret.Data[api.TLSPrivateKeyKey]
		if !found {
			return nil, fmt.Errorf("secret '%s' does not have a key", c.acmeSecretKeyName)
		}
		derBlock, _ := pem.Decode(pemKey)
		if derBlock == nil {
			return nil, fmt.Errorf("secret '%s' has not a valid pem encoded private key", c.acmeSecretKeyName)
		}
		key, err = x509.ParsePKCS1PrivateKey(derBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing acme client private key: %v", err)
		}
	}
	if key == nil {
		namespace, name, err := cache.SplitMetaNamespaceKey(c.acmeSecretKeyName)
		if err != nil {
			return nil, err
		}
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		pemEncode := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		newSecret := &api.Secret{}
		newSecret.Namespace = namespace
		newSecret.Name = name
		newSecret.Data = map[string][]byte{api.TLSPrivateKeyKey: pemEncode}
		if err := c.CreateOrUpdateSecret(newSecret); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// Implements acme.SignerResolver
func (c *k8scache) GetTLSSecretContent(secretName string) (*acme.TLSSecret, error) {
	secret, err := c.GetSecret(secretName)
	if err != nil {
		return nil, err
	}
	pemCrt, foundCrt := secret.Data[api.TLSCertKey]
	if !foundCrt {
		return nil, fmt.Errorf("secret %s does not have %s key", secretName, api.TLSCertKey)
	}
	derCrt, _ := pem.Decode(pemCrt)
	if derCrt == nil {
		return nil, fmt.Errorf("error decoding crt of secret %s: cannot find a proper pem block", secretName)
	}
	crt, errCrt := x509.ParseCertificate(derCrt.Bytes)
	if errCrt != nil {
		return nil, fmt.Errorf("error parsing crt of secret %s: %w", secretName, errCrt)
	}
	return &acme.TLSSecret{
		Crt: crt,
	}, nil
}

// Implements acme.SignerResolver
func (c *k8scache) SetTLSSecretContent(secretName string, pemCrt, pemKey []byte) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(secretName)
	if err != nil {
		return err
	}
	secret := &api.Secret{}
	secret.Namespace = namespace
	secret.Name = name
	secret.Type = api.SecretTypeTLS
	secret.Data = map[string][]byte{
		api.TLSCertKey:       pemCrt,
		api.TLSPrivateKeyKey: pemKey,
	}
	return c.CreateOrUpdateSecret(secret)
}

// Implements acme.ServerResolver
func (c *k8scache) GetToken(domain, uri string) string {
	config, err := c.GetConfigMap(c.acmeTokenConfigmapName)
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

// Implements acme.ClientResolver
func (c *k8scache) SetToken(domain string, uri, token string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(c.acmeTokenConfigmapName)
	if err != nil {
		return err
	}
	config, err := c.listers.configMapLister.ConfigMaps(namespace).Get(name)
	if err != nil {
		config = &api.ConfigMap{}
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
	return c.CreateOrUpdateConfigMap(config)
}

func (c *k8scache) CreateOrUpdateSecret(secret *api.Secret) (err error) {
	cli := c.client.CoreV1().Secrets(secret.Namespace)
	if _, err = c.listers.secretLister.Secrets(secret.Namespace).Get(secret.Name); err != nil {
		_, err = cli.Create(c.ctx, secret, metav1.CreateOptions{})
	} else {
		_, err = cli.Update(c.ctx, secret, metav1.UpdateOptions{})
	}
	return err
}

func (c *k8scache) CreateOrUpdateConfigMap(cm *api.ConfigMap) (err error) {
	cli := c.client.CoreV1().ConfigMaps(cm.Namespace)
	if _, err = c.listers.configMapLister.ConfigMaps(cm.Namespace).Get(cm.Name); err != nil {
		_, err = cli.Create(c.ctx, cm, metav1.CreateOptions{})
	} else {
		_, err = cli.Update(c.ctx, cm, metav1.UpdateOptions{})
	}
	return err
}

// implements ListerEvents
func (c *k8scache) IsValidIngress(ing *networking.Ingress) bool {
	// check if ingress `hasAnn` and, if so, if it's valid `fromAnn` perspective
	var hasAnn, fromAnn bool
	var ann string
	ann, hasAnn = ing.Annotations["kubernetes.io/ingress.class"]
	if c.cfg.WatchIngressWithoutClass {
		fromAnn = !hasAnn || ann == c.cfg.IngressClass
	} else {
		fromAnn = hasAnn && ann == c.cfg.IngressClass
	}

	// check if ingress `hasClass` and, if so, if it's valid `fromClass` perspective
	var hasClass, fromClass bool
	if className := ing.Spec.IngressClassName; className != nil {
		hasClass = true
		if ingClass, err := c.GetIngressClass(*className); ingClass != nil {
			fromClass = c.IsValidIngressClass(ingClass)
		} else if err != nil {
			c.logger.Warn("error reading IngressClass '%s': %v", *className, err)
		} else {
			c.logger.Warn("IngressClass not found: %s", *className)
		}
	}

	// annotation has precedence by default,
	// c.cfg.IngressClassPrecedence as `true` gives precedence to IngressClass
	// if both class and annotation are configured and they conflict
	if hasAnn {
		if hasClass && fromAnn != fromClass {
			if c.cfg.IngressClassPrecedence {
				c.logger.Warn("ingress %s/%s has conflicting ingress class configuration, "+
					"using ingress class reference because of --ingress-class-precedence enabled (%t)",
					ing.Namespace, ing.Name, fromClass)
				return fromClass
			}
			c.logger.Warn("ingress %s/%s has conflicting ingress class configuration, using annotation reference (%t)",
				ing.Namespace, ing.Name, fromAnn)
		}
		return fromAnn
	}
	if hasClass {
		return fromClass
	}
	return fromAnn
}

func (c *k8scache) IsValidIngressClass(ingressClass *networking.IngressClass) bool {
	return ingressClass.Spec.Controller == c.cfg.ControllerName
}

// implements ListerEvents
func (c *k8scache) IsValidGatewayA1(gw *gatewayv1alpha1.Gateway) bool {
	className := gw.Spec.GatewayClassName
	gwClass, err := c.GetGatewayClassA1(className)
	if err != nil {
		c.logger.Warn("error reading GatewayClass v1alpha1 '%s': %v", className, err)
		return false
	} else if gwClass == nil {
		c.logger.Warn("GatewayClass v1alpha1 not found: %s", className)
		return false
	}
	return c.IsValidGatewayClassA1(gwClass)
}

// implements ListerEvents
func (c *k8scache) IsValidGateway(gw *gatewayv1alpha2.Gateway) bool {
	className := gw.Spec.GatewayClassName
	gwClass, err := c.GetGatewayClass(string(className))
	if err != nil {
		c.logger.Warn("error reading GatewayClass v1alpha2 '%s': %v", className, err)
		return false
	} else if gwClass == nil {
		c.logger.Warn("GatewayClass v1alpha2 not found: %s", className)
		return false
	}
	return c.IsValidGatewayClass(gwClass)
}

// implements ListerEvents
func (c *k8scache) IsValidGatewayClassA1(gwClass *gatewayv1alpha1.GatewayClass) bool {
	return gwClass.Spec.Controller == c.cfg.ControllerName
}

// implements ListerEvents
func (c *k8scache) IsValidGatewayClass(gwClass *gatewayv1alpha2.GatewayClass) bool {
	return gwClass.Spec.ControllerName == gatewayv1alpha2.GatewayController(c.cfg.ControllerName)
}

// implements ListerEvents
func (c *k8scache) IsValidConfigMap(cm *api.ConfigMap) bool {
	// IngressClass' Parameters can use ConfigMaps in the controller namespace
	if cm.Namespace == c.podNamespace {
		return true
	}
	key := fmt.Sprintf("%s/%s", cm.Namespace, cm.Name)
	return key == c.globalConfigMapKey || key == c.tcpConfigMapKey
}

// implements ListerEvents
func (c *k8scache) Notify(old, cur interface{}) {
	// IMPLEMENT
	// maintain a list of changed objects only if partial parsing is being used
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()
	// old != nil: has the `old` state of a changed or removed object
	// cur != nil: has the `cur` state of a changed or a just created object
	// old and cur == nil: cannot identify what was changed, need to start a full resync
	ch := &c.changed
	if old != nil {
		switch old := old.(type) {
		case *networking.Ingress:
			if cur == nil {
				ch.IngressesDel = append(ch.IngressesDel, old)
			}
		case *networking.IngressClass:
			if cur == nil {
				ch.IngressClassesDel = append(ch.IngressClassesDel, old)
			}
		case *gatewayv1alpha1.Gateway:
			if cur == nil {
				ch.GatewaysA1Del = append(ch.GatewaysA1Del, old)
				ch.NeedFullSync = true
			}
		case *gatewayv1alpha1.GatewayClass:
			if cur == nil {
				ch.GatewayClassesA1Del = append(ch.GatewayClassesA1Del, old)
				ch.NeedFullSync = true
			}
		case *gatewayv1alpha1.HTTPRoute:
			if cur == nil {
				ch.HTTPRoutesA1Del = append(ch.HTTPRoutesA1Del, old)
				ch.NeedFullSync = true
			}
		case *api.Service:
			if cur == nil {
				ch.ServicesDel = append(ch.ServicesDel, old)
			}
		case *api.Secret:
			if cur == nil {
				secret := old
				ch.SecretsDel = append(ch.SecretsDel, secret)
				c.controller.DeleteSecret(fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
			}
		case *api.ConfigMap:
			if cur == nil {
				ch.ConfigMapsDel = append(ch.ConfigMapsDel, old)
			}
		case cache.DeletedFinalStateUnknown:
			ch.NeedFullSync = true
		}
	}
	if cur != nil {
		switch cur := cur.(type) {
		case *networking.Ingress:
			ing := cur
			if old == nil {
				ch.IngressesAdd = append(ch.IngressesAdd, ing)
			} else {
				ch.IngressesUpd = append(ch.IngressesUpd, ing)
			}
		case *networking.IngressClass:
			cls := cur
			if old == nil {
				ch.IngressClassesAdd = append(ch.IngressClassesAdd, cls)
			} else {
				ch.IngressClassesUpd = append(ch.IngressClassesUpd, cls)
			}
		case *gatewayv1alpha1.Gateway:
			gw := cur
			if old == nil {
				ch.GatewaysA1Add = append(ch.GatewaysA1Add, gw)
			} else {
				ch.GatewaysA1Upd = append(ch.GatewaysA1Upd, gw)
			}
			ch.NeedFullSync = true
		case *gatewayv1alpha1.GatewayClass:
			cls := cur
			if old == nil {
				ch.GatewayClassesA1Add = append(ch.GatewayClassesA1Add, cls)
			} else {
				ch.GatewayClassesA1Upd = append(ch.GatewayClassesA1Upd, cls)
			}
			ch.NeedFullSync = true
		case *gatewayv1alpha1.HTTPRoute:
			hr := cur
			if old == nil {
				ch.HTTPRoutesA1Add = append(ch.HTTPRoutesA1Add, hr)
			} else {
				ch.HTTPRoutesA1Upd = append(ch.HTTPRoutesA1Upd, hr)
			}
			ch.NeedFullSync = true
		case *gatewayv1alpha2.Gateway:
			gw := cur
			if old == nil {
				ch.GatewaysAdd = append(ch.GatewaysAdd, gw)
			} else {
				ch.GatewaysUpd = append(ch.GatewaysUpd, gw)
			}
			ch.NeedFullSync = true
		case *gatewayv1alpha2.GatewayClass:
			cls := cur
			if old == nil {
				ch.GatewayClassesAdd = append(ch.GatewayClassesAdd, cls)
			} else {
				ch.GatewayClassesUpd = append(ch.GatewayClassesUpd, cls)
			}
			ch.NeedFullSync = true
		case *gatewayv1alpha2.HTTPRoute:
			hr := cur
			if old == nil {
				ch.HTTPRoutesAdd = append(ch.HTTPRoutesAdd, hr)
			} else {
				ch.HTTPRoutesUpd = append(ch.HTTPRoutesUpd, hr)
			}
			ch.NeedFullSync = true
		case *api.Endpoints:
			ch.EndpointsNew = append(ch.EndpointsNew, cur)
		case *api.Service:
			svc := cur
			if old == nil {
				ch.ServicesAdd = append(ch.ServicesAdd, svc)
			} else {
				ch.ServicesUpd = append(ch.ServicesUpd, svc)
			}
		case *api.Secret:
			secret := cur
			if old == nil {
				ch.SecretsAdd = append(ch.SecretsAdd, secret)
			} else {
				ch.SecretsUpd = append(ch.SecretsUpd, secret)
			}
			c.controller.UpdateSecret(fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
		case *api.ConfigMap:
			cm := cur
			if old == nil {
				ch.ConfigMapsAdd = append(ch.ConfigMapsAdd, cm)
			} else {
				ch.ConfigMapsUpd = append(ch.ConfigMapsUpd, cm)
			}
			key := fmt.Sprintf("%s/%s", cm.Namespace, cm.Name)
			switch key {
			case c.globalConfigMapKey:
				ch.GlobalConfigMapDataNew = cm.Data
			case c.tcpConfigMapKey:
				ch.TCPConfigMapDataNew = cm.Data
			}
		case *api.Pod:
			ch.PodsNew = append(ch.PodsNew, cur)
		case cache.DeletedFinalStateUnknown:
			ch.NeedFullSync = true
		}
	}
	if old == nil && cur == nil {
		ch.NeedFullSync = true
	}
	if c.clear {
		// Wait before notify, giving the time to receive
		// all/most of the changes of a batch update
		time.AfterFunc(c.waitBeforeUpdate, func() { c.updateQueue.Notify() })
	}
	c.clear = false
}

// implements converters.types.Cache
func (c *k8scache) SwapChangedObjects() *convtypes.ChangedObjects {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()
	//
	var changedObj []string
	changedLinks := convtypes.TrackingLinks{}
	type event string
	var eventDel event = "del"
	var eventUpdate event = "update"
	var eventAdd event = "add"
	addChanges := func(ctx convtypes.ResourceType, ev event, ns, n string) {
		var fullname string
		if ns != "" {
			fullname = ns + "/" + n
		} else {
			fullname = n
		}
		changedObj = append(changedObj, fmt.Sprintf("%s/%s:%s", ev, ctx, fullname))
		changedLinks[ctx] = append(changedLinks[ctx], fullname)
	}
	ch := c.changed
	if ch.GlobalConfigMapDataNew != nil && !reflect.DeepEqual(ch.GlobalConfigMapDataCur, ch.GlobalConfigMapDataNew) {
		changedObj = append(changedObj, "update/global")
	}
	if ch.TCPConfigMapDataNew != nil && !reflect.DeepEqual(ch.TCPConfigMapDataCur, ch.TCPConfigMapDataNew) {
		changedObj = append(changedObj, "update/tcp-services")
	}
	for _, ing := range ch.IngressesDel {
		addChanges(convtypes.ResourceIngress, eventDel, ing.Namespace, ing.Name)
	}
	for _, ing := range ch.IngressesUpd {
		addChanges(convtypes.ResourceIngress, eventUpdate, ing.Namespace, ing.Name)
	}
	for _, ing := range ch.IngressesAdd {
		addChanges(convtypes.ResourceIngress, eventAdd, ing.Namespace, ing.Name)
	}
	for _, cls := range ch.IngressClassesDel {
		addChanges(convtypes.ResourceIngressClass, eventDel, "", cls.Name)
	}
	for _, cls := range ch.IngressClassesUpd {
		addChanges(convtypes.ResourceIngressClass, eventUpdate, "", cls.Name)
	}
	for _, cls := range ch.IngressClassesAdd {
		addChanges(convtypes.ResourceIngressClass, eventAdd, "", cls.Name)
	}
	for _, gw := range ch.GatewaysA1Del {
		addChanges(convtypes.ResourceGatewayA1, eventDel, gw.Namespace, gw.Name)
	}
	for _, gw := range ch.GatewaysA1Upd {
		addChanges(convtypes.ResourceGatewayA1, eventUpdate, gw.Namespace, gw.Name)
	}
	for _, gw := range ch.GatewaysA1Add {
		addChanges(convtypes.ResourceGatewayA1, eventAdd, gw.Namespace, gw.Name)
	}
	for _, cls := range ch.GatewayClassesA1Del {
		addChanges(convtypes.ResourceGatewayClassA1, eventDel, "", cls.Name)
	}
	for _, cls := range ch.GatewayClassesA1Upd {
		addChanges(convtypes.ResourceGatewayClassA1, eventUpdate, "", cls.Name)
	}
	for _, cls := range ch.GatewayClassesA1Add {
		addChanges(convtypes.ResourceGatewayClassA1, eventAdd, "", cls.Name)
	}
	for _, hr := range ch.HTTPRoutesA1Del {
		addChanges(convtypes.ResourceHTTPRouteA1, eventDel, hr.Namespace, hr.Name)
	}
	for _, hr := range ch.HTTPRoutesA1Upd {
		addChanges(convtypes.ResourceHTTPRouteA1, eventUpdate, hr.Namespace, hr.Name)
	}
	for _, hr := range ch.HTTPRoutesA1Add {
		addChanges(convtypes.ResourceHTTPRouteA1, eventAdd, hr.Namespace, hr.Name)
	}
	for _, gw := range ch.GatewaysDel {
		addChanges(convtypes.ResourceGateway, eventDel, gw.Namespace, gw.Name)
	}
	for _, gw := range ch.GatewaysUpd {
		addChanges(convtypes.ResourceGateway, eventUpdate, gw.Namespace, gw.Name)
	}
	for _, gw := range ch.GatewaysAdd {
		addChanges(convtypes.ResourceGateway, eventAdd, gw.Namespace, gw.Name)
	}
	for _, cls := range ch.GatewayClassesDel {
		addChanges(convtypes.ResourceGatewayClass, eventDel, "", cls.Name)
	}
	for _, cls := range ch.GatewayClassesUpd {
		addChanges(convtypes.ResourceGatewayClass, eventUpdate, "", cls.Name)
	}
	for _, cls := range ch.GatewayClassesAdd {
		addChanges(convtypes.ResourceGatewayClass, eventAdd, "", cls.Name)
	}
	for _, hr := range ch.HTTPRoutesDel {
		addChanges(convtypes.ResourceHTTPRoute, eventDel, hr.Namespace, hr.Name)
	}
	for _, hr := range ch.HTTPRoutesUpd {
		addChanges(convtypes.ResourceHTTPRoute, eventUpdate, hr.Namespace, hr.Name)
	}
	for _, hr := range ch.HTTPRoutesAdd {
		addChanges(convtypes.ResourceHTTPRoute, eventAdd, hr.Namespace, hr.Name)
	}
	for _, ep := range ch.EndpointsNew {
		addChanges(convtypes.ResourceEndpoints, eventUpdate, ep.Namespace, ep.Name)
	}
	for _, svc := range ch.ServicesDel {
		addChanges(convtypes.ResourceService, eventDel, svc.Namespace, svc.Name)
	}
	for _, svc := range ch.ServicesUpd {
		addChanges(convtypes.ResourceService, eventUpdate, svc.Namespace, svc.Name)
	}
	for _, svc := range ch.ServicesAdd {
		addChanges(convtypes.ResourceService, eventAdd, svc.Namespace, svc.Name)
	}
	for _, secret := range ch.SecretsDel {
		addChanges(convtypes.ResourceSecret, eventDel, secret.Namespace, secret.Name)
	}
	for _, secret := range ch.SecretsUpd {
		addChanges(convtypes.ResourceSecret, eventUpdate, secret.Namespace, secret.Name)
	}
	for _, secret := range ch.SecretsAdd {
		addChanges(convtypes.ResourceSecret, eventAdd, secret.Namespace, secret.Name)
	}
	for _, cm := range ch.ConfigMapsDel {
		addChanges(convtypes.ResourceConfigMap, eventDel, cm.Namespace, cm.Name)
	}
	for _, cm := range ch.ConfigMapsUpd {
		addChanges(convtypes.ResourceConfigMap, eventUpdate, cm.Namespace, cm.Name)
	}
	for _, cm := range ch.ConfigMapsAdd {
		addChanges(convtypes.ResourceConfigMap, eventAdd, cm.Namespace, cm.Name)
	}
	for _, pod := range ch.PodsNew {
		addChanges(convtypes.ResourcePod, eventUpdate, pod.Namespace, pod.Name)
	}
	ch.Objects = changedObj
	ch.Links = changedLinks
	//
	// leave ch with the current state, cleanup c.changed to receive new events
	c.changed = convtypes.ChangedObjects{
		GlobalConfigMapDataCur: ch.GlobalConfigMapDataCur,
		GlobalConfigMapDataNew: ch.GlobalConfigMapDataNew,
		TCPConfigMapDataCur:    ch.TCPConfigMapDataCur,
		TCPConfigMapDataNew:    ch.TCPConfigMapDataNew,
	}
	if ch.GlobalConfigMapDataNew != nil {
		c.changed.GlobalConfigMapDataCur = ch.GlobalConfigMapDataNew
		c.changed.GlobalConfigMapDataNew = nil
	}
	if ch.TCPConfigMapDataNew != nil {
		c.changed.TCPConfigMapDataCur = ch.TCPConfigMapDataNew
		c.changed.TCPConfigMapDataNew = nil
	}
	//
	c.clear = true
	return &ch
}
