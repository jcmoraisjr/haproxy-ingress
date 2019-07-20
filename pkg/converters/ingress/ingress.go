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

package ingress

import (
	"fmt"
	"strconv"
	"strings"

	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/annotations"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// Config ...
type Config interface {
	Sync(ingress []*extensions.Ingress)
}

// NewIngressConverter ...
func NewIngressConverter(options *ingtypes.ConverterOptions, haproxy haproxy.Config, globalConfig map[string]string) Config {
	if options.DefaultConfig == nil {
		options.DefaultConfig = createDefaults
	}
	annDefaults, globalDefaults := options.DefaultConfig()
	c := &converter{
		haproxy:            haproxy,
		options:            options,
		logger:             options.Logger,
		cache:              options.Cache,
		mapBuilder:         annotations.NewMapBuilder(options.Logger, options.AnnotationPrefix+"/", mergeMaps(annDefaults, globalConfig)),
		updater:            annotations.NewUpdater(haproxy, options.Cache, options.Logger),
		globalConfig:       mergeConfig(globalDefaults, globalConfig),
		hostAnnotations:    map[*hatypes.Host]*annotations.Mapper{},
		backendAnnotations: map[*hatypes.Backend]*annotations.Mapper{},
	}
	haproxy.ConfigDefaultX509Cert(options.DefaultSSLFile.Filename)
	if options.DefaultBackend != "" {
		if backend, err := c.addBackend(&annotations.Source{}, "/", options.DefaultBackend, "", map[string]string{}); err == nil {
			haproxy.ConfigDefaultBackend(backend)
		} else {
			c.logger.Error("error reading default service: %v", err)
		}
	}
	return c
}

type converter struct {
	haproxy            haproxy.Config
	options            *ingtypes.ConverterOptions
	logger             types.Logger
	cache              ingtypes.Cache
	mapBuilder         *annotations.MapBuilder
	updater            annotations.Updater
	globalConfig       *ingtypes.ConfigGlobals
	hostAnnotations    map[*hatypes.Host]*annotations.Mapper
	backendAnnotations map[*hatypes.Backend]*annotations.Mapper
}

func (c *converter) Sync(ingress []*extensions.Ingress) {
	for _, ing := range ingress {
		c.syncIngress(ing)
	}
	c.syncAnnotations()
}

func (c *converter) syncIngress(ing *extensions.Ingress) {
	fullIngName := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)
	source := &annotations.Source{
		Namespace: ing.Namespace,
		Name:      ing.Name,
		Type:      "ingress",
	}
	annHost, annBack := c.readAnnotations(ing.Annotations)
	if ing.Spec.Backend != nil {
		svcName, svcPort := readServiceNamePort(ing.Spec.Backend)
		err := c.addDefaultHostBackend(source, utils.FullQualifiedName(ing.Namespace, svcName), svcPort, annHost, annBack)
		if err != nil {
			c.logger.Warn("skipping default backend of ingress '%s': %v", fullIngName, err)
		}
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		hostname := rule.Host
		if hostname == "" {
			hostname = "*"
		}
		host := c.addHost(hostname, source, annHost)
		for _, path := range rule.HTTP.Paths {
			uri := path.Path
			if uri == "" {
				uri = "/"
			}
			if host.FindPath(uri) != nil {
				c.logger.Warn("skipping redeclared path '%s' of ingress '%s'", uri, fullIngName)
				continue
			}
			svcName, svcPort := readServiceNamePort(&path.Backend)
			fullSvcName := utils.FullQualifiedName(ing.Namespace, svcName)
			backend, err := c.addBackend(source, uri, fullSvcName, svcPort, annBack)
			if err != nil {
				c.logger.Warn("skipping backend config of ingress '%s': %v", fullIngName, err)
				continue
			}
			host.AddPath(backend, uri)
			sslpassthrough, _ := strconv.ParseBool(annHost[ingtypes.HostSSLPassthrough])
			sslpasshttpport := annHost[ingtypes.HostSSLPassthroughHTTPPort]
			if sslpassthrough && sslpasshttpport != "" {
				if _, err := c.addBackend(source, uri, fullSvcName, sslpasshttpport, annBack); err != nil {
					c.logger.Warn("skipping http port config of ssl-passthrough: %v", err)
				}
			}
		}
		for _, tls := range ing.Spec.TLS {
			for _, tlshost := range tls.Hosts {
				if tlshost == hostname {
					tlsPath := c.addTLS(ing.Namespace, tls.SecretName)
					if host.TLS.TLSHash == "" {
						host.TLS.TLSFilename = tlsPath.Filename
						host.TLS.TLSHash = tlsPath.SHA1Hash
					} else if host.TLS.TLSHash != tlsPath.SHA1Hash {
						msg := fmt.Sprintf("TLS of host '%s' was already assigned", host.Hostname)
						if tls.SecretName != "" {
							c.logger.Warn("skipping TLS secret '%s' of ingress '%s': %s", tls.SecretName, fullIngName, msg)
						} else {
							c.logger.Warn("skipping default TLS secret of ingress '%s': %s", fullIngName, msg)
						}
					}
				}
			}
		}
	}
}

func (c *converter) syncAnnotations() {
	c.updater.UpdateGlobalConfig(c.haproxy.Global(), c.globalConfig)
	for _, host := range c.haproxy.Hosts() {
		if ann, found := c.hostAnnotations[host]; found {
			c.updater.UpdateHostConfig(host, ann)
		}
	}
	for _, backend := range c.haproxy.Backends() {
		if ann, found := c.backendAnnotations[backend]; found {
			c.updater.UpdateBackendConfig(backend, ann)
		}
	}
}

func (c *converter) addDefaultHostBackend(source *annotations.Source, fullSvcName, svcPort string, annHost, annBack map[string]string) error {
	uri := "/"
	if fr := c.haproxy.FindHost("*"); fr != nil {
		if fr.FindPath(uri) != nil {
			return fmt.Errorf("path %s was already defined on default host", uri)
		}
	}
	backend, err := c.addBackend(source, uri, fullSvcName, svcPort, annBack)
	if err != nil {
		return err
	}
	host := c.addHost("*", source, annHost)
	host.AddPath(backend, uri)
	return nil
}

func (c *converter) addHost(hostname string, source *annotations.Source, ann map[string]string) *hatypes.Host {
	host := c.haproxy.AcquireHost(hostname)
	mapper, found := c.hostAnnotations[host]
	if !found {
		mapper = c.mapBuilder.NewMapper()
		c.hostAnnotations[host] = mapper
	}
	skipped := mapper.AddAnnotations(source, "/", ann)
	if len(skipped) > 0 {
		c.logger.Warn("skipping host annotation(s) from %v due to conflict: %v", source, skipped)
	}
	return host
}

func (c *converter) addBackend(source *annotations.Source, uri, fullSvcName, svcPort string, ann map[string]string) (*hatypes.Backend, error) {
	svc, err := c.cache.GetService(fullSvcName)
	if err != nil {
		return nil, err
	}
	ssvcName := strings.Split(fullSvcName, "/")
	namespace := ssvcName[0]
	svcName := ssvcName[1]
	if svcPort == "" {
		// if the port wasn't specified, take the first one
		// from the api.Service object
		svcPort = svc.Spec.Ports[0].TargetPort.String()
	}
	epport := findServicePort(svc, svcPort)
	if epport.String() == "" {
		return nil, fmt.Errorf("port not found: '%s'", svcPort)
	}
	backend := c.haproxy.AcquireBackend(namespace, svcName, epport.String())
	mapper, found := c.backendAnnotations[backend]
	if !found {
		// New backend, configure endpoints and svc annotations
		if err := c.addEndpoints(svc, epport, backend); err != nil {
			c.logger.Error("error adding endpoints of service '%s': %v", fullSvcName, err)
		}
		// Initialize with service annotations, giving precedence
		mapper = c.mapBuilder.NewMapper()
		_, ann := c.readAnnotations(svc.Annotations)
		mapper.AddAnnotations(&annotations.Source{
			Namespace: namespace,
			Name:      svcName,
			Type:      "service",
		}, uri, ann)
		c.backendAnnotations[backend] = mapper
	}
	// Merging Ingress annotations
	skipped := mapper.AddAnnotations(source, uri, ann)
	if len(skipped) > 0 {
		c.logger.Warn("skipping backend '%s:%s' annotation(s) from %v due to conflict: %v",
			svcName, svcPort, source, skipped)
	}
	return backend, nil
}

func findServicePort(svc *api.Service, servicePort string) intstr.IntOrString {
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

func (c *converter) addTLS(namespace, secretName string) ingtypes.File {
	if secretName != "" {
		tlsSecretName := namespace + "/" + secretName
		tlsFile, err := c.cache.GetTLSSecretPath(tlsSecretName)
		if err == nil {
			return tlsFile
		}
		c.logger.Warn("using default certificate due to an error reading secret '%s': %v", tlsSecretName, err)
	}
	return c.options.DefaultSSLFile
}

func (c *converter) addEndpoints(svc *api.Service, svcPort intstr.IntOrString, backend *hatypes.Backend) error {
	endpoints, err := c.cache.GetEndpoints(svc)
	if err != nil {
		return err
	}
	// TODO ServiceTypeExternalName
	// TODO ServiceUpstream - annotation nao documentada
	// TODO svcPort.IntValue() doesn't work if svc.targetPort is a pod's named port
	for _, subset := range endpoints.Subsets {
		for _, port := range subset.Ports {
			ssport := int(port.Port)
			if ssport == svcPort.IntValue() && port.Protocol == api.ProtocolTCP {
				for _, addr := range subset.Addresses {
					backend.NewEndpoint(addr.IP, ssport, addr.TargetRef.Namespace+"/"+addr.TargetRef.Name)
				}
				if c.globalConfig.DrainSupport {
					for _, addr := range subset.NotReadyAddresses {
						ep := backend.NewEndpoint(addr.IP, ssport, addr.TargetRef.Namespace+"/"+addr.TargetRef.Name)
						ep.Weight = 0
					}
				}
			}
		}
	}
	if c.globalConfig.DrainSupport {
		pods, err := c.cache.GetTerminatingPods(svc)
		if err != nil {
			return err
		}
		for _, pod := range pods {
			ep := backend.NewEndpoint(pod.Status.PodIP, svcPort.IntValue(), pod.Namespace+"/"+pod.Name)
			ep.Weight = 0
		}
	}
	return nil
}

func (c *converter) readAnnotations(annotations map[string]string) (annHost, annBack map[string]string) {
	annHost = make(map[string]string, len(annotations))
	annBack = make(map[string]string, len(annotations))
	prefix := c.options.AnnotationPrefix + "/"
	for annName, annValue := range annotations {
		if strings.HasPrefix(annName, prefix) {
			name := strings.TrimPrefix(annName, prefix)
			if _, isHostAnn := ingtypes.AnnHost[name]; isHostAnn {
				annHost[name] = annValue
			} else {
				annBack[name] = annValue
			}
		}
	}
	return annHost, annBack
}

func readServiceNamePort(backend *extensions.IngressBackend) (string, string) {
	serviceName := backend.ServiceName
	servicePort := backend.ServicePort.String()
	return serviceName, servicePort
}

func mergeMaps(dst, src map[string]string) map[string]string {
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func mergeConfig(configDefault *ingtypes.ConfigGlobals, config map[string]string) *ingtypes.ConfigGlobals {
	utils.MergeMap(config, configDefault)
	return configDefault
}
