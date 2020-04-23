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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/annotations"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
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
	defaultConfig := options.DefaultConfig()
	for key, value := range globalConfig {
		defaultConfig[key] = value
	}
	c := &converter{
		haproxy:            haproxy,
		options:            options,
		logger:             options.Logger,
		cache:              options.Cache,
		mapBuilder:         annotations.NewMapBuilder(options.Logger, options.AnnotationPrefix+"/", defaultConfig),
		updater:            annotations.NewUpdater(haproxy, options),
		globalConfig:       annotations.NewMapBuilder(options.Logger, "", defaultConfig).NewMapper(),
		hostAnnotations:    map[*hatypes.Host]*annotations.Mapper{},
		backendAnnotations: map[*hatypes.Backend]*annotations.Mapper{},
	}
	haproxy.Frontend().DefaultCert = options.DefaultSSLFile.Filename
	if options.DefaultBackend != "" {
		if backend, err := c.addBackend(&annotations.Source{}, "*/", options.DefaultBackend, "", map[string]string{}); err == nil {
			haproxy.Backends().SetDefaultBackend(backend)
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
	cache              convtypes.Cache
	mapBuilder         *annotations.MapBuilder
	updater            annotations.Updater
	globalConfig       *annotations.Mapper
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
		err := c.addDefaultHostBackend(source, ing.Namespace+"/"+svcName, svcPort, annHost, annBack)
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
			fullSvcName := ing.Namespace + "/" + svcName
			backend, err := c.addBackend(source, hostname+uri, fullSvcName, svcPort, annBack)
			if err != nil {
				c.logger.Warn("skipping backend config of ingress '%s': %v", fullIngName, err)
				continue
			}
			host.AddPath(backend, uri)
			sslpassthrough, _ := strconv.ParseBool(annHost[ingtypes.HostSSLPassthrough])
			sslpasshttpport := annHost[ingtypes.HostSSLPassthroughHTTPPort]
			if sslpassthrough && sslpasshttpport != "" {
				if _, err := c.addBackend(source, hostname+uri, fullSvcName, sslpasshttpport, annBack); err != nil {
					c.logger.Warn("skipping http port config of ssl-passthrough on %v: %v", source, err)
				}
			}
		}
		for _, tls := range ing.Spec.TLS {
			for _, tlshost := range tls.Hosts {
				if tlshost == hostname {
					tlsPath := c.addTLS(source, tls.SecretName)
					if host.TLS.TLSHash == "" {
						host.TLS.TLSFilename = tlsPath.Filename
						host.TLS.TLSHash = tlsPath.SHA1Hash
						host.TLS.TLSCommonName = tlsPath.CommonName
						host.TLS.TLSNotAfter = tlsPath.NotAfter
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
	for _, tls := range ing.Spec.TLS {
		// distinct prefix, read from the Annotations map
		var tlsAcme bool
		if c.options.AcmeTrackTLSAnn {
			tlsAcmeStr, _ := ing.Annotations[ingtypes.ExtraTLSAcme]
			tlsAcme, _ = strconv.ParseBool(tlsAcmeStr)
		}
		if !tlsAcme {
			tlsAcme = strings.ToLower(annHost[ingtypes.HostCertSigner]) == "acme"
		}
		if tlsAcme {
			if tls.SecretName != "" {
				c.haproxy.AcmeData().AddDomains(ing.Namespace+"/"+tls.SecretName, tls.Hosts)
			} else {
				c.logger.Warn("skipping cert signer of ingress '%s': missing secret name", fullIngName)
			}
		}
	}
}

func (c *converter) syncAnnotations() {
	c.updater.UpdateGlobalConfig(c.haproxy, c.globalConfig)
	for _, host := range c.haproxy.Hosts().Items() {
		if ann, found := c.hostAnnotations[host]; found {
			c.updater.UpdateHostConfig(host, ann)
		}
	}
	for _, backend := range c.haproxy.Backends().Items() {
		if ann, found := c.backendAnnotations[backend]; found {
			c.updater.UpdateBackendConfig(backend, ann)
		}
	}
}

func (c *converter) addDefaultHostBackend(source *annotations.Source, fullSvcName, svcPort string, annHost, annBack map[string]string) error {
	hostname := "*"
	uri := "/"
	if fr := c.haproxy.Hosts().FindHost(hostname); fr != nil {
		if fr.FindPath(uri) != nil {
			return fmt.Errorf("path %s was already defined on default host", uri)
		}
	}
	backend, err := c.addBackend(source, hostname+uri, fullSvcName, svcPort, annBack)
	if err != nil {
		return err
	}
	host := c.addHost(hostname, source, annHost)
	host.AddPath(backend, uri)
	return nil
}

func (c *converter) addHost(hostname string, source *annotations.Source, ann map[string]string) *hatypes.Host {
	host := c.haproxy.Hosts().AcquireHost(hostname)
	mapper, found := c.hostAnnotations[host]
	if !found {
		mapper = c.mapBuilder.NewMapper()
		c.hostAnnotations[host] = mapper
	}
	conflict := mapper.AddAnnotations(source, hostname+"/", ann)
	if len(conflict) > 0 {
		c.logger.Warn("skipping host annotation(s) from %v due to conflict: %v", source, conflict)
	}
	return host
}

func (c *converter) addBackend(source *annotations.Source, hostpath, fullSvcName, svcPort string, ann map[string]string) (*hatypes.Backend, error) {
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
	port := convutils.FindServicePort(svc, svcPort)
	if port == nil {
		return nil, fmt.Errorf("port not found: '%s'", svcPort)
	}
	backend := c.haproxy.Backends().AcquireBackend(namespace, svcName, port.TargetPort.String())
	mapper, found := c.backendAnnotations[backend]
	if !found {
		// New backend, initialize with service annotations, giving precedence
		mapper = c.mapBuilder.NewMapper()
		_, ann := c.readAnnotations(svc.Annotations)
		mapper.AddAnnotations(&annotations.Source{
			Namespace: namespace,
			Name:      svcName,
			Type:      "service",
		}, hostpath, ann)
		c.backendAnnotations[backend] = mapper
		backend.Server.InitialWeight = mapper.Get(ingtypes.BackInitialWeight).Int()
	}
	// Merging Ingress annotations
	conflict := mapper.AddAnnotations(source, hostpath, ann)
	if len(conflict) > 0 {
		c.logger.Warn("skipping backend '%s:%s' annotation(s) from %v due to conflict: %v",
			svcName, svcPort, source, conflict)
	}
	// Configure endpoints
	if !found {
		switch mapper.Get(ingtypes.BackBackendServerNaming).Value {
		case "ip":
			backend.EpNaming = hatypes.EpIPPort
		case "pod":
			backend.EpNaming = hatypes.EpTargetRef
		default:
			backend.EpNaming = hatypes.EpSequence
		}
		if mapper.Get(ingtypes.BackServiceUpstream).Bool() {
			if addr, err := convutils.CreateSvcEndpoint(svc, port); err == nil {
				backend.AcquireEndpoint(addr.IP, addr.Port, addr.TargetRef)
			} else {
				c.logger.Error("error adding IP of service '%s': %v", fullSvcName, err)
			}
		} else {
			if err := c.addEndpoints(svc, port, backend); err != nil {
				c.logger.Error("error adding endpoints of service '%s': %v", fullSvcName, err)
			}
		}
	}
	return backend, nil
}

func (c *converter) addTLS(source *annotations.Source, secretName string) convtypes.CrtFile {
	if secretName != "" {
		tlsFile, err := c.cache.GetTLSSecretPath(source.Namespace, secretName)
		if err == nil {
			return tlsFile
		}
		c.logger.Warn("using default certificate due to an error reading secret '%s' on %s: %v", secretName, source, err)
	}
	return c.options.DefaultSSLFile
}

func (c *converter) addEndpoints(svc *api.Service, svcPort *api.ServicePort, backend *hatypes.Backend) error {
	ready, notReady, err := convutils.CreateEndpoints(c.cache, svc, svcPort)
	if err != nil {
		return err
	}
	for _, addr := range ready {
		backend.AcquireEndpoint(addr.IP, addr.Port, addr.TargetRef)
	}
	if c.globalConfig.Get(ingtypes.GlobalDrainSupport).Bool() {
		for _, addr := range notReady {
			ep := backend.AcquireEndpoint(addr.IP, addr.Port, addr.TargetRef)
			ep.Weight = 0
		}
		pods, err := c.cache.GetTerminatingPods(svc)
		if err != nil {
			return err
		}
		for _, pod := range pods {
			targetPort := convutils.FindContainerPort(pod, svcPort)
			if targetPort > 0 {
				ep := backend.AcquireEndpoint(pod.Status.PodIP, targetPort, pod.Namespace+"/"+pod.Name)
				ep.Weight = 0
			} else {
				c.logger.Warn("skipping endpoint %s of service %s/%s: port '%s' was not found",
					pod.Status.PodIP, svc.Namespace, svc.Name, svcPort.TargetPort.String())
			}
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
