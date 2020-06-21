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
	"reflect"
	"sort"
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
	Sync()
}

// NewIngressConverter ...
func NewIngressConverter(options *ingtypes.ConverterOptions, haproxy haproxy.Config) Config {
	if options.DefaultConfig == nil {
		options.DefaultConfig = createDefaults
	}
	changed := options.Cache.SwapChangedObjects()
	// IMPLEMENT
	// config option to allow partial parsing
	// cache also need to know if partial parsing is enabled
	needFullSync := options.Cache.NeedFullSync() || globalConfigNeedFullSync(changed)
	globalConfig := changed.GlobalCur
	if changed.GlobalNew != nil {
		globalConfig = changed.GlobalNew
	}
	defaultConfig := options.DefaultConfig()
	for key, value := range globalConfig {
		defaultConfig[key] = value
	}
	return &converter{
		haproxy:            haproxy,
		options:            options,
		changed:            changed,
		logger:             options.Logger,
		cache:              options.Cache,
		tracker:            options.Tracker,
		mapBuilder:         annotations.NewMapBuilder(options.Logger, options.AnnotationPrefix+"/", defaultConfig),
		updater:            annotations.NewUpdater(haproxy, options),
		globalConfig:       annotations.NewMapBuilder(options.Logger, "", defaultConfig).NewMapper(),
		hostAnnotations:    map[*hatypes.Host]*annotations.Mapper{},
		backendAnnotations: map[*hatypes.Backend]*annotations.Mapper{},
		needFullSync:       needFullSync,
	}
}

type converter struct {
	haproxy            haproxy.Config
	options            *ingtypes.ConverterOptions
	changed            *convtypes.ChangedObjects
	logger             types.Logger
	cache              convtypes.Cache
	tracker            convtypes.Tracker
	mapBuilder         *annotations.MapBuilder
	updater            annotations.Updater
	globalConfig       *annotations.Mapper
	hostAnnotations    map[*hatypes.Host]*annotations.Mapper
	backendAnnotations map[*hatypes.Backend]*annotations.Mapper
	needFullSync       bool
}

func (c *converter) Sync() {
	if c.needFullSync {
		c.haproxy.Clear()
	}
	c.haproxy.Frontend().DefaultCert = c.options.DefaultSSLFile.Filename
	if c.options.DefaultBackend != "" {
		if backend, err := c.addBackend(&annotations.Source{}, "*", "/", c.options.DefaultBackend, "", map[string]string{}); err == nil {
			c.haproxy.Backends().SetDefaultBackend(backend)
		} else {
			c.logger.Error("error reading default service: %v", err)
		}
	}
	if c.needFullSync {
		c.syncFull()
	} else {
		c.syncPartial()
	}
}

func globalConfigNeedFullSync(changed *convtypes.ChangedObjects) bool {
	// Currently if a global is changed, all the ingress objects are parsed again.
	// This need to be done due to:
	//
	//   1. Default host and backend annotations. If a default value
	//      changes, such default may impact any ingress object;
	//   2. At the time of this writing, the following global
	//      configuration keys are used during annotation parsing:
	//        * GlobalDNSResolvers
	//        * GlobalDrainSupport
	//        * GlobalNoTLSRedirectLocations
	//
	// This might be improved after implement a way to guarantee that a global
	// is just a haproxy global, default or frontend config.
	cur, new := changed.GlobalCur, changed.GlobalNew
	return new != nil && !reflect.DeepEqual(cur, new)
}

func (c *converter) syncFull() {
	ingList, err := c.cache.GetIngressList()
	if err != nil {
		c.logger.Error("error reading ingress list: %v", err)
		return
	}
	sortIngress(ingList)
	for _, ing := range ingList {
		c.syncIngress(ing)
	}
	c.fullSyncAnnotations()
}

func (c *converter) syncPartial() {
	// conventions:
	//
	//   * del, upd, add: events from the listers
	//   * old, new:      old state (deleted, before change) and new state (after change, added)
	//   * dirty:         has impact due to a direct or indirect change
	//

	// helper funcs
	ing2names := func(ings []*extensions.Ingress) []string {
		inglist := make([]string, len(ings))
		for i, ing := range ings {
			inglist[i] = ing.Namespace + "/" + ing.Name
		}
		return inglist
	}
	svc2names := func(services []*api.Service) []string {
		serviceList := make([]string, len(services))
		for i, service := range services {
			serviceList[i] = service.Namespace + "/" + service.Name
		}
		return serviceList
	}
	ep2names := func(endpoints []*api.Endpoints) []string {
		epList := make([]string, len(endpoints))
		for i, ep := range endpoints {
			epList[i] = ep.Namespace + "/" + ep.Name
		}
		return epList
	}
	secret2names := func(secrets []*api.Secret) []string {
		secretList := make([]string, len(secrets))
		for i, secret := range secrets {
			secretList[i] = secret.Namespace + "/" + secret.Name
		}
		return secretList
	}

	// remove changed/deleted data
	delIngNames := ing2names(c.changed.IngressesDel)
	updIngNames := ing2names(c.changed.IngressesUpd)
	oldIngNames := append(delIngNames, updIngNames...)
	delSvcNames := svc2names(c.changed.ServicesDel)
	updSvcNames := svc2names(c.changed.ServicesUpd)
	addSvcNames := svc2names(c.changed.ServicesAdd)
	oldSvcNames := append(delSvcNames, updSvcNames...)
	updEndpointsNames := ep2names(c.changed.Endpoints)
	oldSvcNames = append(oldSvcNames, updEndpointsNames...)
	delSecretNames := secret2names(c.changed.SecretsDel)
	updSecretNames := secret2names(c.changed.SecretsUpd)
	addSecretNames := secret2names(c.changed.SecretsAdd)
	oldSecretNames := append(delSecretNames, updSecretNames...)
	dirtyIngs, dirtyHosts, dirtyBacks :=
		c.tracker.GetDirtyLinks(oldIngNames, oldSvcNames, addSvcNames, oldSecretNames, addSecretNames)
	c.tracker.DeleteHostnames(dirtyHosts)
	c.tracker.DeleteBackends(dirtyBacks)
	c.haproxy.Hosts().RemoveAll(dirtyHosts)
	c.haproxy.Backends().RemoveAll(dirtyBacks)
	if len(dirtyHosts) > 0 || len(dirtyBacks) > 0 {
		c.logger.InfoV(2, "changed hosts: %v; backends: %v", dirtyHosts, dirtyBacks)
	}

	// merge dirty and added ingress objects into a single list
	ingMap := make(map[string]*extensions.Ingress)
	for _, ing := range dirtyIngs {
		ingMap[ing] = nil
	}
	for _, ing := range delIngNames {
		delete(ingMap, ing)
	}
	for _, ing := range c.changed.IngressesAdd {
		ingMap[ing.Namespace+"/"+ing.Name] = ing
	}
	ingList := make([]*extensions.Ingress, 0, len(ingMap))
	for name, ing := range ingMap {
		if ing == nil {
			var err error
			ing, err = c.cache.GetIngress(name)
			if err != nil {
				c.logger.Warn("ignoring ingress '%s': %v", name, err)
				ing = nil
			}
		}
		if ing != nil {
			ingList = append(ingList, ing)
		}
	}

	// reinclude changed/added data
	sortIngress(ingList)
	for _, ing := range ingList {
		c.syncIngress(ing)
	}
	if c.globalConfig.Get(ingtypes.GlobalDrainSupport).Bool() {
		for _, pod := range c.changed.Pods {
			if err := c.applyPod(pod); err != nil {
				c.logger.Warn("skipping apply pod '%s/%s' update: %v", pod.Namespace, pod.Name, err)
			}
		}
	}
	c.partialSyncAnnotations(dirtyHosts, dirtyBacks)
}

func sortIngress(ingress []*extensions.Ingress) {
	sort.Slice(ingress, func(i, j int) bool {
		i1 := ingress[i]
		i2 := ingress[j]
		if i1.CreationTimestamp != i2.CreationTimestamp {
			return i1.CreationTimestamp.Before(&i2.CreationTimestamp)
		}
		return i1.Namespace+"/"+i1.Name < i2.Namespace+"/"+i2.Name
	})
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
			backend, err := c.addBackend(source, hostname, uri, fullSvcName, svcPort, annBack)
			if err != nil {
				c.logger.Warn("skipping backend config of ingress '%s': %v", fullIngName, err)
				continue
			}
			host.AddPath(backend, uri)
			sslpassthrough, _ := strconv.ParseBool(annHost[ingtypes.HostSSLPassthrough])
			sslpasshttpport := annHost[ingtypes.HostSSLPassthroughHTTPPort]
			if sslpassthrough && sslpasshttpport != "" {
				if _, err := c.addBackend(source, hostname, uri, fullSvcName, sslpasshttpport, annBack); err != nil {
					c.logger.Warn("skipping http port config of ssl-passthrough on %v: %v", source, err)
				}
			}
		}
		for _, tls := range ing.Spec.TLS {
			for _, tlshost := range tls.Hosts {
				if tlshost == hostname {
					tlsPath := c.addTLS(source, tlshost, tls.SecretName)
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

func (c *converter) fullSyncAnnotations() {
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

func (c *converter) partialSyncAnnotations(hosts []string, backends []hatypes.BackendID) {
	for _, hostname := range hosts {
		host := c.haproxy.Hosts().FindHost(hostname)
		if ann, found := c.hostAnnotations[host]; found {
			c.updater.UpdateHostConfig(host, ann)
		}
	}
	for _, backendID := range backends {
		backend := c.haproxy.Backends().FindBackendID(backendID)
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
	backend, err := c.addBackend(source, hostname, uri, fullSvcName, svcPort, annBack)
	if err != nil {
		return err
	}
	host := c.addHost(hostname, source, annHost)
	host.AddPath(backend, uri)
	return nil
}

func (c *converter) addHost(hostname string, source *annotations.Source, ann map[string]string) *hatypes.Host {
	// TODO build a stronger tracking
	host := c.haproxy.Hosts().AcquireHost(hostname)
	c.tracker.TrackHostname(convtypes.IngressType, source.FullName(), hostname)
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

func (c *converter) addBackend(source *annotations.Source, hostname, uri, fullSvcName, svcPort string, ann map[string]string) (*hatypes.Backend, error) {
	// TODO build a stronger tracking
	svc, err := c.cache.GetService(fullSvcName)
	if err != nil {
		c.tracker.TrackMissingOnHostname(convtypes.ServiceType, fullSvcName, hostname)
		return nil, err
	}
	c.tracker.TrackHostname(convtypes.ServiceType, fullSvcName, hostname)
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
	c.tracker.TrackBackend(convtypes.IngressType, source.FullName(), backend.BackendID())
	hostpath := hostname + uri
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

func (c *converter) addTLS(source *annotations.Source, hostname, secretName string) convtypes.CrtFile {
	if secretName != "" {
		fullName := secretName
		if strings.Index(secretName, "/") == -1 {
			fullName = source.Namespace + "/" + secretName
		}
		tlsFile, err := c.cache.GetTLSSecretPath(source.Namespace, secretName)
		if err == nil {
			c.tracker.TrackHostname(convtypes.SecretType, fullName, hostname)
			return tlsFile
		}
		c.tracker.TrackMissingOnHostname(convtypes.SecretType, fullName, hostname)
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

func (c *converter) applyPod(pod *api.Pod) error {
	// IMPLEMENT
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
