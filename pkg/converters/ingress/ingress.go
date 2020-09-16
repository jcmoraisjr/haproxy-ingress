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
	networking "k8s.io/api/networking/v1beta1"

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
	defaultCrt         convtypes.CrtFile
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
	c.syncDefaultCrt()
	c.syncDefaultBackend()
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

func (c *converter) syncDefaultCrt() {
	crt := c.options.FakeCrtFile
	if c.options.DefaultCrtSecret != "" {
		var err error
		crt, err = c.cache.GetTLSSecretPath("", c.options.DefaultCrtSecret, convtypes.TrackingTarget{})
		if err != nil {
			crt = c.options.FakeCrtFile
			c.logger.Warn("using auto generated fake certificate due to an error reading default TLS certificate: %v", err)
		}
	}
	frontend := c.haproxy.Frontend()
	if !c.needFullSync {
		if frontend.DefaultCrtFile != crt.Filename || frontend.DefaultCrtHash != crt.SHA1Hash {
			// TODO implement a proper secret tracking and partial sync
			c.haproxy.Clear()
			frontend = c.haproxy.Frontend() // Clear() recreates internal objects
			c.needFullSync = true
		}
	}
	if c.needFullSync && crt == c.options.FakeCrtFile {
		c.logger.Info("using auto generated fake certificate")
	}
	frontend.DefaultCrtFile = crt.Filename
	frontend.DefaultCrtHash = crt.SHA1Hash
	c.defaultCrt = crt
}

func (c *converter) syncDefaultBackend() {
	if c.options.DefaultBackend != "" {
		if backend, err := c.addBackend(&annotations.Source{}, hatypes.DefaultHost, "/", c.options.DefaultBackend, "", map[string]string{}); err == nil {
			c.haproxy.Backends().SetDefaultBackend(backend)
		} else {
			c.logger.Error("error reading default service: %v", err)
		}
	}
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
	c.syncEndpointCookies()
}

func (c *converter) syncPartial() {
	// conventions:
	//
	//   * del, upd, add: events from the listers
	//   * old, new:      old state (deleted, before change) and new state (after change, added)
	//   * dirty:         has impact due to a direct or indirect change
	//

	// helper funcs
	ing2names := func(ings []*networking.Ingress) []string {
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
	pod2names := func(pods []*api.Pod) []string {
		podList := make([]string, len(pods))
		for i, pod := range pods {
			podList[i] = pod.Namespace + "/" + pod.Name
		}
		return podList
	}

	if len(c.changed.Objects) > 0 {
		c.logger.InfoV(2, "applying %d change notification(s): %v", len(c.changed.Objects), c.changed.Objects)
	}

	// remove changed/deleted data
	delIngNames := ing2names(c.changed.IngressesDel)
	updIngNames := ing2names(c.changed.IngressesUpd)
	addIngNames := ing2names(c.changed.IngressesAdd)
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
	addPodNames := pod2names(c.changed.Pods)
	c.trackAddedIngress()
	dirtyIngs, dirtyHosts, dirtyBacks, dirtyUsers, dirtyStorages :=
		c.tracker.GetDirtyLinks(oldIngNames, addIngNames, oldSvcNames, addSvcNames, oldSecretNames, addSecretNames, addPodNames)
	c.tracker.DeleteHostnames(dirtyHosts)
	c.tracker.DeleteBackends(dirtyBacks)
	c.tracker.DeleteUserlists(dirtyUsers)
	c.tracker.DeleteStorages(dirtyStorages)
	c.haproxy.Hosts().RemoveAll(dirtyHosts)
	c.haproxy.Backends().RemoveAll(dirtyBacks)
	c.haproxy.Userlists().RemoveAll(dirtyUsers)
	c.haproxy.AcmeData().Storages().RemoveAll(dirtyStorages)
	c.logger.InfoV(2, "syncing %d host(s) and %d backend(s)", len(dirtyHosts), len(dirtyBacks))

	// merge dirty and added ingress objects into a single list
	ingMap := make(map[string]*networking.Ingress)
	for _, ing := range dirtyIngs {
		ingMap[ing] = nil
	}
	for _, ing := range delIngNames {
		delete(ingMap, ing)
	}
	for _, ing := range c.changed.IngressesAdd {
		ingMap[ing.Namespace+"/"+ing.Name] = ing
	}
	ingList := make([]*networking.Ingress, 0, len(ingMap))
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
	c.partialSyncAnnotations()
	c.syncChangedEndpointCookies()
}

// trackAddedIngress add tracking hostnames and backends to new ingress objects
//
// All state change works removing hosts and backs objects in an old state and
// resyncing ingress objects to recreate hosts and backs in a new state. This
// works very well, except with new ingress objects that references hosts or
// backs that already exist - all the tracking starts from the ingress parsing.
//
// trackAddedIngress does the same tracking the sync ingress already do, but
// before real sync starts and just before calculate dirty objects - if an
// existent host or back is tracked only by an added ingress, it is tracked
// here and removed before parse the added ingress which will readd such hosts
// and backs
func (c *converter) trackAddedIngress() {
	for _, ing := range c.changed.IngressesAdd {
		name := ing.Namespace + "/" + ing.Name
		if ing.Spec.Backend != nil {
			backend := c.findBackend(ing.Namespace, ing.Spec.Backend)
			if backend != nil {
				c.tracker.TrackBackend(convtypes.IngressType, name, backend.BackendID())
			}
		}
		for _, rule := range ing.Spec.Rules {
			c.tracker.TrackHostname(convtypes.IngressType, name, rule.Host)
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					backend := c.findBackend(ing.Namespace, &path.Backend)
					if backend != nil {
						c.tracker.TrackBackend(convtypes.IngressType, name, backend.BackendID())
					}
				}
			}
		}
	}
}

func (c *converter) findBackend(namespace string, backend *networking.IngressBackend) *hatypes.Backend {
	svcName, svcPort := readServiceNamePort(backend)
	fullSvcName := namespace + "/" + svcName
	svc, err := c.cache.GetService(fullSvcName)
	if err != nil {
		return nil
	}
	port := convutils.FindServicePort(svc, svcPort)
	if port == nil {
		return nil
	}
	return c.haproxy.Backends().FindBackend(namespace, svcName, port.TargetPort.String())
}

func sortIngress(ingress []*networking.Ingress) {
	sort.Slice(ingress, func(i, j int) bool {
		i1 := ingress[i]
		i2 := ingress[j]
		if i1.CreationTimestamp != i2.CreationTimestamp {
			return i1.CreationTimestamp.Before(&i2.CreationTimestamp)
		}
		return i1.Namespace+"/"+i1.Name < i2.Namespace+"/"+i2.Name
	})
}

func (c *converter) syncIngress(ing *networking.Ingress) {
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
			hostname = hatypes.DefaultHost
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
			match := c.readPathType(path, annHost[ingtypes.HostPathType])
			host.AddPath(backend, uri, match)
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
				secretName := ing.Namespace + "/" + tls.SecretName
				c.haproxy.AcmeData().Storages().Acquire(secretName).AddDomains(tls.Hosts)
				c.tracker.TrackStorage(convtypes.IngressType, fullIngName, secretName)
			} else {
				c.logger.Warn("skipping cert signer of ingress '%s': missing secret name", fullIngName)
			}
		}
	}
}

func (c *converter) syncEndpointCookies() {
	for _, backend := range c.haproxy.Backends().Items() {
		c.syncBackendEndpointCookies(backend)
	}
}

func (c *converter) syncChangedEndpointCookies() {
	for _, backend := range c.haproxy.Backends().ItemsAdd() {
		c.syncBackendEndpointCookies(backend)
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

func (c *converter) partialSyncAnnotations() {
	for _, host := range c.haproxy.Hosts().ItemsAdd() {
		if ann, found := c.hostAnnotations[host]; found {
			c.updater.UpdateHostConfig(host, ann)
		}
	}
	for _, backend := range c.haproxy.Backends().ItemsAdd() {
		if ann, found := c.backendAnnotations[backend]; found {
			c.updater.UpdateBackendConfig(backend, ann)
		}
	}
}

func (c *converter) readPathType(path networking.HTTPIngressPath, ann string) hatypes.MatchType {
	match := hatypes.MatchBegin
	pathType := networking.PathTypeImplementationSpecific
	if path.PathType != nil {
		pathType = *path.PathType
	}
	switch pathType {
	case networking.PathTypeExact:
		match = hatypes.MatchExact
	case networking.PathTypePrefix:
		match = hatypes.MatchPrefix
	default:
		matchStr := strings.ToLower(ann)
		switch matchStr {
		case "", "begin":
			match = hatypes.MatchBegin
		case "prefix":
			match = hatypes.MatchPrefix
		case "exact":
			match = hatypes.MatchExact
		case "regex":
			match = hatypes.MatchRegex
		default:
			c.logger.Warn("unsupported path-type '%s', using 'begin' instead.", matchStr)
		}
		if pathType != networking.PathTypeImplementationSpecific {
			c.logger.Warn("unsupported '%s' pathType from ingress spec, using '%s' instead.",
				pathType, networking.PathTypeImplementationSpecific)
		}
	}
	return match
}

func (c *converter) addDefaultHostBackend(source *annotations.Source, fullSvcName, svcPort string, annHost, annBack map[string]string) error {
	hostname := hatypes.DefaultHost
	uri := "/"
	if fr := c.haproxy.Hosts().FindHost(hostname); fr != nil {
		if fr.FindPath(uri) != nil {
			return fmt.Errorf("path %s was already defined on default host", uri)
		}
	}
	backend, err := c.addBackend(source, hostname, uri, fullSvcName, svcPort, annBack)
	if err != nil {
		c.tracker.TrackHostname(convtypes.IngressType, source.FullName(), hostname)
		return err
	}
	host := c.addHost(hostname, source, annHost)
	host.AddPath(backend, uri, hatypes.MatchBegin)
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
	conflict := mapper.AddAnnotations(source, hatypes.CreatePathLink(hostname, "/"), ann)
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
	pathlink := hatypes.CreatePathLink(hostname, uri)
	mapper, found := c.backendAnnotations[backend]
	if !found {
		// New backend, initialize with service annotations, giving precedence
		mapper = c.mapBuilder.NewMapper()
		_, ann := c.readAnnotations(svc.Annotations)
		mapper.AddAnnotations(&annotations.Source{
			Namespace: namespace,
			Name:      svcName,
			Type:      "service",
		}, pathlink, ann)
		c.backendAnnotations[backend] = mapper
		backend.Server.InitialWeight = mapper.Get(ingtypes.BackInitialWeight).Int()
	}
	// Merging Ingress annotations
	conflict := mapper.AddAnnotations(source, pathlink, ann)
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

func (c *converter) syncBackendEndpointCookies(backend *hatypes.Backend) {
	cookieAffinity := backend.CookieAffinity()
	for _, ep := range backend.Endpoints {
		if cookieAffinity {
			switch backend.EpCookieStrategy {
			default:
				ep.CookieValue = ep.Name
			case hatypes.EpCookiePodUid:
				if ep.TargetRef != "" {
					pod, err := c.cache.GetPod(ep.TargetRef)
					if err == nil {
						ep.CookieValue = fmt.Sprintf("%v", pod.UID)
					} else {
						c.logger.Error("error calculating cookie value for pod %s: %v", ep.TargetRef, err)
					}
				}
			}
		}
	}
}

func (c *converter) addTLS(source *annotations.Source, hostname, secretName string) convtypes.CrtFile {
	if secretName != "" {
		tlsFile, err := c.cache.GetTLSSecretPath(
			source.Namespace,
			secretName,
			convtypes.TrackingTarget{Hostname: hostname},
		)
		if err == nil {
			return tlsFile
		}
		c.logger.Warn("using default certificate due to an error reading secret '%s' on %s: %v", secretName, source, err)
	}
	return c.defaultCrt
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
		pods, err := c.cache.GetTerminatingPods(svc, convtypes.TrackingTarget{Backend: backend.BackendID()})
		if err != nil {
			return fmt.Errorf("cannot fetch terminating pods on drain-support mode: %v", err)
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

func readServiceNamePort(backend *networking.IngressBackend) (string, string) {
	serviceName := backend.ServiceName
	servicePort := backend.ServicePort.String()
	return serviceName, servicePort
}
