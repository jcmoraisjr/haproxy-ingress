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
	networking "k8s.io/api/networking/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/annotations"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	ingutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/utils"
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
		defaultBackSource:  annotations.Source{Name: "<default-backend>", Type: "ingress"},
		mapBuilder:         annotations.NewMapBuilder(options.Logger, options.AnnotationPrefix+"/", defaultConfig),
		updater:            annotations.NewUpdater(haproxy, options),
		globalConfig:       annotations.NewMapBuilder(options.Logger, "", defaultConfig).NewMapper(),
		tcpsvcAnnotations:  map[*hatypes.TCPServicePort]*annotations.Mapper{},
		hostAnnotations:    map[*hatypes.Host]*annotations.Mapper{},
		backendAnnotations: map[*hatypes.Backend]*annotations.Mapper{},
		ingressClasses:     map[string]*ingressClassConfig{},
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
	defaultBackSource  annotations.Source
	mapBuilder         *annotations.MapBuilder
	updater            annotations.Updater
	globalConfig       *annotations.Mapper
	tcpsvcAnnotations  map[*hatypes.TCPServicePort]*annotations.Mapper
	hostAnnotations    map[*hatypes.Host]*annotations.Mapper
	backendAnnotations map[*hatypes.Backend]*annotations.Mapper
	ingressClasses     map[string]*ingressClassConfig
	needFullSync       bool
}

type ingressClassConfig struct {
	resourceType convtypes.ResourceType
	resourceName string
	config       map[string]string
}

func (c *converter) Sync() {
	if c.needFullSync {
		c.haproxy.Clear()
	}
	c.syncDefaultCrt()
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
		if backend, err := c.addBackend(&c.defaultBackSource, hatypes.DefaultHost, "/", c.options.DefaultBackend, "", map[string]string{}); err == nil {
			c.haproxy.Backends().DefaultBackend = backend
			c.tracker.TrackHostname(convtypes.IngressType, c.defaultBackSource.FullName(), hatypes.DefaultHost)
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
	c.syncDefaultBackend()
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
	cls2names := func(clss []*networking.IngressClass) []string {
		clslist := make([]string, len(clss))
		for i, cls := range clss {
			clslist[i] = cls.Name
		}
		return clslist
	}
	cm2names := func(cms []*api.ConfigMap) []string {
		cmlist := make([]string, len(cms))
		for i, cm := range cms {
			cmlist[i] = cm.Namespace + "/" + cm.Name
		}
		return cmlist
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
	delClsNames := cls2names(c.changed.IngressClassesDel)
	updClsNames := cls2names(c.changed.IngressClassesUpd)
	addClsNames := cls2names(c.changed.IngressClassesAdd)
	oldClsNames := append(delClsNames, updClsNames...)
	delCMNames := cm2names(c.changed.ConfigMapsDel)
	updCMNames := cm2names(c.changed.ConfigMapsUpd)
	addCMNames := cm2names(c.changed.ConfigMapsAdd)
	oldCMNames := append(delCMNames, updCMNames...)
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
		c.tracker.GetDirtyLinks(
			oldIngNames, addIngNames,
			oldClsNames, addClsNames,
			oldCMNames, addCMNames,
			oldSvcNames, addSvcNames,
			oldSecretNames, addSecretNames,
			addPodNames,
		)
	c.tracker.DeleteHostnames(dirtyHosts)
	c.tracker.DeleteBackends(dirtyBacks)
	c.tracker.DeleteUserlists(dirtyUsers)
	c.tracker.DeleteStorages(dirtyStorages)

	// TCP services are currently in the host list due to how tracking is
	// currently implemented. This is not a good solution because of their scopes -
	// hosts and TCP services are managed by distinct entities in the haproxy model
	//
	// TODO Create a new tracker for services or another way to clean/remove
	//      backends during service updates. See also normalizeHostname()
	var dirtyTCPServices []string
	dirtyHosts, dirtyTCPServices = splitHostsAndTCPServices(dirtyHosts)
	c.haproxy.TCPServices().RemoveAll(dirtyTCPServices)
	c.haproxy.Hosts().RemoveAll(dirtyHosts)
	c.haproxy.Frontend().RemoveAuthBackendByTarget(dirtyBacks)
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
				if name == c.defaultBackSource.FullName() {
					c.syncDefaultBackend()
				} else {
					c.logger.Warn("ignoring ingress '%s': %v", name, err)
				}
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
		if ing.Spec.DefaultBackend != nil {
			backend := c.findBackend(ing.Namespace, ing.Spec.DefaultBackend)
			if backend != nil {
				c.tracker.TrackBackend(convtypes.IngressType, name, backend.BackendID())
			}
		}
		port, _ := strconv.Atoi(ing.Annotations[c.options.AnnotationPrefix+"/"+ingtypes.TCPTCPServicePort])
		for _, rule := range ing.Spec.Rules {
			c.tracker.TrackHostname(convtypes.IngressType, name, normalizeHostname(rule.Host, port))
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
	svcName, svcPort, err := readServiceNamePort(backend)
	if err != nil {
		return nil
	}
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

// normalizeHostname adjusts the hostname according to the following rules:
//
//  * empty hostnames are changed to `hatypes.DefaultHost` which has a
//    special meaning in the hosts entity
//  * hostnames for tcp services receive the port number to distinguish
//    two tcp services without hostname. hostnames are preserved, making it
//    a bit easier to introduce sni based routing.
//
// Hostnames are used as the tracking ID by backends and secrets. This design
// must be revisited - either evolving the tracking system, or abstracting
// how backends and secrets are tracked, or removing the tracking at all.
func normalizeHostname(hostname string, port int) string {
	if hostname == "" {
		hostname = hatypes.DefaultHost
	}
	if port > 0 {
		return hostname + ":" + strconv.Itoa(port)
	}
	return hostname
}

func splitHostsAndTCPServices(hostnames []string) (hosts, tcpServices []string) {
	hosts = make([]string, 0, len(hostnames))
	for _, h := range hostnames {
		if strings.Index(h, ":") >= 0 {
			tcpServices = append(tcpServices, h)
		} else {
			hosts = append(hosts, h)
		}
	}
	return hosts, tcpServices
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
	annTCP, annHost, annBack := c.readAnnotations(ing.Annotations)
	tcpServicePort, _ := strconv.Atoi(annTCP[ingtypes.TCPTCPServicePort])
	if tcpServicePort == 0 {
		c.syncIngressHTTP(ing, annHost, annBack)
	} else {
		c.syncIngressTCP(ing, tcpServicePort, annTCP, annBack)
	}
}

func (c *converter) syncIngressHTTP(ing *networking.Ingress, annHost, annBack map[string]string) {
	source := &annotations.Source{
		Namespace: ing.Namespace,
		Name:      ing.Name,
		Type:      "ingress",
	}
	if ing.Spec.DefaultBackend != nil {
		svcName, svcPort, err := readServiceNamePort(ing.Spec.DefaultBackend)
		if err == nil {
			err = c.addDefaultHostBackend(source, ing.Namespace+"/"+svcName, svcPort, annHost, annBack)
		}
		if err != nil {
			c.logger.Warn("skipping default backend of %v: %v", source, err)
		}
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		hostname := normalizeHostname(rule.Host, 0)
		ingressClass := c.readIngressClass(source, hostname, ing.Spec.IngressClassName)
		host := c.addHost(hostname, source, annHost)
		for _, path := range rule.HTTP.Paths {
			uri := path.Path
			if uri == "" {
				uri = "/"
			}
			if host.FindPath(uri) != nil {
				c.logger.Warn("skipping redeclared path '%s' of %v", uri, source)
				continue
			}
			svcName, svcPort, err := readServiceNamePort(&path.Backend)
			if err != nil {
				c.logger.Warn("skipping backend config of %v: %v", source, err)
				continue
			}
			fullSvcName := ing.Namespace + "/" + svcName
			backend, err := c.addBackendWithClass(source, hostname, uri, fullSvcName, svcPort, annBack, ingressClass)
			if err != nil {
				c.logger.Warn("skipping backend config of %v: %v", source, err)
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
			// pre-building the auth-url backend
			// TODO move to updater.buildBackendAuthExternal()
			if url := annBack[ingtypes.BackAuthURL]; url != "" {
				urlProto, urlHost, urlPort, _, _ := ingutils.ParseURL(url)
				if (urlProto == "service" || urlProto == "svc") && urlHost != "" && urlPort != "" {
					_, err := c.addBackend(source, hostname, uri, ing.Namespace+"/"+urlHost, urlPort, map[string]string{})
					if err != nil {
						c.logger.Warn("skipping auth-url on %v: %v", source, err)
					}
				}
			}
		}
	}
	for _, tls := range ing.Spec.TLS {
		// tls secret
		for _, hostname := range tls.Hosts {
			host := c.addHost(hostname, source, annHost)
			tlsPath := c.addTLS(source, hostname, tls.SecretName)
			if host.TLS.TLSHash == "" {
				host.TLS.TLSFilename = tlsPath.Filename
				host.TLS.TLSHash = tlsPath.SHA1Hash
				host.TLS.TLSCommonName = tlsPath.CommonName
				host.TLS.TLSNotAfter = tlsPath.NotAfter
			} else if host.TLS.TLSHash != tlsPath.SHA1Hash {
				msg := fmt.Sprintf("TLS of host '%s' was already assigned", host.Hostname)
				if tls.SecretName != "" {
					c.logger.Warn("skipping TLS secret '%s' of %v: %s", tls.SecretName, source, msg)
				} else {
					c.logger.Warn("skipping default TLS secret of %v: %s", source, msg)
				}
			}
		}
		// acme tracking
		var tlsAcme bool
		if c.options.AcmeTrackTLSAnn {
			// distinct prefix, read from the Annotations map
			tlsAcmeStr, _ := ing.Annotations[ingtypes.ExtraTLSAcme]
			tlsAcme, _ = strconv.ParseBool(tlsAcmeStr)
		}
		if !tlsAcme {
			tlsAcme = strings.ToLower(annHost[ingtypes.HostCertSigner]) == "acme"
		}
		if tlsAcme {
			if tls.SecretName != "" {
				secretName := ing.Namespace + "/" + tls.SecretName
				ingName := ing.Namespace + "/" + ing.Name
				c.haproxy.AcmeData().Storages().Acquire(secretName).AddDomains(tls.Hosts)
				c.tracker.TrackStorage(convtypes.IngressType, ingName, secretName)
			} else {
				c.logger.Warn("skipping cert signer of %v: missing secret name", source)
			}
		}
	}
}

func (c *converter) syncIngressTCP(ing *networking.Ingress, tcpServicePort int, annTCP, annBack map[string]string) {
	source := &annotations.Source{
		Namespace: ing.Namespace,
		Name:      ing.Name,
		Type:      "ingress",
	}
	addIngressBackend := func(rawHostname string, ingressBackend *networking.IngressBackend) error {
		hostname := normalizeHostname(rawHostname, tcpServicePort)
		tcpService, err := c.addTCPService(source, hostname, tcpServicePort, annTCP)
		if err != nil {
			return err
		}
		defer func() {
			if tcpService.Backend.IsEmpty() {
				c.haproxy.TCPServices().RemoveService(hostname)
			}
		}()
		svcName, svcPort, err := readServiceNamePort(ingressBackend)
		if err != nil {
			return err
		}
		if !tcpService.Backend.IsEmpty() {
			return fmt.Errorf("service '%s' on %v: backend for port '%d' was already assinged", svcName, source, tcpServicePort)
		}
		fullSvcName := ing.Namespace + "/" + svcName
		ingressClass := c.readIngressClass(source, hostname, ing.Spec.IngressClassName)
		backend, err := c.addBackendWithClass(source, hostname, "/", fullSvcName, svcPort, annBack, ingressClass)
		if err != nil {
			return err
		}
		tcpService.Backend = backend.BackendID()
		return nil
	}
	if ing.Spec.DefaultBackend != nil {
		err := addIngressBackend("", ing.Spec.DefaultBackend)
		if err != nil {
			c.logger.Warn("skipping default backend on %v: %v", source, err)
		}
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Path != "" && path.Path != "/" {
				c.logger.Warn("skipping backend declaration on path '%s' of %v: tcp services do not support path", path.Path, source)
				continue
			}
			err := addIngressBackend(rule.Host, &path.Backend)
			if err != nil {
				c.logger.Warn("skipping path declaration on %v: %v", source, err)
			}
		}
	}
	for _, tls := range ing.Spec.TLS {
		// tls secret
		for _, hostname := range tls.Hosts {
			tcpPort := c.haproxy.TCPServices().FindTCPPort(tcpServicePort)
			if tcpPort == nil {
				c.logger.Warn("skipping TLS of tcp service on %v: backend was not configured", source)
				continue
			}
			tlsPath := c.addTLS(source, normalizeHostname(hostname, tcpServicePort), tls.SecretName)
			if tcpPort.TLS.TLSHash == "" {
				tcpPort.TLS.TLSFilename = tlsPath.Filename
				tcpPort.TLS.TLSHash = tlsPath.SHA1Hash
				tcpPort.TLS.TLSCommonName = tlsPath.CommonName
				tcpPort.TLS.TLSNotAfter = tlsPath.NotAfter
			} else if tcpPort.TLS.TLSHash != tlsPath.SHA1Hash {
				msg := fmt.Sprintf("TLS of tcp service port '%d' was already assigned", tcpServicePort)
				if tls.SecretName != "" {
					c.logger.Warn("skipping TLS secret '%s' of %v: %s", tls.SecretName, source, msg)
				} else {
					c.logger.Warn("skipping default TLS secret of %v: %s", source, msg)
				}
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

func (c *converter) fullSyncTCP() {
	for _, tcpPort := range c.haproxy.TCPServices().Items() {
		if ann, found := c.tcpsvcAnnotations[tcpPort]; found {
			c.updater.UpdateTCPPortConfig(tcpPort, ann)
			for _, tcpHost := range tcpPort.Hosts() {
				c.updater.UpdateTCPHostConfig(tcpHost, ann)
			}
		}
	}
}

func (c *converter) fullSyncAnnotations() {
	c.updater.UpdateGlobalConfig(c.haproxy, c.globalConfig)
	c.fullSyncTCP()
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
	c.fullSyncTCP()
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

func (c *converter) readIngressClass(source *annotations.Source, hostname string, ingressClassName *string) *networking.IngressClass {
	if ingressClassName != nil {
		ingressClass, err := c.cache.GetIngressClass(*ingressClassName)
		if err == nil {
			c.tracker.TrackHostname(convtypes.IngressClassType, *ingressClassName, hostname)
			return ingressClass
		}
		c.tracker.TrackMissingOnHostname(convtypes.IngressClassType, *ingressClassName, hostname)
		c.logger.Warn("error reading IngressClass of %s: %v", source, err)
	}
	return nil
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

func (c *converter) addTCPService(source *annotations.Source, hostname string, port int, ann map[string]string) (*hatypes.TCPServiceHost, error) {
	tcpPort, tcpHost := c.haproxy.TCPServices().AcquireTCPService(hostname)
	if !tcpHost.Backend.IsEmpty() {
		tcpservice := strings.TrimPrefix(hostname, hatypes.DefaultHost)
		return nil, fmt.Errorf("tcp service %s was already assigned to %s", tcpservice, tcpHost.Backend)
	}
	c.tracker.TrackHostname(convtypes.IngressType, source.FullName(), hostname)
	mapper, found := c.tcpsvcAnnotations[tcpPort]
	if !found {
		mapper = c.mapBuilder.NewMapper()
		c.tcpsvcAnnotations[tcpPort] = mapper
	}
	conflict := mapper.AddAnnotations(source, hatypes.CreatePathLink(hostname, "/"), ann)
	if len(conflict) > 0 {
		c.logger.Warn("skipping tcp service annotation(s) from %v due to conflict: %v", source, conflict)
	}
	return tcpHost, nil
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
	return c.addBackendWithClass(source, hostname, uri, fullSvcName, svcPort, ann, nil)
}

func (c *converter) addBackendWithClass(source *annotations.Source, hostname, uri, fullSvcName, svcPort string, ann map[string]string, ingressClass *networking.IngressClass) (*hatypes.Backend, error) {
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
		_, _, ann := c.readAnnotations(svc.Annotations)
		mapper.AddAnnotations(&annotations.Source{
			Namespace: namespace,
			Name:      svcName,
			Type:      "service",
		}, pathlink, ann)
		c.backendAnnotations[backend] = mapper
	}
	// Merging Ingress annotations
	conflict := mapper.AddAnnotations(source, pathlink, ann)
	if len(conflict) > 0 {
		c.logger.Warn("skipping backend '%s:%s' annotation(s) from %v due to conflict: %v",
			svcName, svcPort, source, conflict)
	}
	// Merging IngressClass Parameters with less priority
	if ingressClass != nil {
		if cfg := c.readParameters(ingressClass, hostname); cfg != nil {
			// Using a work around to add a per resource default config:
			// we add IngressClass Parameters after service and ingress annotations,
			// ignoring conflicts. This would really conflict with other Parameters
			// only if the same host+path is declared twice, but such duplication is
			// already filtred out in the ingress parsing.
			_ = mapper.AddAnnotations(source, pathlink, cfg)
		}
	}
	// Configure endpoints
	if !found {
		backend.Server.InitialWeight = mapper.Get(ingtypes.BackInitialWeight).Int()
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
			case hatypes.EpCookiePodUID:
				if ep.TargetRef != "" {
					pod, err := c.cache.GetPod(ep.TargetRef)
					if err == nil {
						ep.CookieValue = fmt.Sprintf("%v", pod.UID)
					} else {
						ep.CookieValue = ep.Name
						c.logger.Error("error calculating cookie value for pod %s; falling back to 'server-name' strategy: %v", ep.TargetRef, err)
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

func (c *converter) readAnnotations(annotations map[string]string) (annTCP, annHost, annBack map[string]string) {
	annTCP = make(map[string]string, len(annotations))
	annHost = make(map[string]string, len(annotations))
	annBack = make(map[string]string, len(annotations))
	prefix := c.options.AnnotationPrefix + "/"
	for annName, annValue := range annotations {
		if strings.HasPrefix(annName, prefix) {
			name := strings.TrimPrefix(annName, prefix)
			if _, isTCPAnn := ingtypes.AnnTCP[name]; isTCPAnn {
				annTCP[name] = annValue
			} else if _, isHostAnn := ingtypes.AnnHost[name]; isHostAnn {
				annHost[name] = annValue
			} else {
				annBack[name] = annValue
			}
		}
	}
	return annTCP, annHost, annBack
}

func (c *converter) readParameters(ingressClass *networking.IngressClass, trackingHostname string) map[string]string {
	ingClassConfig, found := c.ingressClasses[ingressClass.Name]
	if !found {
		ingClassConfig = c.parseParameters(ingressClass, trackingHostname)
		if ingClassConfig == nil {
			// error or Parameters reference not found, so create and assign an
			// empty config to avoid re-parse Parameters on every ingress resource
			ingClassConfig = &ingressClassConfig{}
		}
		c.ingressClasses[ingressClass.Name] = ingClassConfig
	}
	if ingClassConfig.resourceName != "" {
		c.tracker.TrackHostname(ingClassConfig.resourceType, ingClassConfig.resourceName, trackingHostname)
	}
	return ingClassConfig.config
}

func (c *converter) parseParameters(ingressClass *networking.IngressClass, trackingHostname string) *ingressClassConfig {
	parameters := ingressClass.Spec.Parameters
	if parameters == nil {
		return nil
	}
	// Currently only ConfigMap is supported
	if parameters.APIGroup != nil && *parameters.APIGroup != "" {
		c.logger.Warn("unsupported Parameters' APIGroup on IngressClass '%s': %s", ingressClass.Name, *parameters.APIGroup)
		return nil
	}
	if strings.ToLower(parameters.Kind) != "configmap" {
		c.logger.Warn("unsupported Parameters' Kind on IngressClass '%s': %s", ingressClass.Name, parameters.Kind)
		return nil
	}
	podNamespace := c.cache.GetPodNamespace()
	if podNamespace == "" {
		c.logger.Warn("need to configure POD_NAMESPACE to use ConfigMap on IngressClass '%s'", ingressClass.Name)
		return nil
	}
	configMapName := podNamespace + "/" + parameters.Name
	configMap, err := c.cache.GetConfigMap(configMapName)
	if err != nil {
		c.logger.Warn("error reading ConfigMap on IngressClass '%s': %v", ingressClass.Name, err)
		c.tracker.TrackMissingOnHostname(convtypes.ConfigMapType, configMapName, trackingHostname)
		return nil
	}
	return &ingressClassConfig{
		resourceType: convtypes.ConfigMapType,
		resourceName: configMapName,
		config:       configMap.Data,
	}
}

func readServiceNamePort(backend *networking.IngressBackend) (string, string, error) {
	if backend.Service == nil {
		return "", "", fmt.Errorf("resource backend is not supported yet")
	}
	serviceName := backend.Service.Name
	servicePort := backend.Service.Port.Name
	if servicePort == "" {
		servicePort = strconv.Itoa(int(backend.Service.Port.Number))
	}
	return serviceName, servicePort, nil
}
