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
	"hash/fnv"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/annotations"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	ingutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/utils"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// Config ...
type Config interface {
	NeedFullSync() bool
	Sync(full bool)
	ReadAnnotations(backend *hatypes.Backend, services []*api.Service, pathLinks []*hatypes.PathLink)
}

// NewIngressConverter ...
func NewIngressConverter(options *convtypes.ConverterOptions, haproxy haproxy.Config, changed *convtypes.ChangedObjects) Config {
	if options.DefaultConfig == nil {
		options.DefaultConfig = createDefaults
	}
	// IMPLEMENT
	// config option to allow partial parsing
	// cache also need to know if partial parsing is enabled
	globalConfig := changed.GlobalConfigMapDataNew
	if globalConfig == nil {
		globalConfig = changed.GlobalConfigMapDataCur
	}
	defaultConfig := options.DefaultConfig()
	for key, value := range globalConfig {
		defaultConfig[key] = value
	}
	c := &converter{
		options:            options,
		haproxy:            haproxy,
		changed:            changed,
		logger:             options.Logger,
		cache:              options.Cache,
		tracker:            options.Tracker,
		defaultBackSource:  annotations.Source{Name: "<default-backend>", Type: convtypes.ResourceIngress},
		mapBuilder:         annotations.NewMapBuilder(options.Logger, defaultConfig),
		updater:            annotations.NewUpdater(haproxy, options),
		globalConfig:       annotations.NewMapBuilder(options.Logger, defaultConfig).NewMapper(),
		tcpsvcAnnotations:  map[*hatypes.TCPServicePort]*annotations.Mapper{},
		frontAnnotations:   map[*hatypes.Frontend]*annotations.Mapper{},
		hostAnnotations:    map[*hatypes.Host]*annotations.Mapper{},
		backendAnnotations: map[*hatypes.Backend]*annotations.Mapper{},
		ingressClasses:     map[string]*ingressClassConfig{},
	}
	c.readDefaultCertificate()
	return c
}

type converter struct {
	options            *convtypes.ConverterOptions
	haproxy            haproxy.Config
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
	frontAnnotations   map[*hatypes.Frontend]*annotations.Mapper
	hostAnnotations    map[*hatypes.Host]*annotations.Mapper
	backendAnnotations map[*hatypes.Backend]*annotations.Mapper
	ingressClasses     map[string]*ingressClassConfig
}

func (c *converter) ReadAnnotations(backend *hatypes.Backend, services []*api.Service, pathLinks []*hatypes.PathLink) {
	mapper := c.mapBuilder.NewMapper()
	for _, service := range services {
		source := &annotations.Source{
			Namespace: service.Namespace,
			Name:      service.Name,
			Type:      convtypes.ResourceService,
		}
		_, _, _, ann := c.readAnnotations(source, service.Annotations)
		for _, pathLink := range pathLinks {
			conflict := mapper.AddAnnotations(source, pathLink, ann)
			if len(conflict) > 0 {
				c.logger.Warn("skipping %s annotation(s) due to conflict: %v", source, conflict)
			}
		}
	}
	c.updater.UpdateBackendConfig(backend, mapper)
}

type ingressClassConfig struct {
	resourceType convtypes.ResourceType
	resourceName string
	config       map[string]string
}

func (c *converter) NeedFullSync() bool {
	needFullSync := c.defaultCrtNeedFullSync() || c.globalConfigNeedFullSync()
	if needFullSync && c.defaultCrt.SHA1Hash == c.options.FakeCrtFile.SHA1Hash {
		c.logger.Info("using auto generated fake certificate")
	}
	return needFullSync
}

func (c *converter) Sync(full bool) {
	c.syncDefaultCrt()
	if full {
		c.syncFull()
	} else {
		c.syncPartial()
	}
}

func (c *converter) defaultCrtNeedFullSync() bool {
	f := c.haproxy.Frontends()
	return f.DefaultCrtFile != c.defaultCrt.Filename ||
		f.DefaultCrtHash != c.defaultCrt.SHA1Hash
}

func (c *converter) globalConfigNeedFullSync() bool {
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
	cur, new := c.changed.GlobalConfigMapDataCur, c.changed.GlobalConfigMapDataNew
	return new != nil && !reflect.DeepEqual(cur, new)
}

func (c *converter) readDefaultCertificate() {
	crt := c.options.FakeCrtFile
	if c.options.DefaultCrtSecret != "" {
		var err error
		crt, err = c.cache.GetTLSSecretPath("", c.options.DefaultCrtSecret, nil)
		if err != nil {
			crt = c.options.FakeCrtFile
			c.logger.Warn("using auto generated fake certificate due to an error reading default TLS certificate: %v", err)
		}
	}
	c.defaultCrt = crt
}

func (c *converter) syncDefaultCrt() {
	f := c.haproxy.Frontends()
	f.DefaultCrtFile = c.defaultCrt.Filename
	f.DefaultCrtHash = c.defaultCrt.SHA1Hash
}

// bareLink creates a pathlink with default path and match type params,
// used to create generic, TCP, Frontend or Hostname based pathlinks.
func bareLink() *hatypes.PathLink { return hatypes.CreatePathLink("/", hatypes.MatchExact) }

func (c *converter) syncDefaultBackend() {
	if c.options.DefaultBackend != "" {
		if backend, err := c.addBackend(&c.defaultBackSource, bareLink(), c.options.DefaultBackend, "", map[string]string{}, nil); err == nil {
			c.haproxy.Backends().DefaultBackend = backend
			c.tracker.TrackNames(c.defaultBackSource.Type, c.defaultBackSource.FullName(), convtypes.ResourceHAHostname, hatypes.DefaultHost)
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
	c.updater.UpdateGlobalConfig(c.haproxy, c.globalConfig)
	c.syncDefaultBackend()
	for _, ing := range ingList {
		c.syncIngress(ing)
	}
	c.syncConfig()
}

func (c *converter) syncPartial() {
	c.trackAddedIngress()
	trackedLinks := c.tracker.QueryLinks(c.changed.Links, true)

	dirtyIngs := trackedLinks[convtypes.ResourceIngress]
	dirtyTCPServices := trackedLinks[convtypes.ResourceHATCPService]
	dirtyHosts := trackedLinks[convtypes.ResourceHAHostname]
	dirtyBacks := trackedLinks[convtypes.ResourceHABackend]
	dirtyUsers := trackedLinks[convtypes.ResourceHAUserlist]
	dirtyStorages := trackedLinks[convtypes.ResourceAcmeData]

	c.haproxy.TCPServices().RemoveAll(dirtyTCPServices)
	c.haproxy.Frontends().RemoveAllHosts(dirtyHosts)
	c.haproxy.Frontends().AuthProxy.RemoveAuthBackendByTarget(dirtyBacks)
	c.haproxy.Backends().RemoveAll(dirtyBacks)
	c.haproxy.Userlists().RemoveAll(dirtyUsers)
	c.haproxy.AcmeData().Storages().RemoveAll(dirtyStorages)

	// looking for controller pod changes, used by peers.
	// missing a better tracking and global update approach.
	ctrlNamespace := c.cache.GetControllerPod().Namespace + "/"
	changedPods := c.changed.Links[convtypes.ResourcePod]
	for _, pod := range changedPods {
		if strings.HasPrefix(pod, ctrlNamespace) {
			c.logger.Info("updating peers due to changes in controller pods")
			c.updater.UpdatePeers(c.haproxy, c.globalConfig)
			break
		}
	}

	c.logger.InfoV(2, "syncing %d host(s) and %d backend(s)", len(dirtyHosts), len(dirtyBacks))

	// merge dirty and added ingress objects into a single list
	ingMap := make(map[string]*networking.Ingress)
	for _, ing := range dirtyIngs {
		ingMap[ing] = nil
	}
	for _, ing := range c.changed.IngressesDel {
		delete(ingMap, ing.Namespace+"/"+ing.Name)
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
	c.syncConfig()
}

// trackAddedIngress add tracking hostnames and backends to new ingress objects
//
// All state change works removing hosts and backs objects in an old state and
// resyncing ingress objects to recreate hosts and backs in a new state. This
// works very well, except with ingress objects that starts to reference hosts or
// backs that already exist - all the tracking starts from the ingress parsing.
//
// trackAddedIngress does the same tracking the sync ingress already do, but
// before real sync starts and just before calculate dirty objects - if an
// existent host or back is tracked only by an added ingress, it is tracked
// here and removed before parse the added ingress which will readd such hosts
// and backs
func (c *converter) trackAddedIngress() {
	for _, ing := range append(c.changed.IngressesAdd, c.changed.IngressesUpd...) {
		name := ing.Namespace + "/" + ing.Name
		if ing.Spec.DefaultBackend != nil {
			backend := c.findBackend(ing.Namespace, ing.Spec.DefaultBackend)
			if backend != nil {
				c.tracker.TrackNames(convtypes.ResourceIngress, name, convtypes.ResourceHABackend, backend.ID)
			}
		}
		port, _ := strconv.Atoi(c.readConfigKey(ing.Annotations, ingtypes.TCPTCPServicePort))
		ctx := convtypes.ResourceHAHostname
		if port > 0 {
			ctx = convtypes.ResourceHATCPService
		}
		for _, rule := range ing.Spec.Rules {
			c.tracker.TrackNames(convtypes.ResourceIngress, name, ctx, normalizeHostname(rule.Host, port))
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					backend := c.findBackend(ing.Namespace, &path.Backend)
					if backend != nil {
						c.tracker.TrackNames(convtypes.ResourceIngress, name, convtypes.ResourceHABackend, backend.ID)
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
	svc, err := c.cache.GetService(namespace, svcName)
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
//   - empty hostnames are changed to `hatypes.DefaultHost` which has a
//     special meaning in the hosts entity
//   - hostnames for tcp services receive the port number to distinguish
//     two tcp services without hostname. hostnames are preserved, making it
//     a bit easier to introduce sni based routing.
func normalizeHostname(hostname string, port int) string {
	if hostname == "" {
		hostname = hatypes.DefaultHost
	}
	if port > 0 {
		return hostname + ":" + strconv.Itoa(port)
	}
	return hostname
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
	source := &annotations.Source{
		Namespace: ing.Namespace,
		Name:      ing.Name,
		Type:      convtypes.ResourceIngress,
	}
	annTCP, annFront, annHost, annBack := c.readAnnotations(source, ing.Annotations)
	tcpServicePort, _ := strconv.Atoi(annTCP[ingtypes.TCPTCPServicePort])
	if tcpServicePort == 0 {
		c.syncIngressHTTP(source, ing, annFront, annHost, annBack)
	} else {
		c.syncIngressTCP(source, ing, tcpServicePort, annTCP, annBack)
	}
}

func (c *converter) acquireFrontend(source *annotations.Source, annFront, annHost map[string]string) *frontend {
	link := bareLink()
	mapper := c.mapBuilder.NewMapper()
	_ = mapper.AddAnnotations(source, link, annFront)
	_ = mapper.AddAnnotations(source, link, annHost)
	f := c.haproxy.Frontends()
	httpPort := mapper.Get(ingtypes.FrontFrontingProxyPort).Int32()
	if httpPort == 0 {
		httpPort = mapper.Get(ingtypes.FrontHTTPPort).Int32()
	}
	return &frontend{
		f:           f,
		innerHTTP:   f.AcquireFrontend(httpPort, false),
		httpsPort:   mapper.Get(ingtypes.FrontHTTPSPort).Int32(),
		alwaysTLS:   mapper.Get(ingtypes.HostSSLAlwaysAddHTTPS).Bool(),
		followRedir: mapper.Get(ingtypes.HostSSLAlwaysFollowRedirect).Bool(),
		hosts:       make(map[string]*host),
	}
}

type frontend struct {
	f *hatypes.Frontends
	innerHTTP,
	innerHTTPS *hatypes.Frontend
	httpsPort   int32
	alwaysTLS   bool
	followRedir bool
	hosts       map[string]*host
}

type host struct {
	inner,
	innerHTTPS *hatypes.Host
	paths []*hatypes.Path
	links []*hatypes.Path
	redir []*hatypes.Path
}

func (f *frontend) FindHost(hostname string) *host {
	if inner := f.innerHTTP.FindHost(hostname); inner != nil {
		h := &host{inner: inner}
		f.hosts[hostname] = h
		return h
	}
	return nil
}

func (f *frontend) AcquireHost(hostname string) *host {
	h, found := f.hosts[hostname]
	if !found {
		h = &host{inner: f.innerHTTP.AcquireHost(hostname)}
		f.hosts[hostname] = h
	}
	return h
}

func (f *frontend) AcquireHostHTTPS(hostname string) *host {
	if f.innerHTTPS == nil {
		f.innerHTTPS = f.f.AcquireFrontend(f.httpsPort, true)
	}
	h := f.AcquireHost(hostname)
	h.innerHTTPS = f.innerHTTPS.AcquireHost(hostname)
	return h
}

func (f *frontend) RemoveAllHosts(hostnames []string) {
	f.innerHTTP.RemoveAllHosts(hostnames)
	if f.innerHTTPS != nil {
		f.innerHTTPS.RemoveAllHosts(hostnames)
	}
	maps.DeleteFunc(f.hosts, func(h string, _ *host) bool {
		return slices.Contains(hostnames, h)
	})
}

func (h *host) AddPath(backend *hatypes.Backend, path string, match hatypes.MatchType) {
	h.paths = append(h.paths, h.inner.AddPath(backend, path, match))
}

func (h *host) AddLink(backend *hatypes.Backend, link *hatypes.PathLink) {
	h.links = append(h.links, h.inner.AddLink(backend, link))
}

func (h *host) AddRedirect(path string, match hatypes.MatchType, redirTo string) {
	h.redir = append(h.redir, h.inner.AddRedirect(path, match, redirTo))
}

func (c *converter) syncIngressHTTP(source *annotations.Source, ing *networking.Ingress, annFront, annHost, annBack map[string]string) {
	f := c.acquireFrontend(source, annFront, annHost)
	defer c.syncHTTPS(f)
	if ing.Spec.DefaultBackend != nil {
		svcName, svcPort, err := readServiceNamePort(ing.Spec.DefaultBackend)
		if err == nil {
			err = c.addDefaultHostBackend(f, source, ing.Namespace+"/"+svcName, svcPort, annFront, annHost, annBack)
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
		ingressClass := c.readIngressClass(source, ing.Spec.IngressClassName)
		sslpassthrough, _ := strconv.ParseBool(annHost[ingtypes.HostSSLPassthrough])
		host := c.addHost(f, hostname, source, annFront, annHost, false)
		for _, path := range rule.HTTP.Paths {
			uri := path.Path
			if uri == "" {
				uri = "/"
			}
			match := c.readPathType(path, annBack[ingtypes.BackPathType])
			pathLink := hatypes.CreatePathLink(uri, match).WithHTTPHost(host.inner)
			if headerMatch := annBack[ingtypes.BackHTTPHeaderMatch]; headerMatch != "" {
				c.addHeaderMatch(source, pathLink, headerMatch, false)
			}
			if headerMatch := annBack[ingtypes.BackHTTPHeaderMatchRegex]; headerMatch != "" {
				c.addHeaderMatch(source, pathLink, headerMatch, true)
			}
			if sslpassthrough && uri == "/" {
				if host.inner.FindPath(uri) != nil {
					c.logger.Warn("skipping redeclared ssl-passthrough root path on %v", source)
					continue
				}
			} else if host.inner.FindPathWithLink(pathLink) != nil {
				c.logger.Warn("skipping redeclared path '%s' type '%s' on %v", uri, match, source)
				continue
			}
			if redirectTo := annBack[ingtypes.BackRedirectTo]; redirectTo != "" {
				host.AddRedirect(uri, match, redirectTo)
				continue
			}
			svcName, svcPort, err := readServiceNamePort(&path.Backend)
			if err != nil {
				c.logger.Warn("skipping backend config of %v: %v", source, err)
				continue
			}
			fullSvcName := ing.Namespace + "/" + svcName
			backend, err := c.addBackend(source, pathLink, fullSvcName, svcPort, annBack, ingressClass)
			if err != nil {
				c.logger.Warn("skipping backend config of %v: %v", source, err)
				continue
			}
			if sslpassthrough {
				// TODO missing a better abstraction for ssl-passthrough handling
				host := f.AcquireHostHTTPS(hostname)
				host.innerHTTPS.SSLPassthrough = true
				if uri == "/" {
					// regular passthrough configuration
					backend.ModeTCP = true
					host.innerHTTPS.AddLink(backend, pathLink)
					var hback *hatypes.Backend
					if hport := annHost[ingtypes.HostSSLPassthroughHTTPPort]; hport != "" {
						hback, err = c.addBackend(source, pathLink, fullSvcName, hport, annBack, nil)
						if err != nil {
							c.logger.Warn("skipping http port config of ssl-passthrough on %v: %v", source, err)
							hback = nil
						}
					}
					if hback == nil {
						hback = c.haproxy.Backends().AcquireRedirectHTTPSBackend()
					}
					host.inner.AddLink(hback, pathLink)
				} else {
					// non root path, configure it on HTTP only
					host.inner.AddLink(backend, pathLink)
				}
			} else {
				// regular http(s) request, non ssl-passthrough
				host.AddLink(backend, pathLink)
			}
			// pre-building the auth-url backend
			// TODO move to updater.buildBackendAuthExternal()
			// TODO addBackend() might change the portName on named port configurations to enforce consistency,
			// however updater's FindBackend() won't do it, leading to a silently broken configuration.
			// See https://github.com/jcmoraisjr/haproxy-ingress/issues/981
			// Moving this logic to updater will fix this behavior, in the mean time we'll add a few more
			// tips in the doc.
			if url := annBack[ingtypes.BackAuthURL]; url != "" {
				urlProto, urlHost, urlPort, _, _ := ingutils.ParseURL(url)
				if (urlProto == "service" || urlProto == "svc") && urlHost != "" && urlPort != "" {
					authSvcName := urlHost
					if !strings.Contains(authSvcName, "/") {
						authSvcName = ing.Namespace + "/" + authSvcName
					}
					_, err := c.addBackend(source, pathLink, authSvcName, urlPort, map[string]string{}, nil)
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
			host := c.addHost(f, hostname, source, annFront, annHost, true)
			tlsPath := c.addTLS(source, tls.SecretName)
			hhttps := host.innerHTTPS
			if hhttps.TLS.TLSHash == "" {
				hhttps.TLS.TLSFilename = tlsPath.Filename
				hhttps.TLS.TLSHash = tlsPath.SHA1Hash
				hhttps.TLS.TLSCommonName = tlsPath.Certificate.Subject.CommonName
				hhttps.TLS.TLSNotAfter = tlsPath.Certificate.NotAfter
			} else if hhttps.TLS.TLSHash != tlsPath.SHA1Hash {
				msg := fmt.Sprintf("TLS of host '%s' was already assigned", hhttps.Hostname)
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
			tlsAcmeStr := ing.Annotations[ingtypes.ExtraTLSAcme]
			tlsAcme, _ = strconv.ParseBool(tlsAcmeStr)
		}
		if !tlsAcme {
			tlsAcme = strings.ToLower(annHost[ingtypes.HostCertSigner]) == "acme"
		}
		if tlsAcme {
			if tls.SecretName != "" {
				secretName := ing.Namespace + "/" + tls.SecretName
				ingName := ing.Namespace + "/" + ing.Name
				acmeStorage := c.haproxy.AcmeData().Storages().Acquire(secretName)
				acmeStorage.AddDomains(tls.Hosts)
				if preferredChain := annHost[ingtypes.HostAcmePreferredChain]; preferredChain != "" {
					if err := acmeStorage.AssignPreferredChain(preferredChain); err != nil {
						c.logger.Warn("preferred chain ignored on %v due to an error: %v", source, err)
					}
				}
				c.tracker.TrackNames(convtypes.ResourceIngress, ingName, convtypes.ResourceAcmeData, secretName)
			} else {
				c.logger.Warn("skipping cert signer of %v: missing secret name", source)
			}
		}
	}
}

func (c *converter) syncHTTPS(f *frontend) {
	var https *hatypes.Frontend
	for hostname, host := range f.hosts {
		if f.alwaysTLS || host.innerHTTPS != nil {
			if https == nil {
				https = c.haproxy.Frontends().AcquireFrontend(f.httpsPort, true)
			}
			h := https.AcquireHost(hostname)
			for _, srcpath := range host.paths {
				srcpath.HasHTTPS = true
				dstpath := h.AddPath(srcpath.Backend, srcpath.Path(), srcpath.Match())
				c.backendAnnotations[srcpath.Backend].CopyConfig(dstpath.Link, srcpath.Link)
			}
			for _, srcpath := range host.links {
				srcpath.HasHTTPS = true
				dstpath := h.AddLink(srcpath.Backend, srcpath.Link)
				c.backendAnnotations[srcpath.Backend].CopyConfig(dstpath.Link, srcpath.Link)
			}
			for _, srcpath := range host.redir {
				srcpath.HasHTTPS = true
				_ = h.AddRedirect(srcpath.Path(), srcpath.Match(), srcpath.RedirTo)
			}
		}
	}
}

func (c *converter) syncIngressTCP(source *annotations.Source, ing *networking.Ingress, tcpServicePort int, annTCP, annBack map[string]string) {
	addIngressBackend := func(rawHostname string, ingressBackend *networking.IngressBackend) error {
		hostname := normalizeHostname(rawHostname, tcpServicePort)
		tcpService, tcpLink, err := c.addTCPService(source, hostname, annTCP)
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
			return fmt.Errorf("service '%s' on %v: backend for port '%d' was already assigned", svcName, source, tcpServicePort)
		}
		fullSvcName := ing.Namespace + "/" + svcName
		ingressClass := c.readIngressClass(source, ing.Spec.IngressClassName)
		backend, err := c.addBackend(source, tcpLink, fullSvcName, svcPort, annBack, ingressClass)
		if err != nil {
			return err
		}
		tcpService.Backend = backend.BackendID()
		backend.ModeTCP = true
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
		secretName := tls.SecretName
		tcpPort := c.haproxy.TCPServices().FindTCPPort(tcpServicePort)
		if tcpPort == nil {
			c.logger.Warn("skipping TLS of tcp service on %v: backend was not configured", source)
			return
		}
		tlsPath := c.addTLS(source, secretName)
		tlsHosts := tls.Hosts
		if len(tlsHosts) == 0 {
			// configures default host if none is declared
			tlsHosts = []string{hatypes.DefaultHost}
		}
		for _, tlsHost := range tlsHosts {
			if _, found := tcpPort.TLS[tlsHost]; !found {
				tcpPort.TLS[tlsHost] = &hatypes.TCPServiceTLSConfig{
					Hostname: tlsHost,
					TLSConfig: hatypes.TLSConfig{
						TLSFilename:   tlsPath.Filename,
						TLSHash:       tlsPath.SHA1Hash,
						TLSCommonName: tlsPath.Certificate.Subject.CommonName,
						TLSNotAfter:   tlsPath.Certificate.NotAfter,
						// tcp updater fills other tlsConfig fields, reading from annotation config
					},
				}
			} else {
				msg := fmt.Sprintf("hostname on tcp service port :%d was already assigned", tcpServicePort)
				if secretName != "" {
					c.logger.Warn("skipping TLS secret '%s' on %v: %s", secretName, source, msg)
				} else {
					c.logger.Warn("skipping default TLS secret of %v: %s", source, msg)
				}
			}
		}
	}
}

func (c *converter) syncConfig() {
	for tcpPort, mapper := range c.tcpsvcAnnotations {
		c.updater.UpdateTCPPortConfig(tcpPort, mapper)
		if tcpHost := tcpPort.DefaultHost(); tcpHost != nil {
			c.updater.UpdateTCPHostConfig(tcpPort, tcpHost, mapper)
		}
		for _, tcpHost := range tcpPort.Hosts() {
			c.updater.UpdateTCPHostConfig(tcpPort, tcpHost, mapper)
		}
	}
	for front, mapper := range c.frontAnnotations {
		c.updater.UpdateFrontConfig(front, mapper)
	}
	for host, mapper := range c.hostAnnotations {
		c.updater.UpdateHostConfig(host, mapper)
	}
	for backend, mapper := range c.backendAnnotations {
		c.updater.UpdateBackendConfig(backend, mapper)
		c.syncBackendEndpointCookies(backend)
		c.syncBackendEndpointHashes(backend)
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
			c.logger.Warn("unsupported '%s' pathType from Ingress spec, using '%s' instead.",
				pathType, networking.PathTypeImplementationSpecific)
		}
	}
	return match
}

func (c *converter) readIngressClass(source *annotations.Source, ingressClassName *string) *networking.IngressClass {
	if ingressClassName != nil {
		c.tracker.TrackNames(convtypes.ResourceIngressClass, *ingressClassName, source.Type, source.FullName())
		ingressClass, err := c.cache.GetIngressClass(*ingressClassName)
		if err == nil {
			return ingressClass
		}
		c.logger.Warn("error reading IngressClass of %s: %v", source, err)
	}
	return nil
}

func (c *converter) addDefaultHostBackend(f *frontend, source *annotations.Source, fullSvcName, svcPort string, annFront, annHost, annBack map[string]string) error {
	hostname := hatypes.DefaultHost
	uri := "/"
	match := hatypes.MatchBegin

	// existing stores if the host already existed before calling this func
	var existing bool
	if host := f.FindHost(hostname); host != nil {
		if host.inner.FindPath(uri, match) != nil {
			return fmt.Errorf("path %s was already defined on default host", uri)
		}
		existing = true
	}

	host := f.AcquireHost(hostname)
	pathLink := hatypes.CreatePathLink(uri, match).WithHTTPHost(host.inner)
	backend, err := c.addBackend(source, pathLink, fullSvcName, svcPort, annBack, nil)
	if err != nil {
		c.tracker.TrackNames(source.Type, source.FullName(), convtypes.ResourceService, fullSvcName)
		if !existing {
			// we needed to create it in order to configure a pathLink,
			// so reverting the creation since we are not going to use it.
			f.RemoveAllHosts([]string{hostname})
		}
		return err
	}
	host = c.addHost(f, hostname, source, annFront, annHost, false)
	host.AddPath(backend, uri, match)
	return nil
}

func (c *converter) addTCPService(source *annotations.Source, hostname string, ann map[string]string) (*hatypes.TCPServiceHost, *hatypes.PathLink, error) {
	tcpPort, tcpHost := c.haproxy.TCPServices().AcquireTCPService(hostname)
	if !tcpHost.Backend.IsEmpty() {
		tcpservice := strings.TrimPrefix(hostname, hatypes.DefaultHost)
		return nil, nil, fmt.Errorf("tcp service %s was already assigned to %s", tcpservice, tcpHost.Backend)
	}
	c.tracker.TrackNames(source.Type, source.FullName(), convtypes.ResourceHATCPService, hostname)
	mapper, found := c.tcpsvcAnnotations[tcpPort]
	if !found {
		mapper = c.mapBuilder.NewMapper()
		c.tcpsvcAnnotations[tcpPort] = mapper
	}
	tcpLink := bareLink().WithTCPHost(tcpHost)
	conflict := mapper.AddAnnotations(source, tcpLink, ann)
	if len(conflict) > 0 {
		c.logger.Warn("skipping tcp service annotation(s) from %v due to conflict: %v", source, conflict)
	}
	return tcpHost, tcpLink, nil
}

func (c *converter) addHost(f *frontend, hostname string, source *annotations.Source, annFront, annHost map[string]string, https bool) *host {
	// TODO build a stronger tracking
	c.tracker.TrackNames(source.Type, source.FullName(), convtypes.ResourceHAHostname, hostname)
	host := f.AcquireHost(hostname)

	if conflicts := c.addFrontAnnotations(f.innerHTTP, source, annFront); len(conflicts) > 0 {
		c.logger.Warn("skipping frontend annotation(s) from %v due to conflict: %v", source, conflicts)
	}
	if conflicts := c.addHostAnnotations(host.inner, source, annHost); len(conflicts) > 0 {
		c.logger.Warn("skipping host annotation(s) from %v due to conflict: %v", source, conflicts)
	}

	if https {
		host := f.AcquireHostHTTPS(hostname)
		_ = c.addFrontAnnotations(f.innerHTTPS, source, annFront)
		_ = c.addHostAnnotations(host.innerHTTPS, source, annHost)
	}

	return host
}

func (c *converter) addFrontAnnotations(frontend *hatypes.Frontend, source *annotations.Source, annFront map[string]string) (conflicts []string) {
	mapperFront, foundFront := c.frontAnnotations[frontend]
	if !foundFront {
		mapperFront = c.mapBuilder.NewMapper()
		c.frontAnnotations[frontend] = mapperFront
	}
	return mapperFront.AddAnnotations(source, bareLink().WithHTTPFront(frontend), annFront)
}

func (c *converter) addHostAnnotations(host *hatypes.Host, source *annotations.Source, annHost map[string]string) (conflicts []string) {
	mapperHost, foundHost := c.hostAnnotations[host]
	if !foundHost {
		mapperHost = c.mapBuilder.NewMapper()
		c.hostAnnotations[host] = mapperHost
	}
	return mapperHost.AddAnnotations(source, bareLink().WithHTTPHost(host), annHost)
}

func (c *converter) addHeaderMatch(source *annotations.Source, pathLink *hatypes.PathLink, headerMatch string, regex bool) {
	var headers hatypes.HTTPHeaderMatch
	for _, header := range utils.LineToSlice(headerMatch) {
		name, value, err := utils.SplitHeaderNameValue(header)
		if err != nil {
			c.logger.Warn("ignoring header on %s: %v", source, err)
		}
		if name == "" {
			continue
		}
		if regex {
			if _, err := regexp.Compile(value); err != nil {
				c.logger.Warn("ignoring invalid regex on %s: %v", source, err)
				continue
			}
		}
		headers = append(headers, hatypes.HTTPMatch{
			Regex: regex,
			Name:  name,
			Value: value,
		})
	}
	if len(headers) > 0 {
		pathLink.AddHeadersMatch(headers)
	}
}

func (c *converter) addBackend(source *annotations.Source, pathLink *hatypes.PathLink, fullSvcName, svcPort string, ann map[string]string, ingressClass *networking.IngressClass) (*hatypes.Backend, error) {
	// TODO build a stronger tracking
	hostname := pathLink.Hostname()
	ctx := convtypes.ResourceHAHostname
	if strings.Contains(hostname, ":") {
		// TODO this is the wrong way to identify if this is a tcp service. But
		// it works. There is a refactor to be made in some haproxy model types
		// to better fit gateway api, this should help here; otherwise, we'll
		// need to evolve to an implementation that's not based on assumptions.
		ctx = convtypes.ResourceHATCPService
	}
	c.tracker.TrackRefName([]convtypes.TrackingRef{
		{Context: convtypes.ResourceService, UniqueName: fullSvcName},
		{Context: convtypes.ResourceEndpoints, UniqueName: fullSvcName},
	}, ctx, hostname)
	svc, err := c.cache.GetService(source.Namespace, fullSvcName)
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
		if svc.Spec.Type != api.ServiceTypeExternalName || len(svc.Spec.Ports) > 0 {
			return nil, fmt.Errorf("port not found: '%s'", svcPort)
		}
		portNumber, _ := strconv.Atoi(svcPort)
		if portNumber == 0 {
			return nil, fmt.Errorf("service %s has no port and ingress port is not numerical: '%s'",
				api.ServiceTypeExternalName, svcPort)
		}
		port = &api.ServicePort{
			Port:       int32(portNumber),
			TargetPort: intstr.FromInt(portNumber),
		}
	}
	backend := c.haproxy.Backends().AcquireBackend(namespace, svcName, port.TargetPort.String())
	c.tracker.TrackNames(source.Type, source.FullName(), convtypes.ResourceHABackend, backend.ID)
	// TODO convert backend Port and DNSPort; see also tmpl's server-template
	backend.DNSPort = readDNSPort(svc.Spec.ClusterIP == api.ClusterIPNone, port)
	mapper, found := c.backendAnnotations[backend]
	if !found {
		mapper = c.mapBuilder.NewMapper()
		c.backendAnnotations[backend] = mapper
	}
	// Starting with service annotations, giving precedence
	_, _, _, svcann := c.readAnnotations(source, svc.Annotations)
	mapper.AddAnnotations(&annotations.Source{
		Namespace: namespace,
		Name:      svcName,
		Type:      convtypes.ResourceService,
	}, pathLink, svcann)
	// Merging Ingress annotations
	conflict := mapper.AddAnnotations(source, pathLink, ann)
	if len(conflict) > 0 {
		c.logger.Warn("skipping backend '%s:%s' annotation(s) from %v due to conflict: %v",
			svcName, svcPort, source, conflict)
	}
	// Merging IngressClass Parameters with less priority
	if ingressClass != nil {
		if cfg := c.readParameters(ingressClass); cfg != nil {
			// Using a workaround to add a per resource default config:
			// we add IngressClass Parameters after service and ingress annotations,
			// ignoring conflicts. This would really conflict with other Parameters
			// only if the same host+path is declared twice, but such duplication is
			// already filtered out in the ingress parsing.
			_ = mapper.AddAnnotations(source, pathLink, cfg)
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

func readDNSPort(headlessService bool, port *api.ServicePort) string {
	targetPort := port.TargetPort.String()
	targetPortNum, _ := strconv.Atoi(targetPort)
	if targetPortNum > 0 {
		if headlessService {
			return targetPort
		}
		return strconv.Itoa(int(port.Port))
	}
	if port.Name == "" {
		return targetPort
	}
	return port.Name
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

func (c *converter) syncBackendEndpointHashes(backend *hatypes.Backend) {
	mapper := c.backendAnnotations[backend]
	if mapper == nil || !mapper.Get(ingtypes.BackAssignBackendServerID).Bool() {
		return
	}

	// We need to take the endpoints in some order to resolve hash collisions... TargetRef will do
	eps := make([]*hatypes.Endpoint, len(backend.Endpoints))
	copy(eps, backend.Endpoints)
	sort.SliceStable(eps, func(i, j int) bool {
		ep1 := eps[i]
		ep2 := eps[j]
		return ep1.TargetRef < ep2.TargetRef
	})

	usedPUIDS := map[uint32]struct{}{}
	for _, ep := range eps {
		if ep.TargetRef == "" {
			continue
		}

		var hash uint32
		pod, err := c.cache.GetPod(ep.TargetRef)
		if err == nil {
			hasher := fnv.New32a()
			hasher.Write([]byte(pod.UID))
			// We get a uint32, but haproxy uses an int32 and insists on it being nonnegative,
			// so truncate to 31 bits.
			hash = hasher.Sum32() & 0x7fffffff
		} else {
			hash = 1
			c.logger.Error("error calculating hash value for pod %s; ID assignment won't be stable: %v", ep.TargetRef, err)
		}
		for {
			// If the ID is already used, linearly probe to find one that's not. 0 is an invalid value for haproxy, so we
			// can let endpoints where we don't want a PUID have 0, but we should skip it here.
			_, exists := usedPUIDS[hash]
			if hash != 0 && !exists {
				break
			}
			hash = (hash + 1) & 0x7fffffff
		}
		usedPUIDS[hash] = struct{}{}
		ep.PUID = int32(hash)
	}
}

func (c *converter) addTLS(source *annotations.Source, secretName string) convtypes.CrtFile {
	if secretName != "" {
		tlsFile, err := c.cache.GetTLSSecretPath(
			source.Namespace,
			secretName,
			[]convtypes.TrackingRef{{Context: source.Type, UniqueName: source.FullName()}},
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
		pods, err := c.cache.GetTerminatingPods(svc,
			[]convtypes.TrackingRef{{Context: convtypes.ResourceHABackend, UniqueName: backend.ID}})
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

func (c *converter) readAnnotations(source *annotations.Source, ann map[string]string) (annTCP, annFront, annHost, annBack map[string]string) {
	keys := c.readConfigKeys(source, ann)
	annTCP = make(map[string]string, len(keys))
	annFront = make(map[string]string, len(keys))
	annHost = make(map[string]string, len(keys))
	annBack = make(map[string]string, len(keys))
	for key, value := range keys {
		if _, isTCPAnn := ingtypes.AnnTCP[key]; isTCPAnn {
			annTCP[key] = value
		} else if _, isFrontAnn := ingtypes.AnnFront[key]; isFrontAnn {
			annFront[key] = value
		} else if _, isHostAnn := ingtypes.AnnHost[key]; isHostAnn {
			annHost[key] = value
			// TCP services read both TCP and Host scoped configuration keys
			// in a single step. Our approach is to add all Host keys to the
			// TCP mapper. We're concatenating them here instead of concatenate
			// later when creating the TCP mapper.
			annTCP[key] = value
		} else {
			if _, isDuoAnn := ingtypes.AnnDuo[key]; isDuoAnn {
				annHost[key] = value
			}
			annBack[key] = value
		}
	}
	return annTCP, annFront, annHost, annBack
}

func (c *converter) readConfigKey(ann map[string]string, key string) string {
	for _, prefix := range c.options.AnnotationPrefix {
		if value, found := ann[prefix+"/"+key]; found {
			return value
		}
	}
	return ""
}

func (c *converter) readConfigKeys(source *annotations.Source, ann map[string]string) map[string]string {
	keys := make(map[string]string, len(ann))
	for _, prefix := range c.options.AnnotationPrefix {
		prefix += "/"
		for annKey, annValue := range ann {
			if strings.HasPrefix(annKey, prefix) {
				key := strings.TrimPrefix(annKey, prefix)
				if curValue, found := keys[key]; !found {
					keys[key] = annValue
				} else if curValue != annValue {
					c.logger.Warn(
						"annotation '%s' on %s was ignored due to conflict with another annotation(s) for the same '%s' configuration key",
						annKey, source, key)
				}
			}
		}
	}
	return keys
}

func (c *converter) readParameters(ingressClass *networking.IngressClass) map[string]string {
	ingClassConfig, found := c.ingressClasses[ingressClass.Name]
	if !found {
		ingClassConfig = c.parseParameters(ingressClass)
		if ingClassConfig == nil {
			// error or Parameters reference not found, so create and assign an
			// empty config to avoid re-parse Parameters on every ingress resource
			ingClassConfig = &ingressClassConfig{}
		}
		c.ingressClasses[ingressClass.Name] = ingClassConfig
	}
	return ingClassConfig.config
}

func (c *converter) parseParameters(ingressClass *networking.IngressClass) *ingressClassConfig {
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
	podNamespace := c.cache.GetControllerPod().Namespace
	if podNamespace == "" {
		c.logger.Warn("need to configure POD_NAMESPACE to use ConfigMap on IngressClass '%s'", ingressClass.Name)
		return nil
	}
	configMapName := podNamespace + "/" + parameters.Name
	c.tracker.TrackNames(convtypes.ResourceConfigMap, configMapName, convtypes.ResourceIngressClass, ingressClass.Name)
	configMap, err := c.cache.GetConfigMap(configMapName)
	if err != nil {
		c.logger.Warn("error reading ConfigMap on IngressClass '%s': %v", ingressClass.Name, err)
		return nil
	}
	return &ingressClassConfig{
		resourceType: convtypes.ResourceConfigMap,
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
