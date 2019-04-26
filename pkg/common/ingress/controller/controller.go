/*
Copyright 2015 The Kubernetes Authors.

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
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"

	apiv1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/bluegreen"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/class"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/connection"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/healthcheck"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/hsts"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxybackend"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/sessionaffinity"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/snippet"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/status"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/k8s"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/task"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/utils"
)

const (
	defUpstreamName = "upstream-default-backend"
	defServerName   = "_"
	rootLocation    = "/"

	fakeCertificate = "default-fake-certificate"
)

var (
	// list of ports that cannot be used by TCP or UDP services
	reservedPorts = []string{"8181", "18080"}

	fakeCertificatePath = ""
	fakeCertificateSHA  = ""

	cloner = conversion.NewCloner()
)

// GenericController holds the boilerplate code required to build an Ingress controlller.
type GenericController struct {
	cfg *Configuration

	defaultBackend *defaults.Backend

	listers         *ingress.StoreLister
	cacheController *cacheController

	annotations annotationExtractor

	recorder record.EventRecorder

	syncQueue *task.Queue

	syncStatus status.Sync

	// local store of SSL certificates
	// (only certificates used in ingress)
	sslCertTracker *sslCertTracker

	syncRateLimiter flowcontrol.RateLimiter

	// stopLock is used to enforce only a single call to Stop is active.
	// Needed because we allow stopping through an http endpoint and
	// allowing concurrent stoppers leads to stack traces.
	stopLock *sync.Mutex

	stopCh chan struct{}

	// runningConfig contains the running configuration in the Backend
	runningConfig *ingress.Configuration

	forceReload int32
}

// Configuration contains all the settings required by an Ingress controller
type Configuration struct {
	Client clientset.Interface

	RateLimitUpdate float32
	ResyncPeriod    time.Duration

	DefaultService string
	IngressClass   string
	Namespace      string
	ConfigMapName  string

	ForceNamespaceIsolation bool
	AllowCrossNamespace     bool
	DisableNodeList         bool

	// optional
	TCPConfigMapName string
	// optional
	UDPConfigMapName      string
	DefaultSSLCertificate string
	VerifyHostname        bool
	DefaultHealthzURL     string
	DefaultIngressClass   string
	// optional
	PublishService string
	// Backend is the particular implementation to be used.
	// (for instance NGINX)
	Backend ingress.Controller

	UpdateStatus           bool
	UseNodeInternalIP      bool
	ElectionID             string
	UpdateStatusOnShutdown bool

	SortBackends bool
}

// newIngressController creates an Ingress controller
func newIngressController(config *Configuration) *GenericController {

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{
		Interface: config.Client.CoreV1().Events(config.Namespace),
	})

	ic := GenericController{
		cfg:             config,
		stopLock:        &sync.Mutex{},
		stopCh:          make(chan struct{}),
		syncRateLimiter: flowcontrol.NewTokenBucketRateLimiter(config.RateLimitUpdate, 1),
		recorder: eventBroadcaster.NewRecorder(scheme.Scheme, apiv1.EventSource{
			Component: "ingress-controller",
		}),
		sslCertTracker: newSSLCertTracker(),
	}

	ic.syncQueue = task.NewTaskQueue(ic.syncIngress)

	ic.listers, ic.cacheController = ic.createListers(config.DisableNodeList)

	if config.UpdateStatus {
		ic.syncStatus = status.NewStatusSyncer(status.Config{
			Client:                 config.Client,
			PublishService:         ic.cfg.PublishService,
			IngressLister:          ic.listers.Ingress,
			ElectionID:             config.ElectionID,
			IngressClass:           config.IngressClass,
			DefaultIngressClass:    config.DefaultIngressClass,
			UpdateStatusOnShutdown: config.UpdateStatusOnShutdown,
			CustomIngressStatus:    ic.cfg.Backend.UpdateIngressStatus,
			UseNodeInternalIP:      ic.cfg.UseNodeInternalIP,
		})
	} else {
		glog.Warning("Update of ingress status is disabled (flag --update-status=false was specified)")
	}
	ic.annotations = newAnnotationExtractor(&ic)

	ic.cfg.Backend.SetListers(ic.listers)

	cloner.RegisterDeepCopyFunc(ingress.GetGeneratedDeepCopyFuncs)

	return &ic
}

// Info returns information about the backend
func (ic GenericController) Info() *ingress.BackendInfo {
	return ic.cfg.Backend.Info()
}

// IngressClass returns information about the backend
func (ic GenericController) IngressClass() string {
	return ic.cfg.IngressClass
}

// GetDefaultBackend returns the default backend
func (ic *GenericController) GetDefaultBackend() defaults.Backend {
	if ic.defaultBackend == nil {
		defaultBackend := ic.cfg.Backend.BackendDefaults()
		ic.defaultBackend = &defaultBackend
	}
	// this can cause a nil dereference due to nil assignment
	// of ic.defaultBackend on syncIngress()
	// we are safe here because all GetDefaultBackend() calls
	// are in the same thread, coming from syncIngress()
	return *ic.defaultBackend
}

// GetPublishService returns the configured service used to set ingress status
func (ic GenericController) GetPublishService() *apiv1.Service {
	s, err := ic.listers.Service.GetByName(ic.cfg.PublishService)
	if err != nil {
		return nil
	}

	return s
}

// GetRecorder returns the event recorder
func (ic GenericController) GetRecorder() record.EventRecorder {
	return ic.recorder
}

// GetSecret searches for a secret in the local secrets Store
func (ic GenericController) GetSecret(name string) (*apiv1.Secret, error) {
	return ic.listers.Secret.GetByName(name)
}

// GetService searches for a service in the local secrets Store
func (ic GenericController) GetService(name string) (*apiv1.Service, error) {
	return ic.listers.Service.GetByName(name)
}

// sync collects all the pieces required to assemble the configuration file and
// then sends the content to the backend (OnUpdate) receiving the populated
// template as response reloading the backend if is required.
func (ic *GenericController) syncIngress(item interface{}) error {
	ic.syncRateLimiter.Accept()

	if ic.syncQueue.IsShuttingDown() {
		return nil
	}

	// force reload of default backend data
	// see GetDefaultBackend()
	ic.defaultBackend = nil

	if element, ok := item.(task.Element); ok {
		if name, ok := element.Key.(string); ok {
			if obj, exists, _ := ic.listers.Ingress.GetByKey(name); exists {
				ing := obj.(*extensions.Ingress)
				ic.readSecrets(ing)
			}
		}
	}

	// Sort ingress rules using the ResourceVersion field
	ings := ic.listers.Ingress.List()
	sort.SliceStable(ings, func(i, j int) bool {
		ir := ings[i].(*extensions.Ingress).ResourceVersion
		jr := ings[j].(*extensions.Ingress).ResourceVersion
		return ir < jr
	})

	// filter ingress rules
	var ingresses []*extensions.Ingress
	for _, ingIf := range ings {
		ing := ingIf.(*extensions.Ingress)
		if !class.IsValid(ing, ic.cfg.IngressClass, ic.cfg.DefaultIngressClass) {
			continue
		}

		ingresses = append(ingresses, ing)
	}

	upstreams, servers := ic.getBackendServers(ingresses)
	var passUpstreams []*ingress.SSLPassthroughBackend

	for _, server := range servers {
		if !server.SSLPassthrough.HasSSLPassthrough {
			continue
		}

		for _, loc := range server.Locations {
			if loc.Path != "" && loc.Path != rootLocation {
				glog.Warningf("ignoring path %v of ssl passthrough host %v", loc.Path, server.Hostname)
				continue
			}
			passUpstreams = append(passUpstreams, &ingress.SSLPassthroughBackend{
				Backend:         loc.Backend,
				HTTPPassBackend: loc.HTTPPassBackend,
				Hostname:        server.Hostname,
				Service:         loc.Service,
				Port:            loc.Port,
			})
			break
		}
	}

	pcfg := ingress.Configuration{
		Backends:            upstreams,
		Servers:             servers,
		TCPEndpoints:        ic.getStreamServices(ic.cfg.TCPConfigMapName, apiv1.ProtocolTCP),
		UDPEndpoints:        ic.getStreamServices(ic.cfg.UDPConfigMapName, apiv1.ProtocolUDP),
		PassthroughBackends: passUpstreams,
	}

	if !ic.isForceReload() && ic.runningConfig != nil && ic.runningConfig.Equal(&pcfg) {
		glog.V(3).Infof("skipping backend reload (no changes detected)")
		return nil
	}

	glog.Infof("backend reload required")

	err := ic.cfg.Backend.OnUpdate(pcfg)
	if err != nil {
		incReloadErrorCount()
		glog.Errorf("unexpected failure restarting the backend: \n%v", err)
		return err
	}

	glog.Infof("ingress backend successfully reloaded...")
	incReloadCount()
	setSSLExpireTime(servers)

	ic.runningConfig = &pcfg
	ic.SetForceReload(false)

	return nil
}

func (ic *GenericController) getStreamServices(configmapName string, proto apiv1.Protocol) []ingress.L4Service {
	glog.V(3).Infof("obtaining information about stream services of type %v located in configmap %v", proto, configmapName)
	if configmapName == "" {
		// no configmap configured
		return []ingress.L4Service{}
	}

	_, _, err := k8s.ParseNameNS(configmapName)
	if err != nil {
		glog.Errorf("unexpected error reading configmap %v: %v", configmapName, err)
		return []ingress.L4Service{}
	}

	configmap, err := ic.listers.ConfigMap.GetByName(configmapName)
	if err != nil {
		glog.Errorf("unexpected error reading configmap %v: %v", configmapName, err)
		return []ingress.L4Service{}
	}

	var svcs []ingress.L4Service
	// k -> port to expose
	// v -> <namespace>/<service name>:<port from service to be used>
	for k, v := range configmap.Data {
		externalPort, err := strconv.Atoi(k)
		if err != nil {
			glog.Warningf("%v is not valid as a TCP/UDP port", k)
			continue
		}

		// this ports used by the backend
		if utils.StringInSlice(k, reservedPorts) {
			glog.Warningf("port %v cannot be used for TCP or UDP services. It is reserved for the Ingress controller", k)
			continue
		}

		// 1: namespace/name of the target service
		// 2: port number
		// 3: "PROXY" means accept proxy protocol
		// 4: "PROXY[-V1|V2]" means send proxy protocol, defaults to V2
		// 5: namespace/name of crt/key secret if should ssl-offload
		nsSvcPort := utils.SplitMin(v, ":", 5)

		nsName := nsSvcPort[0]
		svcPort := nsSvcPort[1]
		if nsName == "" || svcPort == "" {
			glog.Warningf("invalid format (namespace/service-name:port:[PROXY]:[PROXY[-V1|-V2]]:namespace/secret-name) '%v'", v)
			continue
		}

		svcProxyProtocol := ingress.ProxyProtocol{}
		// Proxy protocol is only possible if the service is TCP
		if proto == apiv1.ProtocolTCP {
			svcProxyProtocol.Decode = strings.ToUpper(nsSvcPort[2]) == "PROXY"
			svcProxyProtocol.EncodeVersion = proxyProtocolParamToVersion(nsSvcPort[3])
		} else if nsSvcPort[2] != "" || nsSvcPort[3] != "" {
			glog.Warningf("ignoring PROXY protocol on non TCP service %v:%v", nsName, svcPort)
		}

		crtSecret := nsSvcPort[4]
		if crtSecret != "" {
			_, _, err = k8s.ParseNameNS(crtSecret)
			if err != nil {
				glog.Warningf("%v", err)
				continue
			}
		}

		svcNs, svcName, err := k8s.ParseNameNS(nsName)
		if err != nil {
			glog.Warningf("%v", err)
			continue
		}

		svcObj, svcExists, err := ic.listers.Service.GetByKey(nsName)
		if err != nil {
			glog.Warningf("error getting service %v: %v", nsName, err)
			continue
		}

		if !svcExists {
			glog.Warningf("service %v was not found", nsName)
			continue
		}

		svc := svcObj.(*apiv1.Service)

		crt := &ingress.SSLCert{}
		if crtSecret != "" {
			crt, err = ic.GetCertificate(crtSecret)
			if err != nil {
				glog.Errorf("error reading crt/key of TCP service %v/%v: %v", nsName, svcPort, err)
				continue
			}
		}

		var endps []ingress.Endpoint
		targetPort, err := strconv.Atoi(svcPort)
		if err != nil {
			glog.V(3).Infof("searching service %v endpoints using the name '%v'", svcNs, svcName, svcPort)
			for _, sp := range svc.Spec.Ports {
				if sp.Name == svcPort {
					if sp.Protocol == proto {
						endps = ic.getEndpoints(svc, &sp, proto, &healthcheck.Upstream{})
						break
					}
				}
			}
		} else {
			// we need to use the TargetPort (where the endpoints are running)
			glog.V(3).Infof("searching service %v/%v endpoints using the target port '%v'", svcNs, svcName, targetPort)
			for _, sp := range svc.Spec.Ports {
				if sp.Port == int32(targetPort) {
					if sp.Protocol == proto {
						endps = ic.getEndpoints(svc, &sp, proto, &healthcheck.Upstream{})
						break
					}
				}
			}
		}

		// stream services cannot contain empty upstreams and there is no
		// default backend equivalent
		if len(endps) == 0 {
			glog.Warningf("service %v/%v does not have any active endpoints for port %v and protocol %v", svcNs, svcName, svcPort, proto)
			continue
		}

		svcs = append(svcs, ingress.L4Service{
			Port: externalPort,
			Backend: ingress.L4Backend{
				Name:          svcName,
				Namespace:     svcNs,
				Port:          intstr.FromString(svcPort),
				Protocol:      proto,
				ProxyProtocol: svcProxyProtocol,
				SSLCert:       *crt,
			},
			Endpoints: endps,
		})
	}

	return svcs
}

// getDefaultUpstream returns an upstream associated with the
// default backend service. In case of error retrieving information
// configure the upstream to return http code 503.
func (ic *GenericController) getDefaultUpstream() *ingress.Backend {
	upstream := &ingress.Backend{
		Name:             defUpstreamName,
		BalanceAlgorithm: ic.GetDefaultBackend().BalanceAlgorithm,
		SlotsIncrement:   ic.GetDefaultBackend().BackendServerSlotsIncrement,
	}
	svcKey := ic.cfg.DefaultService
	svcObj, svcExists, err := ic.listers.Service.GetByKey(svcKey)
	if err != nil {
		glog.Warningf("unexpected error searching the default backend %v: %v", ic.cfg.DefaultService, err)
		upstream.Endpoints = append(upstream.Endpoints, ic.cfg.Backend.DefaultEndpoint())
		return upstream
	}

	if !svcExists {
		glog.Warningf("service %v does not exist", svcKey)
		upstream.Endpoints = append(upstream.Endpoints, ic.cfg.Backend.DefaultEndpoint())
		return upstream
	}

	svc := svcObj.(*apiv1.Service)
	endps := ic.getEndpoints(svc, &svc.Spec.Ports[0], apiv1.ProtocolTCP, &healthcheck.Upstream{})
	if len(endps) == 0 {
		glog.Warningf("service %v does not have any active endpoints", svcKey)
		endps = []ingress.Endpoint{ic.cfg.Backend.DefaultEndpoint()}
	}

	upstream.Service = svc
	upstream.Endpoints = append(upstream.Endpoints, endps...)
	return upstream
}

type backendContext struct {
	ing         *extensions.Ingress
	affinity    *sessionaffinity.AffinityConfig
	balance     string
	blueGreen   *bluegreen.Config
	proxy       *proxybackend.Config
	snippet     snippet.Config
	conn        *connection.Config
	slotsInc    int
	useresolver string
}

func (ic *GenericController) createBackendContext(ing *extensions.Ingress) *backendContext {
	return &backendContext{
		affinity:    ic.annotations.SessionAffinity(ing),
		balance:     ic.annotations.BalanceAlgorithm(ing),
		blueGreen:   ic.annotations.BlueGreen(ing),
		proxy:       ic.annotations.ProxyBackend(ing),
		snippet:     ic.annotations.ConfigurationSnippet(ing),
		conn:        ic.annotations.Connection(ing),
		slotsInc:    ic.annotations.SlotsIncrement(ing),
		useresolver: ic.annotations.UseResolver(ing),
	}
}

// getBackendServers returns a list of Upstream and Server to be used by the backend
// An upstream can be used in multiple servers if the namespace, service name and port are the same
func (ic *GenericController) getBackendServers(ingresses []*extensions.Ingress) ([]*ingress.Backend, []*ingress.Server) {
	du := ic.getDefaultUpstream()
	upstreams := ic.createUpstreams(ingresses, du)
	servers := ic.createServers(ingresses, upstreams, du)

	for _, ing := range ingresses {

		ctx := ic.createBackendContext(ing)

		if ing.Spec.Backend != nil {
			upsName := fmt.Sprintf("%v-%v-%v",
				ing.GetNamespace(),
				ing.Spec.Backend.ServiceName,
				ing.Spec.Backend.ServicePort.String())
			ctx.copyBackendAnnotations(upstreams[upsName])
		}

		anns := ic.annotations.Extract(ing)

		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if host == "" {
				host = defServerName
			}
			server := servers[host]
			if server == nil {
				server = servers[defServerName]
			}

			if rule.HTTP == nil &&
				host != defServerName {
				glog.V(3).Infof("ingress rule %v/%v does not contain HTTP rules, using default backend", ing.Namespace, ing.Name)
				continue
			}

			if server.CertificateAuth.CAFileName == "" {
				ca := ic.annotations.CertificateAuth(ing)
				if ca != nil {
					server.CertificateAuth = *ca
					// It is possible that no CAFileName is found in the secret
					if server.CertificateAuth.CAFileName == "" {
						glog.V(3).Infof("secret %v does not contain 'ca.crt', mutual authentication not enabled - ingress rule %v/%v.", server.CertificateAuth.Secret, ing.Namespace, ing.Name)
					}
				}
			} else {
				glog.V(3).Infof("server %v already contains a mutual authentication configuration - ingress rule %v/%v", server.Hostname, ing.Namespace, ing.Name)
			}

			for _, path := range rule.HTTP.Paths {
				upsName := fmt.Sprintf("%v-%v-%v",
					ing.GetNamespace(),
					path.Backend.ServiceName,
					path.Backend.ServicePort.String())

				ups, found := upstreams[upsName]
				if !found {
					// a skipped ssl-passthrough path, just ignore
					continue
				}

				var upshttpPassName string
				if httpPort := server.SSLPassthrough.HTTPPort; server.SSLPassthrough.HasSSLPassthrough && httpPort > 0 {
					if httpPort != path.Backend.ServicePort.IntValue() {
						upshttpPassName = fmt.Sprintf("%v-%v-%v",
							ing.GetNamespace(), path.Backend.ServiceName, httpPort)
						ctx.copyBackendAnnotations(upstreams[upshttpPassName])
					} else {
						// cannot reuse the same port on ssl-passthrough (https) and http
						glog.Warningf("ssl-passthrough http and https ports are the same, ignoring http port")
					}
				}

				// if there's no path defined we assume /
				nginxPath := rootLocation
				if path.Path != "" {
					nginxPath = path.Path
				}

				addLoc := true
				for _, loc := range server.Locations {
					if loc.Path == nginxPath {
						addLoc = false

						if !loc.IsDefBackend {
							glog.V(3).Infof("avoiding replacement of ingress rule %v/%v location %v upstream %v (%v)", ing.Namespace, ing.Name, loc.Path, ups.Name, loc.Backend)
							break
						}

						glog.V(3).Infof("replacing ingress rule %v/%v location %v upstream %v (%v)", ing.Namespace, ing.Name, loc.Path, ups.Name, loc.Backend)
						loc.Backend = ups.Name
						loc.IsDefBackend = false
						loc.Backend = ups.Name
						loc.HTTPPassBackend = upshttpPassName
						loc.Port = ups.Port
						loc.Service = ups.Service
						loc.Ingress = ing
						mergeLocationAnnotations(loc, anns)
						if loc.Redirect.FromToWWW {
							server.RedirectFromToWWW = true
						}
						break
					}
				}
				// is a new location
				if addLoc {
					glog.V(3).Infof("adding location %v in ingress rule %v/%v upstream %v", nginxPath, ing.Namespace, ing.Name, ups.Name)
					loc := &ingress.Location{
						Path:            nginxPath,
						Backend:         ups.Name,
						HTTPPassBackend: upshttpPassName,
						IsDefBackend:    false,
						Service:         ups.Service,
						Port:            ups.Port,
						Ingress:         ing,
					}
					mergeLocationAnnotations(loc, anns)
					if loc.Redirect.FromToWWW {
						server.RedirectFromToWWW = true
					}
					server.Locations = append(server.Locations, loc)
				}

				ctx.copyBackendAnnotations(upstreams[upsName])

				if ctx.affinity.AffinityType == "cookie" {
					locs := ups.SessionAffinity.CookieSessionAffinity.Locations
					if _, ok := locs[host]; !ok {
						locs[host] = []string{}
					}

					locs[host] = append(locs[host], path.Path)
				}
			}
		}
	}

	// update backends (upstreams) with passthrough config
	for _, upstream := range upstreams {
		var isHTTPSfrom []*ingress.Server
		for _, server := range servers {
			for _, location := range server.Locations {
				if upstream.Name == location.Backend {
					if len(upstream.Endpoints) == 0 {
						glog.V(3).Infof("upstream %v does not have any active endpoints. Using default backend", upstream.Name)
						location.Backend = defUpstreamName
					}
					if server.SSLPassthrough.HasSSLPassthrough && location.Path == rootLocation {
						if location.Backend == defUpstreamName {
							glog.Warningf("ignoring ssl passthrough of %v as it doesn't have a default backend (root context)", server.Hostname)
							continue
						}
						isHTTPSfrom = append(isHTTPSfrom, server)
					}
				}
				if upstream.Name == location.HTTPPassBackend && len(upstream.Endpoints) == 0 {
					glog.V(3).Infof("upstream %v does not have any active endpoints. Using default backend", upstream.Name)
					location.HTTPPassBackend = defUpstreamName
				}
			}
		}
		if len(isHTTPSfrom) > 0 {
			upstream.SSLPassthrough = true
		}
	}

	weightBalance(&upstreams, ic.listers.Pod)

	aUpstreams := make([]*ingress.Backend, 0, len(upstreams))
	// create the list of upstreams and skip those without endpoints
	for _, upstream := range upstreams {
		if len(upstream.Endpoints) == 0 {
			continue
		}
		aUpstreams = append(aUpstreams, upstream)
	}

	if ic.cfg.SortBackends {
		sort.SliceStable(aUpstreams, func(a, b int) bool {
			return aUpstreams[a].Name < aUpstreams[b].Name
		})
	}

	aServers := make([]*ingress.Server, 0, len(servers))
	for _, value := range servers {
		sort.SliceStable(value.Locations, func(i, j int) bool {
			return value.Locations[i].Path > value.Locations[j].Path
		})
		aServers = append(aServers, value)
	}

	sort.SliceStable(aServers, func(i, j int) bool {
		return aServers[i].Hostname < aServers[j].Hostname
	})

	return aUpstreams, aServers
}

func (ctx *backendContext) copyBackendAnnotations(backend *ingress.Backend) {

	if backend.SessionAffinity.AffinityType == "" {
		backend.SessionAffinity.AffinityType = ctx.affinity.AffinityType
	}

	if ctx.affinity.AffinityType == "cookie" {
		backend.SessionAffinity.CookieSessionAffinity.Name = ctx.affinity.CookieConfig.Name
		backend.SessionAffinity.CookieSessionAffinity.Strategy = ctx.affinity.CookieConfig.Strategy
		backend.SessionAffinity.CookieSessionAffinity.Hash = ctx.affinity.CookieConfig.Hash
	}

	if backend.BalanceAlgorithm == "" {
		backend.BalanceAlgorithm = ctx.balance
	}

	if len(backend.BlueGreen.DeployWeight) == 0 {
		backend.BlueGreen = *ctx.blueGreen
	}

	if backend.Proxy.ProxyProtocol == "" {
		backend.Proxy.ProxyProtocol = ctx.proxy.ProxyProtocol
	}

	if len(backend.ConfigurationSnippet.Backend) == 0 {
		backend.ConfigurationSnippet = ctx.snippet
	}

	if backend.Connection.MaxConnServer == 0 {
		backend.Connection.MaxConnServer = ctx.conn.MaxConnServer
	}
	if backend.Connection.MaxQueueServer == 0 {
		backend.Connection.MaxQueueServer = ctx.conn.MaxQueueServer
	}
	if backend.Connection.TimeoutQueue == "" {
		backend.Connection.TimeoutQueue = ctx.conn.TimeoutQueue
	}

	if backend.SlotsIncrement == 0 {
		backend.SlotsIncrement = ctx.slotsInc
	}

	if backend.UseResolver == "" {
		backend.UseResolver = ctx.useresolver
	}
}

// GetAuthCertificate is used by the auth-tls annotations to get a cert from a secret
func (ic GenericController) GetAuthCertificate(name string) (*resolver.AuthSSLCert, error) {
	cert, err := ic.GetCertificate(name)
	if err != nil {
		return &resolver.AuthSSLCert{}, err
	}
	return &resolver.AuthSSLCert{
		Secret:      name,
		CrtFileName: cert.PemFileName,
		CAFileName:  cert.CAFileName,
		PemSHA:      cert.PemSHA,
	}, nil
}

// GetCertificate get a SSLCert object from a secret name
func (ic *GenericController) GetCertificate(name string) (*ingress.SSLCert, error) {
	crt, exists := ic.sslCertTracker.Get(name)
	if !exists {
		ic.syncSecret(name)
		crt, exists = ic.sslCertTracker.Get(name)
	}
	if exists {
		return crt.(*ingress.SSLCert), nil
	}
	if _, err := ic.listers.Secret.GetByName(name); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("secret '%v' have neither ca.crt nor tls.crt/tls.key pair", name)
}

// GetFullResourceName add the currentNamespace prefix if name doesn't provide one
// and AllowCrossNamespace is allowing this
func (ic GenericController) GetFullResourceName(name, currentNamespace string) string {
	if name == "" {
		return ""
	}
	if strings.Index(name, "/") == -1 {
		// there isn't a slash, just the resourcename
		return fmt.Sprintf("%v/%v", currentNamespace, name)
	} else if !ic.cfg.AllowCrossNamespace {
		// there IS a slash: namespace/resourcename
		// and cross namespace isn't allowed
		ns := strings.Split(name, "/")[0]
		if ns != currentNamespace {
			// concat currentNamespace in order to fail resource reading
			return fmt.Sprintf("%v/%v", currentNamespace, name)
		}
	}
	return name
}

// createUpstreams creates the NGINX upstreams for each service referenced in
// Ingress rules. The servers inside the upstream are endpoints.
func (ic *GenericController) createUpstreams(data []*extensions.Ingress, du *ingress.Backend) map[string]*ingress.Backend {
	upstreams := make(map[string]*ingress.Backend)
	upstreams[defUpstreamName] = du

	for _, ing := range data {
		secUpstream := ic.annotations.SecureUpstream(ing)
		hz := ic.annotations.HealthCheck(ing)
		serviceUpstream := ic.annotations.ServiceUpstream(ing)
		upstreamHashBy := ic.annotations.UpstreamHashBy(ing)
		sslpt := ic.annotations.SSLPassthrough(ing)

		var defBackend string
		if ing.Spec.Backend != nil {
			defBackend = fmt.Sprintf("%v-%v-%v",
				ing.GetNamespace(),
				ing.Spec.Backend.ServiceName,
				ing.Spec.Backend.ServicePort.String())

			glog.V(3).Infof("creating upstream %v", defBackend)
			upstreams[defBackend] = newUpstream(defBackend)
			svcKey := fmt.Sprintf("%v/%v", ing.GetNamespace(), ing.Spec.Backend.ServiceName)

			// Add the service cluster endpoint as the upstream instead of individual endpoints
			// if the serviceUpstream annotation is enabled
			if serviceUpstream {
				endpoint, err := ic.getServiceClusterEndpoint(svcKey, ing.Spec.Backend)
				if err != nil {
					glog.Errorf("Failed to get service cluster endpoint for service %s: %v", svcKey, err)
				} else {
					upstreams[defBackend].Endpoints = []ingress.Endpoint{endpoint}
				}
			}

			if len(upstreams[defBackend].Endpoints) == 0 {
				endps, err := ic.serviceEndpoints(svcKey, ing.Spec.Backend.ServicePort.String(), hz)
				upstreams[defBackend].Endpoints = append(upstreams[defBackend].Endpoints, endps...)
				if err != nil {
					glog.Warningf("error creating upstream %v: %v", defBackend, err)
				}
			}

		}

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				backends := []extensions.IngressBackend{path.Backend}
				if sslpt.HasSSLPassthrough {
					if path.Path != "" && path.Path != rootLocation {
						glog.Warningf(
							"ignoring path '%v' from sslpassthrough ingress %v/%v",
							path.Path, ing.Namespace, ing.Name)
						continue
					}
					if sslpt.HTTPPort > 0 {
						backends = append(backends, extensions.IngressBackend{
							ServiceName: path.Backend.ServiceName,
							ServicePort: intstr.FromInt(sslpt.HTTPPort),
						})
					}
				}

				// a dumb loop just to avoid ctrl+c ctrl+v.
				// syncIngress and core dependencies need
				// to be rewritten from scratch in order
				// to fix coupling and improve cohesion.
				for _, backend := range backends {
					name := fmt.Sprintf("%v-%v-%v",
						ing.GetNamespace(),
						backend.ServiceName,
						backend.ServicePort.String())

					if _, ok := upstreams[name]; ok {
						continue
					}

					glog.V(3).Infof("creating upstream %v", name)
					upstreams[name] = newUpstream(name)
					upstreams[name].Port = backend.ServicePort

					if secUpstream != nil && !upstreams[name].Secure.IsSecure {
						upstreams[name].Secure = *secUpstream
					}

					if upstreams[name].UpstreamHashBy == "" {
						upstreams[name].UpstreamHashBy = upstreamHashBy
					}

					svcKey := fmt.Sprintf("%v/%v", ing.GetNamespace(), backend.ServiceName)

					// Add the service cluster endpoint as the upstream instead of individual endpoints
					// if the serviceUpstream annotation is enabled
					if serviceUpstream {
						endpoint, err := ic.getServiceClusterEndpoint(svcKey, &backend)
						if err != nil {
							glog.Errorf("failed to get service cluster endpoint for service %s: %v", svcKey, err)
						} else {
							upstreams[name].Endpoints = []ingress.Endpoint{endpoint}
						}
					}

					if len(upstreams[name].Endpoints) == 0 {
						endp, err := ic.serviceEndpoints(svcKey, backend.ServicePort.String(), hz)
						if err != nil {
							glog.Warningf("error obtaining service endpoints: %v", err)
							continue
						}
						upstreams[name].Endpoints = endp
					}

					s, err := ic.listers.Service.GetByName(svcKey)
					if err != nil {
						glog.Warningf("error obtaining service: %v", err)
						continue
					}

					upstreams[name].Service = s
				}
			}
		}
	}

	return upstreams
}

func (ic *GenericController) getServiceClusterEndpoint(svcKey string, backend *extensions.IngressBackend) (endpoint ingress.Endpoint, err error) {
	svcObj, svcExists, err := ic.listers.Service.GetByKey(svcKey)

	if !svcExists {
		return endpoint, fmt.Errorf("service %v does not exist", svcKey)
	}

	svc := svcObj.(*apiv1.Service)
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return endpoint, fmt.Errorf("no ClusterIP found for service %s", svcKey)
	}

	endpoint.Address = svc.Spec.ClusterIP

	// If the service port in the ingress uses a name, lookup
	// the actual port in the service spec
	if backend.ServicePort.Type == intstr.String {
		var port int32 = -1
		for _, svcPort := range svc.Spec.Ports {
			if svcPort.Name == backend.ServicePort.String() {
				port = svcPort.Port
				break
			}
		}
		if port == -1 {
			return endpoint, fmt.Errorf("no port mapped for service %s and port name %s", svc.Name, backend.ServicePort.String())
		}
		endpoint.Port = fmt.Sprintf("%d", port)
	} else {
		endpoint.Port = backend.ServicePort.String()
	}

	return endpoint, err
}

// serviceEndpoints returns the upstream servers (endpoints) associated
// to a service.
func (ic *GenericController) serviceEndpoints(svcKey, backendPort string,
	hz *healthcheck.Upstream) ([]ingress.Endpoint, error) {
	svc, err := ic.listers.Service.GetByName(svcKey)

	var upstreams []ingress.Endpoint
	if err != nil {
		return upstreams, fmt.Errorf("error getting service %v from the cache: %v", svcKey, err)
	}

	glog.V(3).Infof("obtaining port information for service %v", svcKey)
	for _, servicePort := range svc.Spec.Ports {
		// targetPort could be a string, use the name or the port (int)
		if strconv.Itoa(int(servicePort.Port)) == backendPort ||
			servicePort.TargetPort.String() == backendPort ||
			servicePort.Name == backendPort {

			endps := ic.getEndpoints(svc, &servicePort, apiv1.ProtocolTCP, hz)
			if len(endps) == 0 {
				glog.Warningf("service %v does not have any active endpoints", svcKey)
				endps = []ingress.Endpoint{ic.cfg.Backend.DefaultEndpoint()}
			}

			if ic.cfg.SortBackends {
				sort.SliceStable(endps, func(i, j int) bool {
					iName := endps[i].Address
					jName := endps[j].Address
					if iName != jName {
						return iName < jName
					}

					return endps[i].Port < endps[j].Port
				})
			}
			upstreams = append(upstreams, endps...)
			break
		}
	}

	// Ingress with an ExternalName service and no port defined in the service.
	if len(svc.Spec.Ports) == 0 && svc.Spec.Type == apiv1.ServiceTypeExternalName {
		externalPort, err := strconv.Atoi(backendPort)
		if err != nil {
			glog.Warningf("only numeric ports are allowed in ExternalName services: %v is not valid as a TCP/UDP port", backendPort)
			return upstreams, nil
		}

		servicePort := apiv1.ServicePort{
			Protocol:   "TCP",
			Port:       int32(externalPort),
			TargetPort: intstr.FromString(backendPort),
		}
		endps := ic.getEndpoints(svc, &servicePort, apiv1.ProtocolTCP, hz)
		if len(endps) == 0 {
			glog.Warningf("service %v does not have any active endpoints", svcKey)
			return upstreams, nil
		}

		upstreams = append(upstreams, endps...)
		return upstreams, nil
	}

	if !ic.cfg.SortBackends {
		rand.Seed(time.Now().UnixNano())
		for i := range upstreams {
			j := rand.Intn(i + 1)
			upstreams[i], upstreams[j] = upstreams[j], upstreams[i]
		}
	}

	return upstreams, nil
}

// createServers initializes a map that contains information about the list of
// FDQN referenced by ingress rules and the common name field in the referenced
// SSL certificates. Each server is configured with location / using a default
// backend specified by the user or the one inside the ingress spec.
func (ic *GenericController) createServers(data []*extensions.Ingress,
	upstreams map[string]*ingress.Backend,
	du *ingress.Backend) map[string]*ingress.Server {

	servers := make(map[string]*ingress.Server, len(data))
	// If a server has a hostname equivalent to a pre-existing alias, then we
	// remove the alias to avoid conflicts.
	aliases := make(map[string]string, len(data))

	bdef := ic.GetDefaultBackend()
	proxyCfg := proxy.Configuration{
		BodySize:         bdef.ProxyBodySize,
		ConnectTimeout:   bdef.ProxyConnectTimeout,
		SendTimeout:      bdef.ProxySendTimeout,
		ReadTimeout:      bdef.ProxyReadTimeout,
		BufferSize:       bdef.ProxyBufferSize,
		CookieDomain:     bdef.ProxyCookieDomain,
		CookiePath:       bdef.ProxyCookiePath,
		NextUpstream:     bdef.ProxyNextUpstream,
		RequestBuffering: bdef.ProxyRequestBuffering,
	}
	hstsCfg := hsts.Config{
		Enable:     bdef.HSTS,
		Subdomains: bdef.HSTSIncludeSubdomains,
		MaxAge:     bdef.HSTSMaxAge,
		Preload:    bdef.HSTSPreload,
	}

	// generated on Start() with createDefaultSSLCertificate()
	defaultPemFileName := fakeCertificatePath
	defaultPemSHA := fakeCertificateSHA

	// Tries to fetch the default Certificate from nginx configuration.
	// If it does not exists, use the ones generated on Start()
	if secret, err := ic.listers.Secret.GetByName(ic.cfg.DefaultSSLCertificate); err == nil {
		defaultCertificate, err := ic.getPemCertificate(secret)
		if err == nil {
			defaultPemFileName = defaultCertificate.PemFileName
			defaultPemSHA = defaultCertificate.PemSHA
		}
	}

	// initialize the default server
	servers[defServerName] = &ingress.Server{
		Hostname:       defServerName,
		SSLCertificate: defaultPemFileName,
		SSLPemChecksum: defaultPemSHA,
		Locations: []*ingress.Location{
			{
				Path:         rootLocation,
				IsDefBackend: true,
				Backend:      du.Name,
				Proxy:        proxyCfg,
				HSTS:         hstsCfg,
				Service:      du.Service,
			},
		}}

	// initialize all the servers
	for _, ing := range data {

		// check if ssl passthrough is configured
		sslpt := ic.annotations.SSLPassthrough(ing)

		// default upstream server
		un := du.Name

		if ing.Spec.Backend != nil {
			// replace default backend
			defUpstream := fmt.Sprintf("%v-%v-%v", ing.GetNamespace(), ing.Spec.Backend.ServiceName, ing.Spec.Backend.ServicePort.String())
			if backendUpstream, ok := upstreams[defUpstream]; ok {
				un = backendUpstream.Name

				// Special case:
				// ingress only with a backend and no rules
				// this case defines a "catch all" server
				defLoc := servers[defServerName].Locations[0]
				if defLoc.IsDefBackend && len(ing.Spec.Rules) == 0 {
					defLoc.IsDefBackend = false
					defLoc.Backend = backendUpstream.Name
					defLoc.Service = backendUpstream.Service
				}
			}
		}

		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if host == "" {
				host = defServerName
			}
			if _, ok := servers[host]; ok {
				// server already configured
				continue
			}

			servers[host] = &ingress.Server{
				Hostname: host,
				Locations: []*ingress.Location{
					{
						Path:         rootLocation,
						IsDefBackend: true,
						Backend:      un,
						Proxy:        proxyCfg,
						HSTS:         hstsCfg,
						Service:      &apiv1.Service{},
					},
				},
				SSLPassthrough: *sslpt,
			}
		}
	}

	// configure default location, alias, and SSL
	for _, ing := range data {
		// setup server-alias based on annotations
		aliasCfg := ic.annotations.Alias(ing)
		aliasHost := aliasCfg.Host
		srvsnippet := ic.annotations.ServerSnippet(ing)

		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if host == "" {
				host = defServerName
			}

			// setup server aliases
			if aliasHost != "" {
				if servers[host].Alias.Host == "" {
					servers[host].Alias.Host = aliasHost
					if _, ok := aliases[aliasHost]; !ok {
						aliases[aliasHost] = host
					}
				} else {
					glog.Warningf("ingress %v/%v for host %v contains an Alias but one has already been configured.",
						ing.Namespace, ing.Name, host)
				}
			}
			if servers[host].Alias.Regex == "" {
				servers[host].Alias.Regex = aliasCfg.Regex
			} else if aliasCfg.Regex != "" {
				glog.Warningf("ingress %v/%v for host %v contains an Alias Regex but one has already been configured.",
					ing.Namespace, ing.Name, host)
			}

			//notifying the user that it has already been configured.
			if servers[host].ServerSnippet != "" && srvsnippet != "" {
				glog.Warningf("ingress %v/%v for host %v contains a Server Snippet section that it has already been configured.",
					ing.Namespace, ing.Name, host)
			}

			// only add a server snippet if the server does not have one previously configured
			if servers[host].ServerSnippet == "" && srvsnippet != "" {
				servers[host].ServerSnippet = srvsnippet
			}

			// only add a certificate if the server does not have one previously configured
			if servers[host].SSLCertificate != "" {
				continue
			}

			if len(ing.Spec.TLS) == 0 {
				glog.V(3).Infof("ingress %v/%v for host %v does not contains a TLS section", ing.Namespace, ing.Name, host)
				continue
			}

			tlsSecretName := ""
			found := false
			for _, tls := range ing.Spec.TLS {
				if sets.NewString(tls.Hosts...).Has(host) {
					tlsSecretName = tls.SecretName
					found = true
					break
				}
			}

			if !found {
				glog.V(3).Infof("ingress %v/%v for host %v contains a TLS section but none of the host match",
					ing.Namespace, ing.Name, host)
				continue
			}

			// From now we want TLS. If assigning a custom
			// crt failed we end up with the default cert
			servers[host].SSLCertificate = defaultPemFileName
			servers[host].SSLPemChecksum = defaultPemSHA

			if tlsSecretName == "" {
				glog.V(3).Infof("host %v is listed on tls section but secretName is empty. Using default cert", host)
				continue
			}

			key := ic.GetFullResourceName(tlsSecretName, ing.Namespace)
			bc, exists := ic.sslCertTracker.Get(key)
			if !exists {
				glog.Warningf("ssl certificate \"%v\" does not exist in local store. Using the default cert", key)
				continue
			}

			cert := bc.(*ingress.SSLCert)
			if ic.cfg.VerifyHostname {
				err := cert.Certificate.VerifyHostname(host)
				if err != nil {
					glog.Warningf("ssl certificate %v does not contain a Subject Alternative Name for host %v. Using the default cert", key, host)
					continue
				}
			}

			servers[host].SSLCertificate = cert.PemFileName
			servers[host].SSLPemChecksum = cert.PemSHA
			servers[host].SSLExpireTime = cert.ExpireTime

			if cert.ExpireTime.Before(time.Now().Add(240 * time.Hour)) {
				glog.Warningf("ssl certificate for host %v is about to expire in 10 days", host)
			}
		}
	}

	for alias, host := range aliases {
		if _, found := servers[alias]; found {
			glog.Warningf("There is a conflict with server hostname '%v' and alias '%v' (in server %v). Removing alias to avoid conflicts.", alias, host)
			servers[host].Alias.Host = ""
		}
	}

	return servers
}

// getEndpoints returns a list of <endpoint ip>:<port> for a given service/target port combination.
func (ic *GenericController) getEndpoints(
	s *apiv1.Service,
	servicePort *apiv1.ServicePort,
	proto apiv1.Protocol,
	hz *healthcheck.Upstream) []ingress.Endpoint {

	var upsServers []ingress.Endpoint

	// avoid duplicated upstream servers when the service
	// contains multiple port definitions sharing the same
	// targetport.
	adus := make(map[string]bool)

	// ExternalName services
	if s.Spec.Type == apiv1.ServiceTypeExternalName {
		glog.V(3).Info("Ingress using a service %v of type=ExternalName : %v", s.Name)

		targetPort := servicePort.TargetPort.IntValue()
		// check for invalid port value
		if targetPort <= 0 {
			glog.Errorf("ExternalName service with an invalid port: %v", targetPort)
			return upsServers
		}

		if net.ParseIP(s.Spec.ExternalName) == nil {
			_, err := net.LookupHost(s.Spec.ExternalName)
			if err != nil {
				glog.Errorf("unexpected error resolving host %v: %v", s.Spec.ExternalName, err)
				return upsServers
			}
		}

		return append(upsServers, ingress.Endpoint{
			Address:     s.Spec.ExternalName,
			Port:        fmt.Sprintf("%v", targetPort),
			Draining:    false,
			MaxFails:    hz.MaxFails,
			FailTimeout: hz.FailTimeout,
		})
	}

	glog.V(3).Infof("getting endpoints for service %v/%v and port %v", s.Namespace, s.Name, servicePort.String())
	ep, err := ic.listers.Endpoint.GetServiceEndpoints(s)
	if err != nil {
		glog.Warningf("unexpected error obtaining service endpoints: %v", err)
		return upsServers
	}

	for _, ss := range ep.Subsets {
		for _, epPort := range ss.Ports {

			if !reflect.DeepEqual(epPort.Protocol, proto) {
				continue
			}

			var targetPort int32

			if servicePort.Name == "" {
				// ServicePort.Name is optional if there is only one port
				targetPort = epPort.Port
			} else if servicePort.Name == epPort.Name {
				targetPort = epPort.Port
			}

			// check for invalid port value
			if targetPort <= 0 {
				continue
			}

			upsServers = addIngressEndpoint(ss.Addresses, false, targetPort, adus, hz, upsServers)
			if ic.cfg.Backend.DrainSupport() {
				upsServers = addIngressEndpoint(ss.NotReadyAddresses, true, targetPort, adus, hz, upsServers)
			}
		}
	}

	if ic.cfg.Backend.DrainSupport() {
		terminatingPods, err := ic.listers.Pod.GetTerminatingServicePods(s)
		if err != nil {
			glog.Warningf("unexpected error obtaining terminating pods for service: %v", err)
			return upsServers
		}

		// For each pod associated with this service that is in the terminating state, add it to the output in the draining state
		// This will allow persistent traffic to be sent to the server during the termination grace period.
		for _, tp := range terminatingPods {
			targetPort := determineTerminatingPodTargetPort(&tp, servicePort, proto)
			ep := fmt.Sprintf("%v:%v", tp.Status.PodIP, targetPort)
			if _, exists := adus[ep]; exists {
				continue
			}
			ups := ingress.Endpoint{
				Address:     tp.Status.PodIP,
				Port:        fmt.Sprintf("%v", targetPort),
				Draining:    true,
				MaxFails:    hz.MaxFails,
				FailTimeout: hz.FailTimeout,
				Target: &apiv1.ObjectReference{
					Kind:            tp.Kind,
					Namespace:       tp.Namespace,
					Name:            tp.Name,
					UID:             tp.UID,
					ResourceVersion: tp.ResourceVersion,
				},
			}
			upsServers = append(upsServers, ups)
			adus[ep] = true
		}
	}

	glog.V(3).Infof("endpoints found: %v", upsServers)
	return upsServers
}

func determineTerminatingPodTargetPort(tp *apiv1.Pod, servicePort *apiv1.ServicePort, proto apiv1.Protocol) int32 {
	// Use the int value of the target port by default
	targetPort := int32(servicePort.TargetPort.IntValue())
	// If the target port value is a string and the int value can't be computed,
	// then look it up by iterating through the pod's containers looking for the match
	if targetPort <= 0 {
		portStr := servicePort.TargetPort.String()
		glog.V(4).Infof("Searching for %v on %v", portStr, tp.Name)
		for _, tpc := range tp.Spec.Containers {
			for _, tpcPort := range tpc.Ports {
				if !reflect.DeepEqual(tpcPort.Protocol, proto) {
					continue
				}
				if portStr == tpcPort.Name {
					targetPort = tpcPort.ContainerPort
					glog.V(4).Infof("Found port match for %v on container %v port %v", portStr, tpc.Name, tpcPort)
					break
				}
			}
		}
	}
	// If we still couldn't find a target port by looking through the containers port definitions
	// then use the port value from the service as a fallback.
	if targetPort <= 0 {
		targetPort = servicePort.Port
		glog.Warningf("Using targetPort of %v for terminating pod %v since we were unable to find the named port %v on %v",
			targetPort, tp.Name, servicePort.TargetPort.String(), tp)
	}
	return targetPort
}

func addIngressEndpoint(addresses []apiv1.EndpointAddress,
	draining bool,
	targetPort int32,
	adus map[string]bool,
	hz *healthcheck.Upstream,
	upsServers []ingress.Endpoint) []ingress.Endpoint {
	for _, epAddress := range addresses {
		ep := fmt.Sprintf("%v:%v", epAddress.IP, targetPort)
		if _, exists := adus[ep]; exists {
			continue
		}
		ups := ingress.Endpoint{
			Address:     epAddress.IP,
			Port:        fmt.Sprintf("%v", targetPort),
			Draining:    draining,
			MaxFails:    hz.MaxFails,
			FailTimeout: hz.FailTimeout,
			Target:      epAddress.TargetRef,
		}
		upsServers = append(upsServers, ups)
		adus[ep] = true
	}
	return upsServers
}

// readSecrets extracts information about secrets from an Ingress rule
func (ic *GenericController) readSecrets(ing *extensions.Ingress) {
	for _, tls := range ing.Spec.TLS {
		if tls.SecretName != "" {
			key := ic.GetFullResourceName(tls.SecretName, ing.Namespace)
			ic.syncSecret(key)
		}
	}
	if name, _ := parser.GetStringAnnotation("ingress.kubernetes.io/auth-tls-secret", ing); name != "" {
		key := ic.GetFullResourceName(name, ing.Namespace)
		ic.syncSecret(key)
	}
}

// Stop stops the loadbalancer controller.
func (ic GenericController) Stop() error {
	ic.stopLock.Lock()
	defer ic.stopLock.Unlock()

	// Only try draining the workqueue if we haven't already.
	if !ic.syncQueue.IsShuttingDown() {
		glog.Infof("shutting down controller queues")
		close(ic.stopCh)
		go ic.syncQueue.Shutdown()
		if ic.syncStatus != nil {
			ic.syncStatus.Shutdown()
		}
		return nil
	}

	return fmt.Errorf("shutdown already in progress")
}

// Start starts the Ingress controller.
func (ic *GenericController) Start() {
	glog.Infof("starting Ingress controller")

	ic.cacheController.Run(ic.stopCh)

	createDefaultSSLCertificate()

	time.Sleep(5 * time.Second)
	// initial sync of secrets to avoid unnecessary reloads
	glog.Info("running initial sync of secrets")
	for _, obj := range ic.listers.Ingress.List() {
		ing := obj.(*extensions.Ingress)

		if !class.IsValid(ing, ic.cfg.IngressClass, ic.cfg.DefaultIngressClass) {
			a, _ := parser.GetStringAnnotation(class.IngressKey, ing)
			glog.V(2).Infof("ignoring add for ingress %v based on annotation %v with value %v", ing.Name, class.IngressKey, a)
			continue
		}

		ic.readSecrets(ing)
	}

	go ic.syncQueue.Run(time.Second, ic.stopCh)

	if ic.syncStatus != nil {
		go ic.syncStatus.Run(ic.stopCh)
	}

	go wait.Until(ic.checkMissingSecrets, 30*time.Second, ic.stopCh)

	// force initial sync
	ic.syncQueue.Enqueue(&extensions.Ingress{})

	<-ic.stopCh
}

func (ic *GenericController) isForceReload() bool {
	return atomic.LoadInt32(&ic.forceReload) != 0
}

// SetForceReload ...
func (ic *GenericController) SetForceReload(shouldReload bool) {
	if shouldReload {
		atomic.StoreInt32(&ic.forceReload, 1)
		ic.syncQueue.Enqueue(&extensions.Ingress{})
	} else {
		atomic.StoreInt32(&ic.forceReload, 0)
	}
}

func createDefaultSSLCertificate() {
	defCert, defKey := ssl.GetFakeSSLCert()
	c, err := ssl.AddOrUpdateCertAndKey(fakeCertificate, defCert, defKey, []byte{})
	if err != nil {
		glog.Fatalf("Error generating self signed certificate: %v", err)
	}

	fakeCertificateSHA = c.PemSHA
	fakeCertificatePath = c.PemFileName
}
