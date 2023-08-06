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

package legacy

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/spf13/pflag"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
)

// HAProxyController has internal data of a HAProxyController instance
type HAProxyController struct {
	instance         haproxy.Instance
	logger           *logger
	cache            *k8scache
	metrics          *metrics
	tracker          convtypes.Tracker
	stopCh           <-chan struct{}
	writeModelMutex  sync.Mutex
	ingressQueue     utils.Queue
	acmeQueue        utils.Queue
	reloadQueue      utils.Queue
	leaderelector    types.LeaderElector
	updateCount      int
	reloadCount      int
	controller       *controller.GenericController
	cfg              *controller.Configuration
	configMap        *api.ConfigMap
	converterOptions *convtypes.ConverterOptions
	dynamicConfig    *convtypes.DynamicConfig
}

// NewHAProxyController constructor
func NewHAProxyController() *HAProxyController {
	return &HAProxyController{}
}

// Info provides controller name and repository infos
func (hc *HAProxyController) Info() *ingress.BackendInfo {
	return &ingress.BackendInfo{
		Name:       "HAProxy",
		Release:    version.RELEASE,
		Build:      version.COMMIT,
		Repository: version.REPO,
	}
}

// Start starts the controller
func (hc *HAProxyController) Start() {
	hc.controller = controller.NewIngressController(hc)
	hc.configController()
	hc.startServices()
	hc.logger.Info("HAProxy Ingress successfully initialized")
	//
	<-hc.stopCh
	//
	hc.stopServices()
}

func (hc *HAProxyController) configController() {
	hc.cfg = hc.controller.GetConfig()
	hc.stopCh = hc.controller.GetStopCh()
	hc.controller.SetNewCtrl(hc)
	hc.logger = &logger{depth: 1}
	hc.metrics = createMetrics(hc.cfg.BucketsResponseTime)
	hc.ingressQueue = utils.NewRateLimitingQueue(hc.cfg.RateLimitUpdate, hc.syncIngress)
	hc.tracker = tracker.NewTracker()
	hc.dynamicConfig = &convtypes.DynamicConfig{
		StaticCrossNamespaceSecrets: hc.cfg.AllowCrossNamespace,
	}
	hc.cache = createCache(hc.logger, hc.controller, hc.tracker, hc.dynamicConfig, hc.ingressQueue)
	var acmeSigner acme.Signer
	if hc.cfg.AcmeServer {
		electorID := fmt.Sprintf("%s-%s", hc.cfg.AcmeElectionID, hc.cfg.IngressClass)
		hc.leaderelector = NewLeaderElector(electorID, hc.logger, hc.cache, hc)
		acmeSigner = acme.NewSigner(hc.logger, hc.cache, hc.metrics)
		hc.acmeQueue = utils.NewFailureRateLimitingQueue(
			hc.cfg.AcmeFailInitialDuration,
			hc.cfg.AcmeFailMaxDuration,
			acmeSigner.Notify,
		)
	}
	hc.writeModelMutex = sync.Mutex{}
	if hc.cfg.ReloadInterval.Seconds() > 0 {
		hc.reloadQueue = utils.NewRateLimitingQueue(float32(1/hc.cfg.ReloadInterval.Seconds()), hc.reloadHAProxy)
	}
	masterSocket := hc.cfg.MasterSocket
	if masterSocket == "" && hc.cfg.MasterWorker {
		masterSocket = ingress.DefaultVarRunDirectory + "/master.sock"
	}
	var rootFSPrefix string
	if hc.cfg.LocalFSPrefix != "" {
		rootFSPrefix = "rootfs"
	}
	instanceOptions := haproxy.InstanceOptions{
		RootFSPrefix:      rootFSPrefix,
		LocalFSPrefix:     hc.cfg.LocalFSPrefix,
		HAProxyCfgDir:     hc.cfg.LocalFSPrefix + "/etc/haproxy",
		HAProxyMapsDir:    ingress.DefaultMapsDirectory,
		IsMasterWorker:    hc.cfg.MasterWorker,
		IsExternal:        hc.cfg.MasterSocket != "",
		MasterSocket:      masterSocket,
		AdminSocket:       ingress.DefaultVarRunDirectory + "/admin.sock",
		AcmeSocket:        ingress.DefaultVarRunDirectory + "/acme.sock",
		BackendShards:     hc.cfg.BackendShards,
		AcmeSigner:        acmeSigner,
		AcmeQueue:         hc.acmeQueue,
		ReloadQueue:       hc.reloadQueue,
		LeaderElector:     hc.leaderelector,
		Metrics:           hc.metrics,
		ReloadStrategy:    hc.cfg.ReloadStrategy,
		MaxOldConfigFiles: hc.cfg.MaxOldConfigFiles,
		SortEndpointsBy:   hc.cfg.SortEndpointsBy,
		StopCh:            hc.stopCh,
		TrackInstances:    hc.cfg.TrackOldInstances,
		ValidateConfig:    hc.cfg.ValidateConfig,
	}
	hc.instance = haproxy.CreateInstance(hc.logger, instanceOptions)
	if err := hc.instance.ParseTemplates(); err != nil {
		klog.Exitf("error creating HAProxy instance: %v", err)
	}
	hc.converterOptions = &convtypes.ConverterOptions{
		Logger:           hc.logger,
		Cache:            hc.cache,
		Tracker:          hc.tracker,
		DynamicConfig:    hc.dynamicConfig,
		LocalFSPrefix:    hc.cfg.LocalFSPrefix,
		IsExternal:       instanceOptions.IsExternal,
		MasterSocket:     instanceOptions.MasterSocket,
		AdminSocket:      instanceOptions.AdminSocket,
		AcmeSocket:       instanceOptions.AcmeSocket,
		AnnotationPrefix: hc.cfg.AnnPrefix,
		DefaultBackend:   hc.cfg.DefaultService,
		DefaultCrtSecret: hc.cfg.DefaultSSLCertificate,
		FakeCrtFile:      hc.createFakeCrtFile(),
		FakeCAFile:       hc.createFakeCAFile(),
		DisableKeywords:  utils.Split(hc.cfg.DisableConfigKeywords, ","),
		AcmeTrackTLSAnn:  hc.cfg.AcmeTrackTLSAnn,
		TrackInstances:   hc.cfg.TrackOldInstances,
		HasGatewayA2:     hc.cache.hasGateway(),
		HasGatewayB1:     false,
		EnableEPSlices:   hc.cfg.EnableEndpointSlicesAPI,
	}
}

func (hc *HAProxyController) startServices() {
	hc.cache.RunAsync(hc.stopCh)
	go hc.ingressQueue.Run()
	if hc.reloadQueue != nil {
		go hc.reloadQueue.Run()
	}
	if hc.cfg.StatsCollectProcPeriod.Milliseconds() > 0 {
		go wait.Until(func() {
			hc.instance.CalcIdleMetric()
		}, hc.cfg.StatsCollectProcPeriod, hc.stopCh)
	}
	if hc.leaderelector != nil {
		go hc.leaderelector.Run(hc.stopCh)
	}
	if hc.cfg.AcmeServer {
		server := acme.NewServer(hc.logger, hc.converterOptions.AcmeSocket, hc.cache)
		// TODO move goroutine from the server to the controller
		if err := server.Listen(hc.stopCh); err != nil {
			hc.logger.Fatal("error creating the acme server listener: %v", err)
		}
		go hc.acmeQueue.Run()
		go wait.JitterUntil(func() {
			_, _ = hc.acmeCheck("periodic check")
		}, hc.cfg.AcmeCheckPeriod, 0, false, hc.stopCh)
	}
	hc.controller.StartAsync()
}

func (hc *HAProxyController) stopServices() {
	hc.instance.Shutdown()
	hc.ingressQueue.ShutDown()
	if hc.reloadQueue != nil {
		hc.reloadQueue.ShutDown()
	}
	if hc.acmeQueue != nil {
		hc.acmeQueue.ShutDown()
	}
}

func (hc *HAProxyController) createFakeCrtFile() (tlsFile convtypes.CrtFile) {
	path, hash, crt := hc.controller.CreateDefaultSSLCertificate()
	return convtypes.CrtFile{
		Filename:   path,
		SHA1Hash:   hash,
		CommonName: crt.Subject.CommonName,
		NotAfter:   crt.NotAfter,
	}
}

func (hc *HAProxyController) createFakeCAFile() (crtFile convtypes.CrtFile) {
	fakeCA, _ := ssl.GetFakeSSLCert([]string{}, "Fake CA", []string{})
	fakeCAFile, err := ssl.AddCertAuth("fake-ca", fakeCA, []byte{})
	if err != nil {
		klog.Exitf("error generating fake CA: %v", err)
	}
	crtFile = convtypes.CrtFile{
		Filename: fakeCAFile.PemFileName,
		SHA1Hash: fakeCAFile.PemSHA,
	}
	return crtFile
}

// AcmeCheck ...
func (hc *HAProxyController) AcmeCheck() (int, error) {
	return hc.acmeCheck("external call")
}

// OnStartedLeading ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnStartedLeading(ctx context.Context) {
	_, _ = hc.acmeCheck("started leading")
}

// OnStoppedLeading ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnStoppedLeading() {
	hc.acmeQueue.Clear()
}

// OnNewLeader ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnNewLeader(identity string) {
	hc.logger.Info("leader changed to %s", identity)
}

// Stop shutdown the controller process
func (hc *HAProxyController) Stop() error {
	if hc.cfg.WaitBeforeShutdown > 0 {
		waitBeforeShutdown := time.Duration(hc.cfg.WaitBeforeShutdown) * time.Second
		klog.Infof("Waiting %v before stopping components", waitBeforeShutdown)
		time.Sleep(waitBeforeShutdown)
	}
	err := hc.controller.Stop()
	return err
}

// GetIngressList ...
// implements oldcontroller.NewCtrlIntf
func (hc *HAProxyController) GetIngressList() ([]*networking.Ingress, error) {
	return hc.cache.GetIngressList()
}

// GetSecret ...
// implements oldcontroller.NewCtrlIntf
func (hc *HAProxyController) GetSecret(name string) (*api.Secret, error) {
	return hc.cache.GetSecret(name)
}

// IsValidClass ...
// implements oldcontroller.NewCtrlIntf
func (hc *HAProxyController) IsValidClass(ing *networking.Ingress) bool {
	return hc.cache.IsValidIngress(ing)
}

// Name provides the complete name of the controller
func (hc *HAProxyController) Name() string {
	return "HAProxy Ingress Controller"
}

// DefaultIngressClass returns the ingress class name
func (hc *HAProxyController) DefaultIngressClass() string {
	return "haproxy"
}

// Check health check implementation
func (hc *HAProxyController) Check(_ *http.Request) error {
	return nil
}

// UpdateIngressStatus custom callback used to update the status in an Ingress rule
// If the function returns nil the standard functions will be executed.
func (hc *HAProxyController) UpdateIngressStatus(*networking.Ingress) []networking.IngressLoadBalancerIngress {
	return nil
}

// ConfigureFlags allow to configure more flags before the parsing of
// command line arguments
func (hc *HAProxyController) ConfigureFlags(flags *pflag.FlagSet) {
}

// OverrideFlags allows controller to override command line parameter flags
func (hc *HAProxyController) OverrideFlags(flags *pflag.FlagSet) {
}

// SetConfig receives the ConfigMap the user has configured
func (hc *HAProxyController) SetConfig(configMap *api.ConfigMap) {
	hc.configMap = configMap
}

// SyncIngress sync HAProxy config from a very early stage
func (hc *HAProxyController) syncIngress(item interface{}) {
	if hc.ingressQueue.ShuttingDown() {
		return
	}

	hc.writeModelMutex.Lock()
	defer hc.writeModelMutex.Unlock()

	hc.updateCount++
	hc.logger.Info("starting haproxy update id=%d", hc.updateCount)
	timer := utils.NewTimer(hc.metrics.ControllerProcTime)

	converters.NewConverter(timer, hc.instance.Config(), nil, hc.converterOptions).Sync()

	//
	// update proxy
	//
	hc.instance.AcmeUpdate()
	hc.instance.HAProxyUpdate(timer)
	hc.logger.Info("finish haproxy update id=%d: %s", hc.updateCount, timer.AsString("total"))
}

func (hc *HAProxyController) acmeCheck(source string) (int, error) {
	hc.writeModelMutex.Lock()
	defer hc.writeModelMutex.Unlock()
	return hc.instance.AcmeCheck(source)
}

func (hc *HAProxyController) reloadHAProxy(item interface{}) {
	hc.writeModelMutex.Lock()
	defer hc.writeModelMutex.Unlock()

	hc.reloadCount++
	hc.logger.Info("starting haproxy reload id=%d", hc.reloadCount)
	timer := utils.NewTimer(hc.metrics.ControllerProcTime)

	hc.instance.Reload(timer)
	hc.logger.Info("finish haproxy reload id=%d: %s", hc.reloadCount, timer.AsString("total"))
}
