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
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	configmapconverter "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/configmap"
	ingressconverter "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/tracker"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
)

// HAProxyController has internal data of a HAProxyController instance
type HAProxyController struct {
	instance          haproxy.Instance
	logger            *logger
	cache             *k8scache
	metrics           *metrics
	stopCh            chan struct{}
	ingressQueue      utils.Queue
	acmeQueue         utils.Queue
	leaderelector     types.LeaderElector
	updateCount       int
	controller        *controller.GenericController
	cfg               *controller.Configuration
	configMap         *api.ConfigMap
	converterOptions  *ingtypes.ConverterOptions
	reloadStrategy    *string
	maxOldConfigFiles *int
	validateConfig    *bool
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
	if *hc.reloadStrategy == "multibinder" {
		glog.Warningf("multibinder is deprecated, using reusesocket strategy instead. update your deployment configuration")
	}
	hc.cfg = hc.controller.GetConfig()
	hc.stopCh = hc.controller.GetStopCh()
	hc.controller.SetNewCtrl(hc)
	hc.logger = &logger{depth: 1}
	hc.metrics = createMetrics(hc.cfg.BucketsResponseTime)
	hc.ingressQueue = utils.NewRateLimitingQueue(hc.cfg.RateLimitUpdate, hc.syncIngress)
	hc.cache = createCache(
		hc.logger, hc.cfg.Client, hc.controller, hc.ingressQueue,
		hc.cfg.WatchNamespace, hc.cfg.ForceNamespaceIsolation,
		hc.cfg.ResyncPeriod)
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
	instanceOptions := haproxy.InstanceOptions{
		HAProxyCmd:        "haproxy",
		ReloadCmd:         "/haproxy-reload.sh",
		HAProxyConfigFile: "/etc/haproxy/haproxy.cfg",
		AcmeSigner:        acmeSigner,
		AcmeQueue:         hc.acmeQueue,
		LeaderElector:     hc.leaderelector,
		Metrics:           hc.metrics,
		ReloadStrategy:    *hc.reloadStrategy,
		MaxOldConfigFiles: *hc.maxOldConfigFiles,
		ValidateConfig:    *hc.validateConfig,
	}
	hc.instance = haproxy.CreateInstance(hc.logger, instanceOptions)
	if err := hc.instance.ParseTemplates(); err != nil {
		glog.Fatalf("error creating HAProxy instance: %v", err)
	}
	hc.converterOptions = &ingtypes.ConverterOptions{
		Logger:           hc.logger,
		Cache:            hc.cache,
		Tracker:          tracker.NewTracker(),
		AnnotationPrefix: hc.cfg.AnnPrefix,
		DefaultBackend:   hc.cfg.DefaultService,
		DefaultSSLFile:   hc.createDefaultSSLFile(),
		FakeCAFile:       hc.createFakeCAFile(),
		AcmeTrackTLSAnn:  hc.cfg.AcmeTrackTLSAnn,
	}
}

func (hc *HAProxyController) startServices() {
	hc.cache.RunAsync(hc.stopCh)
	go hc.ingressQueue.Run()
	if hc.cfg.StatsCollectProcPeriod.Milliseconds() > 0 {
		go wait.Until(func() {
			hc.instance.CalcIdleMetric()
		}, hc.cfg.StatsCollectProcPeriod, hc.stopCh)
	}
	if hc.leaderelector != nil {
		go hc.leaderelector.Run(hc.stopCh)
	}
	if hc.cfg.AcmeServer {
		// TODO deduplicate acme socket
		server := acme.NewServer(hc.logger, "/var/run/acme.sock", hc.cache)
		// TODO move goroutine from the server to the controller
		if err := server.Listen(hc.stopCh); err != nil {
			hc.logger.Fatal("error creating the acme server listener: %v", err)
		}
		go hc.acmeQueue.Run()
		go wait.JitterUntil(func() {
			_, _ = hc.instance.AcmeCheck("periodic check")
		}, hc.cfg.AcmeCheckPeriod, 0, false, hc.stopCh)
	}
	hc.controller.StartAsync()
}

func (hc *HAProxyController) stopServices() {
	hc.ingressQueue.ShutDown()
	if hc.acmeQueue != nil {
		hc.acmeQueue.ShutDown()
	}
}

func (hc *HAProxyController) createDefaultSSLFile() (tlsFile convtypes.CrtFile) {
	if hc.cfg.DefaultSSLCertificate != "" {
		tlsFile, err := hc.cache.GetTLSSecretPath("", hc.cfg.DefaultSSLCertificate)
		if err == nil {
			return tlsFile
		}
		glog.Warningf("using auto generated fake certificate due to an error reading default TLS certificate: %v", err)
	} else {
		glog.Info("using auto generated fake certificate")
	}
	path, hash, crt := hc.controller.CreateDefaultSSLCertificate()
	tlsFile = convtypes.CrtFile{
		Filename:   path,
		SHA1Hash:   hash,
		CommonName: crt.Subject.CommonName,
		NotAfter:   crt.NotAfter,
	}
	return tlsFile
}

func (hc *HAProxyController) createFakeCAFile() (crtFile convtypes.CrtFile) {
	fakeCA, _ := ssl.GetFakeSSLCert([]string{}, "Fake CA", []string{})
	fakeCAFile, err := ssl.AddCertAuth("fake-ca", fakeCA, []byte{})
	if err != nil {
		glog.Fatalf("error generating fake CA: %v", err)
	}
	crtFile = convtypes.CrtFile{
		Filename: fakeCAFile.PemFileName,
		SHA1Hash: fakeCAFile.PemSHA,
	}
	return crtFile
}

// AcmeCheck ...
func (hc *HAProxyController) AcmeCheck() (int, error) {
	return hc.instance.AcmeCheck("external call")
}

// OnStartedLeading ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnStartedLeading(ctx context.Context) {
	_, _ = hc.instance.AcmeCheck("started leading")
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
		glog.Infof("Waiting %v before stopping components", waitBeforeShutdown)
		time.Sleep(waitBeforeShutdown)
	}
	err := hc.controller.Stop()
	return err
}

// GetIngressList ...
// implements oldcontroller.NewCtrlIntf
func (hc *HAProxyController) GetIngressList() ([]*extensions.Ingress, error) {
	return hc.cache.GetIngressList()
}

// GetSecret ...
// implements oldcontroller.NewCtrlIntf
func (hc *HAProxyController) GetSecret(name string) (*api.Secret, error) {
	return hc.cache.GetSecret(name)
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
func (hc *HAProxyController) UpdateIngressStatus(*extensions.Ingress) []api.LoadBalancerIngress {
	return nil
}

// ConfigureFlags allow to configure more flags before the parsing of
// command line arguments
func (hc *HAProxyController) ConfigureFlags(flags *pflag.FlagSet) {
	hc.reloadStrategy = flags.String("reload-strategy", "reusesocket",
		`Name of the reload strategy. Options are: native or reusesocket (default)`)
	hc.maxOldConfigFiles = flags.Int("max-old-config-files", 0,
		`Maximum old haproxy timestamped config files to allow before being cleaned up. A value <= 0 indicates a single non-timestamped config file will be used`)
	hc.validateConfig = flags.Bool("validate-config", false,
		`Define if the resulting configuration files should be validated when a dynamic update was applied. Default value is false, which means the validation will only happen when HAProxy need to be reloaded.`)
	ingressClass := flags.Lookup("ingress-class")
	if ingressClass != nil {
		ingressClass.Value.Set("haproxy")
		ingressClass.DefValue = "haproxy"
	}
}

// OverrideFlags allows controller to override command line parameter flags
func (hc *HAProxyController) OverrideFlags(flags *pflag.FlagSet) {
	if !(*hc.reloadStrategy == "native" || *hc.reloadStrategy == "reusesocket" || *hc.reloadStrategy == "multibinder") {
		glog.Fatalf("Unsupported reload strategy: %v", *hc.reloadStrategy)
	}
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

	//
	// ingress converter
	//
	hc.updateCount++
	hc.logger.Info("starting HAProxy update id=%d", hc.updateCount)
	timer := utils.NewTimer(hc.metrics.ControllerProcTime)
	ingConverter := ingressconverter.NewIngressConverter(
		hc.converterOptions,
		hc.instance.Config(),
	)
	ingConverter.Sync()
	timer.Tick("parse_ingress")

	//
	// configmap converters
	//
	if hc.cfg.TCPConfigMapName != "" {
		tcpConfigmap, err := hc.cache.GetConfigMap(hc.cfg.TCPConfigMapName)
		if err == nil && tcpConfigmap != nil {
			tcpSvcConverter := configmapconverter.NewTCPServicesConverter(
				hc.logger,
				hc.instance.Config(),
				hc.cache,
			)
			tcpSvcConverter.Sync(tcpConfigmap.Data)
			timer.Tick("parse_tcp_svc")
		} else {
			hc.logger.Error("error reading TCP services: %v", err)
		}
	}

	//
	// update proxy
	//
	hc.instance.Update(timer)
	hc.logger.Info("finish HAProxy update id=%d: %s", hc.updateCount, timer.AsString("total"))
}
