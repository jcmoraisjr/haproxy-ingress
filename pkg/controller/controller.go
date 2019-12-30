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
	"sort"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	configmapconverter "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/configmap"
	ingressconverter "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress"
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
	cache             *cache
	metrics           *metrics
	stopCh            chan struct{}
	acmeQueue         utils.Queue
	leaderelector     types.LeaderElector
	updateCount       int
	controller        *controller.GenericController
	cfg               *controller.Configuration
	configMap         *api.ConfigMap
	storeLister       *ingress.StoreLister
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
	hc.controller.StartControllers()
	hc.configController()
	hc.startServices()
	hc.controller.Start()
}

func (hc *HAProxyController) configController() {
	if *hc.reloadStrategy == "multibinder" {
		glog.Warningf("multibinder is deprecated, using reusesocket strategy instead. update your deployment configuration")
	}
	hc.cfg = hc.controller.GetConfig()
	hc.stopCh = hc.controller.GetStopCh()
	hc.logger = &logger{depth: 1}
	hc.cache = newCache(hc.cfg.Client, hc.storeLister, hc.controller)
	hc.metrics = createMetrics()
	var acmeSigner acme.Signer
	if hc.cfg.AcmeServer {
		electorID := fmt.Sprintf("%s-%s", hc.cfg.AcmeElectionID, hc.cfg.IngressClass)
		hc.leaderelector = NewLeaderElector(electorID, hc.logger, hc.cache, hc)
		acmeSigner = acme.NewSigner(hc.logger, hc.cache)
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
		AnnotationPrefix: hc.cfg.AnnPrefix,
		DefaultBackend:   hc.cfg.DefaultService,
		DefaultSSLFile:   hc.createDefaultSSLFile(hc.cache),
		AcmeTrackTLSAnn:  hc.cfg.AcmeTrackTLSAnn,
	}
}

func (hc *HAProxyController) startServices() {
	if hc.cfg.StatsCollectProcPeriod.Milliseconds() > 0 {
		go wait.Until(func() {
			hc.instance.CalcIdleMetric()
		}, hc.cfg.StatsCollectProcPeriod, hc.stopCh)
	}
	if hc.leaderelector != nil {
		go hc.leaderelector.Run()
	}
	if hc.cfg.AcmeServer {
		// TODO deduplicate acme socket
		server := acme.NewServer(hc.logger, "/var/run/acme.sock", hc.cache)
		// TODO move goroutine from the server to the controller
		if err := server.Listen(hc.stopCh); err != nil {
			hc.logger.Fatal("error creating the acme server listener: %v", err)
		}
		go hc.acmeQueue.Run()
		go wait.Until(hc.instance.AcmePeriodicCheck, hc.cfg.AcmeCheckPeriod, hc.stopCh)
	}
}

func (hc *HAProxyController) createDefaultSSLFile(cache convtypes.Cache) (tlsFile convtypes.CrtFile) {
	if hc.cfg.DefaultSSLCertificate != "" {
		tlsFile, err := cache.GetTLSSecretPath("", hc.cfg.DefaultSSLCertificate)
		if err == nil {
			return tlsFile
		}
		glog.Warningf("using auto generated fake certificate due to an error reading default TLS certificate: %v", err)
	} else {
		glog.Info("using auto generated fake certificate")
	}
	path, hash, notAfter := hc.controller.CreateDefaultSSLCertificate()
	tlsFile = convtypes.CrtFile{
		Filename: path,
		SHA1Hash: hash,
		NotAfter: notAfter,
	}
	return tlsFile
}

// OnStartedLeading ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnStartedLeading(ctx context.Context) {
	hc.instance.AcmePeriodicCheck()
}

// OnStoppedLeading ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnStoppedLeading() {
}

// OnNewLeader ...
// implements LeaderSubscriber
func (hc *HAProxyController) OnNewLeader(identity string) {
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

// SetListers give access to the store listers
func (hc *HAProxyController) SetListers(lister *ingress.StoreLister) {
	hc.storeLister = lister
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
func (hc *HAProxyController) SyncIngress(item interface{}) error {
	//
	// ingress converter
	//
	hc.updateCount++
	hc.logger.Info("Starting HAProxy update id=%d", hc.updateCount)
	timer := utils.NewTimer(hc.metrics.ControllerProcTime)
	var ingress []*extensions.Ingress
	for _, iing := range hc.storeLister.Ingress.List() {
		ing := iing.(*extensions.Ingress)
		if hc.controller.IsValidClass(ing) {
			ingress = append(ingress, ing)
		}
	}
	sort.Slice(ingress, func(i, j int) bool {
		i1 := ingress[i]
		i2 := ingress[j]
		if i1.CreationTimestamp != i2.CreationTimestamp {
			return i1.CreationTimestamp.Before(&i2.CreationTimestamp)
		}
		return i1.Namespace+"/"+i1.Name < i2.Namespace+"/"+i2.Name
	})
	var globalConfig map[string]string
	if hc.configMap != nil {
		globalConfig = hc.configMap.Data
	}
	ingConverter := ingressconverter.NewIngressConverter(
		hc.converterOptions,
		hc.instance.Config(),
		globalConfig,
	)
	ingConverter.Sync(ingress)
	timer.Tick("parse_ingress")

	//
	// configmap converters
	//
	if hc.cfg.TCPConfigMapName != "" {
		tcpConfigmap, err := hc.storeLister.ConfigMap.GetByName(hc.cfg.TCPConfigMapName)
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
	hc.logger.Info("Finish HAProxy update id=%d: %s", hc.updateCount, timer.AsString("total"))
	return nil
}
