/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package services

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	ctrlutils "github.com/jcmoraisjr/haproxy-ingress/pkg/controller/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils/workqueue"
)

// Services ...
type Services struct {
	client.Client
	Config *config.Config
	//
	legacylogger *lfactory
	log          logr.Logger
	//
	acmeClient   *svcAcmeClient
	acmeServer   *svcAcmeServer
	cache        *c
	converterOpt *convtypes.ConverterOptions
	instance     haproxy.Instance
	metrics      *metrics
	modelMutex   sync.Mutex
	reloadCount  int
	reloadQueue  *workqueue.WorkQueue[any]
	svcleader    *svcLeader
	svchealthz   *svcHealthz
	svcstatus    *svcStatusUpdater
	svcstatusing *svcStatusIng
	updateCount  int
}

// SetupWithManager ...
func (s *Services) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.legacylogger = initLogFactory(ctx)
	s.log = logr.FromContextOrDiscard(ctx).WithName("services")
	ctx = logr.NewContext(ctx, s.log)
	err := s.setup(ctx)
	if err != nil {
		return err
	}
	return s.withManager(mgr)
}

func (s *Services) setup(ctx context.Context) error {
	cfg := s.Config
	sslCerts := CreateSSLCerts(cfg)
	fakeCrt, fakeCA, err := sslCerts.createFakeCertAndCA()
	if err != nil {
		return fmt.Errorf("error generating self-signed fake certificate and certificate authority: %w", err)
	}
	dynConfig := &convtypes.DynamicConfig{
		StaticCrossNamespaceSecrets: cfg.AllowCrossNamespace,
	}
	acmeSocket := cfg.DefaultDirVarRun + "/acme.sock"
	adminSocket := cfg.DefaultDirVarRun + "/admin.sock"
	masterSocket := cfg.MasterSocket
	if masterSocket == "" && cfg.MasterWorker {
		masterSocket = cfg.DefaultDirVarRun + "/master.sock"
	}
	var rootFSPrefix string
	if cfg.LocalFSPrefix != "" {
		rootFSPrefix = "rootfs"
	}

	// When refactoring, give these initializations a special attention to avoid https://go.dev/doc/faq#nil_error
	// This happens when a nil struct pointer is assigned to an interface var: that interface will render `intf != nil` as true.

	var reloadQueue *workqueue.WorkQueue[any]
	if cfg.ReloadInterval > 0 {
		reloadQueue = workqueue.New(s.reloadHAProxy, workqueue.ReloadHAProxyRateLimiter(cfg.ReloadInterval))
	}
	tracker := tracker.NewTracker()
	metrics := createMetrics(cfg.BucketsResponseTime)
	svcleader, err := initSvcLeader(ctx, cfg)
	if err != nil {
		return err
	}
	svchealthz, err := initSvcHealthz(ctx, cfg, metrics, s.acmeExternalCallCheck)
	if err != nil {
		return err
	}
	svcstatus := initSvcStatusUpdater(ctx, s.Client)
	cache := createCacheFacade(ctx, s.Client, cfg, tracker, sslCerts, dynConfig, svcstatus.update)
	svcstatusing := initSvcStatusIng(ctx, cfg, s.Client, cache, svcstatus.update)
	var acmeClient *svcAcmeClient
	var acmeServer *svcAcmeServer
	var acmeSigner acme.Signer
	var acmeQueue acme.Queue
	if cfg.AcmeServer {
		acmeClient = initSvcAcmeClient(ctx, s.Config, s.legacylogger, cache, metrics, svcleader, s.acmePeriodicCheck)
		acmeServer = initSvcAcmeServer(ctx, s.legacylogger, cache, acmeSocket)
		acmeSigner = acmeClient.signer
		acmeQueue = acmeClient
	}
	instanceOptions := haproxy.InstanceOptions{
		RootFSPrefix:      rootFSPrefix,
		LocalFSPrefix:     cfg.LocalFSPrefix,
		HAProxyCfgDir:     cfg.LocalFSPrefix + "/etc/haproxy",
		HAProxyMapsDir:    cfg.DefaultDirMaps,
		IsMasterWorker:    cfg.MasterWorker,
		IsExternal:        cfg.MasterSocket != "",
		GracePeriod:       cfg.HAProxyGracePeriod,
		MasterSocket:      masterSocket,
		AdminSocket:       adminSocket,
		AcmeSocket:        acmeSocket,
		BackendShards:     cfg.BackendShards,
		Metrics:           metrics,
		ReloadQueue:       reloadQueue,
		ReloadStrategy:    cfg.ReloadStrategy,
		MaxOldConfigFiles: cfg.MaxOldConfigFiles,
		SortEndpointsBy:   cfg.SortEndpointsBy,
		StopCtx:           ctx,
		TrackInstances:    cfg.TrackOldInstances,
		ValidateConfig:    cfg.ValidateConfig,
		AcmeSigner:        acmeSigner,
		AcmeQueue:         acmeQueue,
	}
	converterOptions := &convtypes.ConverterOptions{
		Logger:           s.legacylogger.new("converter"),
		Cache:            cache,
		Tracker:          tracker,
		DynamicConfig:    dynConfig,
		LocalFSPrefix:    cfg.LocalFSPrefix,
		IsExternal:       instanceOptions.IsExternal,
		MasterSocket:     instanceOptions.MasterSocket,
		AdminSocket:      instanceOptions.AdminSocket,
		AcmeSocket:       instanceOptions.AcmeSocket,
		AnnotationPrefix: cfg.AnnPrefix,
		DefaultBackend:   cfg.DefaultService,
		DefaultCrtSecret: cfg.DefaultSSLCertificate,
		FakeCrtFile:      fakeCrt,
		FakeCAFile:       fakeCA,
		DisableKeywords:  cfg.DisableKeywords,
		AcmeTrackTLSAnn:  cfg.AcmeTrackTLSAnn,
		TrackInstances:   cfg.TrackOldInstances,
		HasGatewayA2:     cfg.HasGatewayA2,
		HasGatewayB1:     cfg.HasGatewayB1,
		HasGatewayV1:     cfg.HasGatewayV1,
		HasTCPRouteA2:    cfg.HasTCPRouteA2,
		HasTLSRouteA2:    cfg.HasTLSRouteA2,
	}
	instance := haproxy.CreateInstance(s.legacylogger.new("haproxy"), instanceOptions)
	if err := instance.ParseTemplates(); err != nil {
		return fmt.Errorf("error creating HAProxy instance: %w", err)
	}
	s.acmeClient = acmeClient
	s.acmeServer = acmeServer
	s.cache = cache
	s.converterOpt = converterOptions
	s.instance = instance
	s.metrics = metrics
	s.modelMutex = sync.Mutex{}
	s.reloadQueue = reloadQueue
	s.svcleader = svcleader
	s.svchealthz = svchealthz
	s.svcstatus = svcstatus
	s.svcstatusing = svcstatusing
	return nil
}

func (s *Services) withManager(mgr ctrl.Manager) error {
	if s.Config.Election {
		if err := mgr.Add(s.svcleader); err != nil {
			return err
		}
		if err := s.svcleader.addRunnable(ctrlutils.DelayedShutdown(s.svcstatus)); err != nil {
			return err
		}
		if s.Config.UpdateStatus {
			if err := s.svcleader.addRunnable(s.svcstatusing); err != nil {
				return err
			}
		}
		if s.acmeClient != nil {
			if err := s.svcleader.addRunnable(s.acmeClient); err != nil {
				return err
			}
		}
	}
	if s.reloadQueue != nil {
		if err := mgr.Add(s.reloadQueue); err != nil {
			return err
		}
	}
	if s.Config.StatsCollectProcPeriod > 0 {
		if err := mgr.Add(&svcCalcIdle{
			instance: s.instance,
			period:   s.Config.StatsCollectProcPeriod,
		}); err != nil {
			return err
		}
	}
	if s.acmeServer != nil {
		if err := mgr.Add(s.acmeServer); err != nil {
			return err
		}
	}
	if s.svchealthz != nil {
		if err := mgr.Add(s.svchealthz); err != nil {
			return err
		}
	}
	if err := mgr.Add(&svcShutdown{instance: s.instance}); err != nil {
		return err
	}
	return nil
}

func (s *Services) acmeExternalCallCheck() (count int, err error) {
	return s.acmeCheck("external call")
}

func (s *Services) acmePeriodicCheck() (count int, err error) {
	return s.acmeCheck("periodic check")
}

// LeaderChangedSubscriber ...
func (s *Services) LeaderChangedSubscriber(f SvcLeaderChangedFnc) {
	s.svcleader.addSubscriber(f)
}

// GetIsValidResource ...
func (s *Services) GetIsValidResource() IsValidResource {
	return s.cache
}

// ReconcileIngress ...
func (s *Services) ReconcileIngress(ctx context.Context, changed *convtypes.ChangedObjects) error {
	s.modelMutex.Lock()
	defer s.modelMutex.Unlock()
	s.updateCount++
	s.log.Info("starting haproxy update", "id", s.updateCount)
	timer := utils.NewTimer(s.metrics.ControllerProcTime)
	converters.NewConverter(timer, s.instance.Config(), changed, s.converterOpt).Sync()
	if s.svcleader.isLeader() {
		s.instance.AcmeUpdate()
	}
	var err error
	var errmsg string
	if err = s.instance.HAProxyUpdate(timer); err != nil {
		errmsg = "error trying to update haproxy"
	} else if err = s.svcstatusing.changed(ctx, timer, changed); err != nil {
		errmsg = "error trying to synchronize ingress status"
	}
	updatelogger := s.log.WithValues("id", s.updateCount).WithValues(timer.AsValues("total")...)
	if err != nil {
		updatelogger.Error(err, fmt.Sprintf("%s, retrying in %s", errmsg, s.Config.ReloadRetry.String()))
	} else {
		updatelogger.Info("finish haproxy update")
	}
	return err
}

func (s *Services) acmeCheck(source string) (count int, err error) {
	if !s.svcleader.isLeader() {
		err = fmt.Errorf("cannot check acme certificates, this controller is not the leader")
		s.log.Error(err, "error checking acme certificates")
		return 0, err
	}
	s.modelMutex.Lock()
	defer s.modelMutex.Unlock()
	count, err = s.instance.AcmeCheck(source)
	if err != nil {
		s.log.Error(err, "failed checking acme certificates", "source", source)
	} else if count > 0 {
		s.log.Info("checking acme certificates", "source", source, "count", count)
	} else {
		s.log.Info("acme certificate list is empty", "source", source)
	}
	return count, err
}

func (s *Services) reloadHAProxy(context.Context, any) error {
	s.log.Info("acquiring haproxy reload lock")
	s.modelMutex.Lock()
	defer s.modelMutex.Unlock()
	s.reloadCount++
	s.log.Info("starting haproxy reload", "id", s.reloadCount)
	timer := utils.NewTimer(s.metrics.ControllerProcTime)
	err := s.instance.Reload(timer)
	reloadlogger := s.log.WithValues("id", s.reloadCount).WithValues(timer.AsValues("total")...)
	if err != nil {
		reloadlogger.Error(err, fmt.Sprintf("error trying to reload haproxy, retrying in %s", s.Config.ReloadRetry.String()))
		s.reloadQueue.AddAfter(nil, s.Config.ReloadRetry)
	} else {
		reloadlogger.Info("finish haproxy reload")
	}
	// return err!=nil adds another event into the queue, we're reloading manually
	// in the case when an error happens in order to override the rate limit of the reload queue.
	return nil
}
