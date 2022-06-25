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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	ctrlutils "github.com/jcmoraisjr/haproxy-ingress/pkg/controller/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// Services ...
type Services struct {
	client.Client
	Config *config.Config
	//
	legacylogger *lfactory
	log          logr.Logger
	//
	cache        *c
	converterOpt *convtypes.ConverterOptions
	hasAcme      bool
	instance     haproxy.Instance
	metrics      *metrics
	modelMutex   sync.Mutex
	reloadCount  int
	reloadQueue  utils.Queue
	svcleader    *svcLeader
	svcstatus    *svcStatusUpdater
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
		return fmt.Errorf("error generating self signed fake certificate and certificate authority: %w", err)
	}
	dynConfig := &convtypes.DynamicConfig{
		StaticCrossNamespaceSecrets: cfg.AllowCrossNamespace,
	}
	masterSocket := cfg.MasterSocket
	if masterSocket == "" && cfg.MasterWorker {
		masterSocket = cfg.DefaultDirVarRun + "/master.sock"
	}
	var rootFSPrefix string
	if cfg.LocalFSPrefix != "" {
		rootFSPrefix = "rootfs"
	}
	var reloadQueue utils.Queue
	if cfg.ReloadInterval > 0 {
		reloadQueue = utils.NewRateLimitingQueue(float32(1/cfg.ReloadInterval.Seconds()), s.reloadHAProxy)
	}
	tracker := tracker.NewTracker()
	metrics := createMetrics(cfg.BucketsResponseTime)
	svcleader := initSvcLeader(ctx)
	svcstatus := initSvcStatusUpdater(ctx, s.Client)
	cache := createCacheFacade(ctx, s.Client, cfg, tracker, sslCerts, dynConfig, svcstatus.Update)
	instanceOptions := haproxy.InstanceOptions{
		RootFSPrefix:      rootFSPrefix,
		LocalFSPrefix:     cfg.LocalFSPrefix,
		HAProxyCfgDir:     cfg.LocalFSPrefix + "/etc/haproxy",
		HAProxyMapsDir:    cfg.DefaultDirMaps,
		IsMasterWorker:    cfg.MasterWorker,
		IsExternal:        cfg.MasterSocket != "",
		MasterSocket:      masterSocket,
		AdminSocket:       cfg.DefaultDirVarRun + "/admin.sock",
		AcmeSocket:        cfg.DefaultDirVarRun + "/acme.sock",
		BackendShards:     cfg.BackendShards,
		Metrics:           metrics,
		ReloadQueue:       reloadQueue,
		ReloadStrategy:    cfg.ReloadStrategy,
		MaxOldConfigFiles: cfg.MaxOldConfigFiles,
		SortEndpointsBy:   cfg.SortEndpointsBy,
		StopCh:            ctx.Done(),
		TrackInstances:    cfg.TrackOldInstances,
		ValidateConfig:    cfg.ValidateConfig,
		// TODO:
		// AcmeSigner:    acmeSigner,
		// AcmeQueue:     acmeQueue,
		// LeaderElector: leaderElector,
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
		HasGateway:       cfg.HasGateway,
		UpdateStatus:     cfg.UpdateStatus,
	}
	instance := haproxy.CreateInstance(s.legacylogger.new("haproxy"), instanceOptions)
	if err := instance.ParseTemplates(); err != nil {
		return fmt.Errorf("error creating HAProxy instance: %w", err)
	}
	s.cache = cache
	s.converterOpt = converterOptions
	s.hasAcme = false
	s.instance = instance
	s.metrics = metrics
	s.modelMutex = sync.Mutex{}
	s.reloadQueue = reloadQueue
	s.svcleader = svcleader
	s.svcstatus = svcstatus
	return nil
}

func (s *Services) withManager(mgr ctrl.Manager) error {
	if s.Config.Election {
		if err := mgr.Add(s.svcleader); err != nil {
			return err
		}
		if err := mgr.Add(s.svcstatus); err != nil {
			return err
		}
	}
	if s.reloadQueue != nil {
		if err := mgr.Add(ctrlutils.DistributedService(&svcReloadQueue{
			queue: s.reloadQueue,
		})); err != nil {
			return err
		}
	}
	if s.Config.StatsCollectProcPeriod > 0 {
		if err := mgr.Add(ctrlutils.DistributedService(&svcCalcIdle{
			instance: s.instance,
			period:   s.Config.StatsCollectProcPeriod,
		})); err != nil {
			return err
		}
	}
	if s.hasAcme {
		if err := mgr.Add(&svcAcmeClient{
			//
		}); err != nil {
			return err
		}
		if err := mgr.Add(ctrlutils.DistributedService(&svcAcmeServer{
			//
		})); err != nil {
			return err
		}
	}
	return nil
}

// LeaderChangedSubscriber ...
func (s *Services) LeaderChangedSubscriber(f SvcLeaderChangedFnc) {
	s.svcleader.addsubscriber(f)
}

// GetIsValidResource ...
func (s *Services) GetIsValidResource() IsValidResource {
	return s.cache
}

// ReconcileIngress ...
func (s *Services) ReconcileIngress(changed *convtypes.ChangedObjects) {
	s.modelMutex.Lock()
	defer s.modelMutex.Unlock()
	s.updateCount++
	s.log.Info("starting haproxy update", "id", s.updateCount)
	timer := utils.NewTimer(s.metrics.ControllerProcTime)
	converters.NewConverter(timer, s.instance.Config(), changed, s.converterOpt).Sync()
	s.instance.Update(timer)
	s.log.WithValues("id", s.updateCount).WithValues(timer.AsValues("total")...).Info("finish haproxy update")
}

func (s *Services) reloadHAProxy(interface{}) {
	s.modelMutex.Lock()
	defer s.modelMutex.Unlock()
	s.reloadCount++
	s.log.Info("starting haproxy reload", "id", s.reloadCount)
	timer := utils.NewTimer(s.metrics.ControllerProcTime)
	s.instance.Reload(timer)
	s.log.WithValues("id", s.reloadCount).WithValues(timer.AsValues("total")...).Info("finish haproxy reload")
}
