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

package launch

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/reconciler"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/services"
)

// Run ...
func Run(cfg *config.Config) error {
	rootLogger := ctrl.Log
	launchLog := rootLogger.WithName("launch")
	ctx := cfg.RootContext

	launchLog.Info("configuring manager")
	var defaultNamespaces map[string]cache.Config
	if cfg.WatchNamespace != "" {
		defaultNamespaces = map[string]cache.Config{cfg.WatchNamespace: {}}
	}
	mgr, err := ctrl.NewManager(cfg.KubeConfig, ctrl.Options{
		Logger:                  rootLogger.WithName("manager"),
		Scheme:                  cfg.Scheme,
		GracefulShutdownTimeout: cfg.ShutdownTimeout,
		HealthProbeBindAddress:  "0",
		Metrics: server.Options{
			BindAddress: "0",
		},
		Cache: cache.Options{
			SyncPeriod:        cfg.ResyncPeriod,
			DefaultNamespaces: defaultNamespaces,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	launchLog.Info("configuring services")
	services := &services.Services{
		Client: mgr.GetClient(),
		Config: cfg,
	}
	if err := services.SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("unable to create services: %w", err)
	}

	launchLog.Info("configuring ingress reconciler")
	ingress := &reconciler.IngressReconciler{
		Client:   mgr.GetClient(),
		Config:   cfg,
		Services: services,
	}
	if err := ingress.SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("unable to create controller: %w", err)
	}

	launchLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}
