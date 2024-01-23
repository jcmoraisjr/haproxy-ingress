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
	"log"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/reconciler"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/services"
)

// Run ...
func Run() {
	config, err := config.Create()
	if err != nil {
		log.Printf("unable to parse static config: %s\n", err)
		os.Exit(1)
	}

	rootLogger := ctrl.Log
	launchLog := rootLogger.WithName("launch")
	ctx := config.RootContext

	launchLog.Info("configuring manager")
	mgr, err := ctrl.NewManager(config.KubeConfig, ctrl.Options{
		Logger:                  rootLogger.WithName("manager"),
		Scheme:                  config.Scheme,
		LeaderElection:          config.Election,
		LeaderElectionID:        config.ElectionID,
		LeaderElectionNamespace: config.ElectionNamespace,
		GracefulShutdownTimeout: config.ShutdownTimeout,
		HealthProbeBindAddress:  "0",
		Metrics: server.Options{
			BindAddress: "0",
		},
		Cache: cache.Options{
			SyncPeriod:        config.ResyncPeriod,
			DefaultNamespaces: config.WatchNamespaces,
		},
	})
	if err != nil {
		launchLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	launchLog.Info("configuring services")
	services := &services.Services{
		Client: mgr.GetClient(),
		Config: config,
	}
	if err := services.SetupWithManager(ctx, mgr); err != nil {
		launchLog.Error(err, "unable to create services")
		os.Exit(1)
	}

	launchLog.Info("configuring ingress reconciler")
	if err := (&reconciler.IngressReconciler{
		Client:   mgr.GetClient(),
		Config:   config,
		Services: services,
	}).SetupWithManager(ctx, mgr); err != nil {
		launchLog.Error(err, "unable to create controller")
		os.Exit(1)
	}

	launchLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		launchLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
