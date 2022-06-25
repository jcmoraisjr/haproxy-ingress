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

package reconciler

import (
	"context"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/services"
	ctrlutils "github.com/jcmoraisjr/haproxy-ingress/pkg/controller/utils"
)

// IngressReconciler ...
type IngressReconciler struct {
	client.Client
	Config   *config.Config
	Services *services.Services
	//
	watchers *watchers
}

// Reconcile ...
func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	changed := r.watchers.getChangedObjects()
	r.Services.ReconcileIngress(changed)
	return ctrl.Result{}, nil
}

func (r *IngressReconciler) leaderChanged(isLeader bool) {
	changed := r.watchers.getChangedObjects()
	changed.NeedFullSync = true
	r.Services.ReconcileIngress(changed)
}

// SetupWithManager ...
func (r *IngressReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	opt := controller.Options{
		LogConstructor: func(*reconcile.Request) logr.Logger { return logr.FromContextOrDiscard(ctx) },
		Reconciler:     r,
		RecoverPanic:   true,
	}
	c, err := controller.NewUnmanaged("ingress", mgr, opt)
	if err != nil {
		return err
	}
	r.watchers = createWatchers(ctx, r.Config, r.Services.GetIsValidResource())
	for _, handler := range r.watchers.getHandlers() {
		if err := c.Watch(
			handler.getSource(),
			handler.getEventHandler(),
			handler.getPredicates()...,
		); err != nil {
			return err
		}
	}
	r.Services.LeaderChangedSubscriber(r.leaderChanged)
	return mgr.Add(ctrlutils.DistributedService(c))
}
