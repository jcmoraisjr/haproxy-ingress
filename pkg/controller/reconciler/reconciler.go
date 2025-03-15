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
	"fmt"

	"github.com/go-logr/logr"
	k8sworkqueue "k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/services"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils/workqueue"
)

// IngressReconciler ...
type IngressReconciler struct {
	client.Client
	Config   *config.Config
	Services *services.Services
	//
	log      logr.Logger
	watchers *watchers
	queue    k8sworkqueue.TypedRateLimitingInterface[ctrl.Request]
}

// Reconcile ...
func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	changed := r.watchers.getChangedObjects()
	err := r.Services.ReconcileIngress(ctx, changed)
	if err != nil {
		r.log.Error(err, fmt.Sprintf("error reconciling ingress, retrying in %s", r.Config.ReloadRetry.String()))
		return ctrl.Result{RequeueAfter: r.Config.ReloadRetry}, nil
	}
	return ctrl.Result{}, nil
}

func (r *IngressReconciler) leaderChanged(ctx context.Context, isLeader bool) {
	if isLeader && r.watchers.running() {
		r.log.Info("enqueue reconciliation due to leader acquired")
		r.queue.AddRateLimited(reconcile.Request{})
	}
}

// SetupWithManager ...
func (r *IngressReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	r.log = logr.FromContextOrDiscard(ctx).WithName("ingress")
	r.watchers = createWatchers(ctx, r.Config, r.Services.GetIsValidResource())
	opt := controller.Options{
		LogConstructor: func(*reconcile.Request) logr.Logger { return logr.FromContextOrDiscard(ctx).WithName("reconciler") },
		NewQueue: func(controllerName string, rateLimiter k8sworkqueue.TypedRateLimiter[reconcile.Request]) k8sworkqueue.TypedRateLimitingInterface[reconcile.Request] {
			r.queue = k8sworkqueue.NewTypedRateLimitingQueueWithConfig(rateLimiter, k8sworkqueue.TypedRateLimitingQueueConfig[ctrl.Request]{
				Name: controllerName,
			})
			return r.queue
		},
		RateLimiter:        workqueue.IngressReconcilerRateLimiter(r.Config.RateLimitUpdate, r.Config.WaitBeforeUpdate),
		Reconciler:         r,
		RecoverPanic:       ptr.To(true),
		SkipNameValidation: ptr.To(true), // TODO: need to param for test if we add more controllers
	}
	c, err := controller.NewUnmanaged("ingress", mgr, opt)
	if err != nil {
		return err
	}
	for _, handler := range r.watchers.getHandlers() {
		if err := c.Watch(handler.getSource(mgr.GetCache())); err != nil {
			return err
		}
	}
	r.Services.LeaderChangedSubscriber(r.leaderChanged)
	return mgr.Add(c)
}
