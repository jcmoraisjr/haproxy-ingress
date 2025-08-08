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
	"reflect"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	controllerutils "github.com/jcmoraisjr/haproxy-ingress/pkg/controller/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils/workqueue"
)

var _ controllerutils.DelayedService = &svcStatusUpdater{}
var _ svcStatusUpdateFnc = (&svcStatusUpdater{}).update

type svcStatusUpdateFnc func(client.Object)

func initSvcStatusUpdater(ctx context.Context, cli client.Client) *svcStatusUpdater {
	s := &svcStatusUpdater{}
	s.client = cli
	// initialize with a valid queue, even if not the leader, so we don't need to deal with races checking for nil
	s.initQueue()
	s.log = logr.FromContextOrDiscard(ctx).WithName("status")
	return s
}

type svcStatusUpdater struct {
	client client.Client
	ctx    context.Context
	run    bool
	log    logr.Logger
	queue  *workqueue.WorkQueue[client.Object]
}

func (s *svcStatusUpdater) Start(ctx context.Context) error {
	// need a fresh new queue instance in the case this process becomes the leader again
	s.initQueue()
	s.ctx = ctx
	s.run = true
	s.log.Info("starting working queue")
	err := s.queue.Start(ctx)
	s.log.Info("working queue stopped")
	s.run = false
	return err
}

func (s *svcStatusUpdater) CanShutdown() bool {
	return s.queue.Len() == 0
}

func (s *svcStatusUpdater) initQueue() {
	s.queue = workqueue.New(s.notify, workqueue.ExponentialFailureRateLimiter[client.Object](250*time.Millisecond, 2*time.Minute))
}

func (s *svcStatusUpdater) update(obj client.Object) {
	if s.run {
		s.queue.Add(obj)
	} else {
		s.log.Info("ignoring status update, I am not the leader", "obj", fmt.Sprintf("%s %s/%s", reflect.TypeOf(obj).String(), obj.GetNamespace(), obj.GetName()))
	}
}

func (s *svcStatusUpdater) notify(ctx context.Context, obj client.Object) error {
	namespace := obj.GetNamespace()
	name := obj.GetName()
	log := s.log.WithValues("kind", reflect.TypeOf(obj), "namespace", namespace, "name", name)

	from := obj.DeepCopyObject().(client.Object)
	reflect.ValueOf(from).Elem().FieldByName("Status").SetZero()
	if err := s.client.Status().Patch(s.ctx, obj, client.MergeFrom(from)); err != nil {
		log.Error(err, "cannot update status")
		return err
	}

	log.V(1).Info("status updated")
	return nil
}
