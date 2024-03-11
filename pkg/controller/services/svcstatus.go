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
	"reflect"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

var _ svcStatusUpdateFnc = (&svcStatusUpdater{}).update

type svcStatusUpdateFnc func(client.Object)

func initSvcStatusUpdater(ctx context.Context, client client.Client) *svcStatusUpdater {
	s := &svcStatusUpdater{}
	s.client = client
	s.queue = utils.NewFailureRateLimitingQueue(250*time.Millisecond, 2*time.Minute, s.notify)
	s.log = logr.FromContextOrDiscard(ctx).WithName("status")
	return s
}

type svcStatusUpdater struct {
	client  client.Client
	ctx     context.Context
	running bool
	log     logr.Logger
	queue   utils.Queue
}

func (s *svcStatusUpdater) Start(ctx context.Context) error {
	s.ctx = ctx
	s.running = true
	s.queue.RunWithContext(ctx)
	s.running = false
	return nil
}

func (s *svcStatusUpdater) CanShutdown() bool {
	return s.queue.Len() == 0
}

func (s *svcStatusUpdater) update(obj client.Object) {
	if s.running {
		s.queue.Add(obj)
	}
}

func (s *svcStatusUpdater) notify(item interface{}) error {
	obj := item.(client.Object)
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
