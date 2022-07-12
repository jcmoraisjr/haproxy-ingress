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
	"k8s.io/apimachinery/pkg/types"
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
	client   client.Client
	ctx      context.Context
	isleader bool
	log      logr.Logger
	queue    utils.Queue
}

func (s *svcStatusUpdater) update(obj client.Object) {
	if s.isleader {
		s.queue.Add(obj)
	}
}

func (s *svcStatusUpdater) notify(item interface{}) error {
	obj := item.(client.Object)
	namespace := obj.GetNamespace()
	name := obj.GetName()
	log := s.log.WithValues("kind", reflect.TypeOf(obj), "namespace", namespace, "name", name)
	if err := s.client.Status().Update(s.ctx, obj); err != nil {
		// usually `obj` is up to date, but in case of a concurrent
		// update, we'll refresh the object into a new instance and
		// copy the updated status to it.
		typ := reflect.TypeOf(obj)
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		new := reflect.New(typ).Interface().(client.Object)
		if err := s.client.Get(s.ctx, types.NamespacedName{Namespace: namespace, Name: name}, new); err != nil {
			log.Error(err, "cannot read status")
			return err
		}
		// a reflection trick to copy the updated status from the outdated object to the new updated one
		reflect.ValueOf(new).Elem().FieldByName("Status").Set(
			reflect.ValueOf(obj).Elem().FieldByName("Status"))
		if err := s.client.Status().Update(s.ctx, new); err != nil {
			log.Error(err, "cannot update status")
			return err
		}
	}
	log.V(1).Info("status updated")
	return nil
}

func (s *svcStatusUpdater) Start(ctx context.Context) error {
	s.ctx = ctx
	s.isleader = true
	s.queue.RunWithContext(ctx)
	s.isleader = false
	// s.ctx wasn't cleaned up here so lazy notifications
	// doesn't crashloop due to nil ctx.
	return nil
}

func (s *svcStatusUpdater) CanShutdown() bool {
	return s.queue.Len() == 0
}
