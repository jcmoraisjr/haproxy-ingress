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

var _ svcStatusUpdateFnc = (&svcStatusUpdater{}).Update

type svcStatusUpdateFnc func(client.Object)

func initSvcStatusUpdater(ctx context.Context, client client.Client) *svcStatusUpdater {
	s := &svcStatusUpdater{}
	s.client = client
	s.queue = utils.NewFailureRateLimitingQueue(250*time.Millisecond, 2*time.Minute, s.Notify)
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

func (s *svcStatusUpdater) Update(obj client.Object) {
	if s.isleader {
		s.queue.Add(obj)
	}
}

func (s *svcStatusUpdater) Notify(item interface{}) error {
	new := item.(client.Object)
	ns := new.GetNamespace()
	name := new.GetName()
	typ := reflect.TypeOf(new)
	newVal := reflect.ValueOf(new)
	curVal := reflect.New(typ)
	cur := reflect.Indirect(curVal).Interface().(client.Object)
	err := s.client.Get(s.ctx, types.NamespacedName{Namespace: ns, Name: name}, cur)
	if err != nil {
		s.log.Error(err, "cannot read status", "kind", typ, "namespace", ns, "name", name)
		return err
	}
	if reflect.DeepEqual(curVal.Interface(), newVal.Interface()) {
		return nil
	}
	err = s.client.Status().Update(s.ctx, new)
	if err != nil {
		s.log.Error(err, "cannot update status", "kind", typ, "namespace", ns, "name", name)
	}
	return err
}

func (s *svcStatusUpdater) Start(ctx context.Context) error {
	s.ctx = ctx
	s.isleader = true
	s.queue.RunWithContext(ctx)
	s.isleader = false
	s.ctx = nil
	return nil
}
