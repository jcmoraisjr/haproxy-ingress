/*
Copyright 2019 The HAProxy Ingress Controller Authors.

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

package legacy

import (
	"context"
	"os"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"

	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
)

// LeaderSubscriber ...
type LeaderSubscriber interface {
	OnStartedLeading(ctx context.Context)
	OnStoppedLeading()
	OnNewLeader(identity string)
}

type leaderelector struct {
	logger *logger
	le     *leaderelection.LeaderElector
}

// NewLeaderElector ...
func NewLeaderElector(id string, logger *logger, cache *k8scache, subscriber LeaderSubscriber) types.LeaderElector {
	hostname, _ := os.Hostname()
	namespace, podname, err := cache.GetIngressPodName()
	if err != nil {
		logger.Fatal("error reading ingress controller pod: %v", err)
	}

	lock, err := resourcelock.New(
		resourcelock.ConfigMapsLeasesResourceLock,
		namespace,
		id,
		cache.client.CoreV1(),
		cache.client.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity: podname,
			EventRecorder: record.NewBroadcaster().NewRecorder(scheme.Scheme, api.EventSource{
				Component: "haproxy-ingress-leader-elector",
				Host:      hostname,
			}),
		},
	)
	if err != nil {
		logger.Fatal("error starting leader election: %v", err)
	}
	callbacks := leaderelection.LeaderCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			if subscriber != nil {
				subscriber.OnStartedLeading(ctx)
			}
		},
		OnStoppedLeading: func() {
			if subscriber != nil {
				subscriber.OnStoppedLeading()
			}
		},
		OnNewLeader: func(identity string) {
			if subscriber != nil {
				subscriber.OnNewLeader(identity)
			}
		},
	}

	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: 30 * time.Second,
		RenewDeadline: 15 * time.Second,
		RetryPeriod:   10 * time.Second,
		Callbacks:     callbacks,
	})
	if err != nil {
		logger.Fatal("error starting leader election: %v", err)
	}
	return &leaderelector{
		logger: logger,
		le:     le,
	}
}

func (l *leaderelector) IsLeader() bool {
	return l.le.IsLeader()
}

func (l *leaderelector) LeaderName() string {
	name := l.le.GetLeader()
	if name == "" {
		return "<no-leader>"
	}
	return name
}

func (l *leaderelector) Run(stopCh <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		<-stopCh
	}()
	wait.Until(func() {
		l.le.Run(ctx)
	}, time.Second, stopCh)
}
