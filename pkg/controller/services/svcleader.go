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
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	crleaderelection "sigs.k8s.io/controller-runtime/pkg/leaderelection"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
)

const (
	// Default values taken from
	// https://github.com/kubernetes/component-base/blob/master/config/v1alpha1/defaults.go
	defaultLeaseDuration = 15 * time.Second
	defaultRenewDeadline = 10 * time.Second
	defaultRetryPeriod   = 2 * time.Second
)

// SvcLeaderChangedFnc ...
type SvcLeaderChangedFnc func(ctx context.Context, isLeader bool)

func initSvcLeader(ctx context.Context, cfg *config.Config) (*svcLeader, error) {
	r, err := initRecorderProvider(cfg)
	if err != nil {
		return nil, err
	}

	rl, err := crleaderelection.NewResourceLock(cfg.KubeConfig, r, crleaderelection.Options{
		LeaderElection:             cfg.Election,
		LeaderElectionID:           cfg.ElectionID,
		LeaderElectionNamespace:    cfg.ElectionNamespace,
		LeaderElectionResourceLock: resourcelock.LeasesResourceLock,
	})
	if err != nil {
		return nil, err
	}

	s := &svcLeader{
		ctx: ctx,
		log: logr.FromContextOrDiscard(ctx).WithName("leader"),
	}

	if rl != nil {
		s.le, err = leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Name:          cfg.ElectionID,
			Lock:          rl,
			LeaseDuration: defaultLeaseDuration,
			RenewDeadline: defaultRenewDeadline,
			RetryPeriod:   defaultRetryPeriod,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: s.onStartedLeading,
				OnStoppedLeading: s.onStoppedLeading,
			},
		})
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

type svcLeader struct {
	ctx         context.Context
	le          *leaderelection.LeaderElector
	log         logr.Logger
	runnables   []manager.Runnable
	rgroup      *errgroup.Group
	rcancel     context.CancelFunc
	subscribers []SvcLeaderChangedFnc
}

func (s *svcLeader) Start(ctx context.Context) error {
	if s.le != nil {
		s.le.Run(ctx)
	}
	<-ctx.Done()
	return nil
}

func (s *svcLeader) onStartedLeading(ctx context.Context) {
	s.log.Info("leader acquired")

	ctxwg, cancel := context.WithCancel(ctx)
	wg, ctxrun := errgroup.WithContext(ctxwg)
	for i := range s.runnables {
		r := s.runnables[i]
		wg.Go(func() error {
			return r.Start(ctxrun)
		})
	}
	s.rgroup = wg
	s.rcancel = cancel

	for _, f := range s.subscribers {
		go f(ctx, true)
	}
}

func (s *svcLeader) onStoppedLeading() {
	for _, f := range s.subscribers {
		go f(s.ctx, false)
	}

	if s.rcancel != nil && s.rgroup != nil {
		s.rcancel()
		err := s.rgroup.Wait()
		if err != nil {
			s.log.Error(err, "error stop leading")
		}
	} else {
		s.log.Error(fmt.Errorf("cannot stop services, leader was not taken"), "error stop leading")
	}
	s.rcancel = nil
	s.rgroup = nil

	s.log.Info("stopped leading")
}

func (s *svcLeader) addRunnable(r manager.Runnable) error {
	s.runnables = append(s.runnables, r)
	return nil
}

func (s *svcLeader) addSubscriber(f SvcLeaderChangedFnc) {
	s.subscribers = append(s.subscribers, f)
}

func (s *svcLeader) isLeader() bool {
	if s.le != nil {
		return s.le.IsLeader()
	}
	return false
}
