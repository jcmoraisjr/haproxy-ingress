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
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

type svcAcmeCheckFnc func() (count int, err error)

func initSvcAcmeServer(ctx context.Context, logger *lfactory, cache acme.Cache, socket string) *svcAcmeServer {
	return &svcAcmeServer{
		log:    logr.FromContextOrDiscard(ctx).WithName("acme").WithName("server"),
		server: acme.NewServer(logger.new("acme.server"), socket, cache),
	}
}

type svcAcmeServer struct {
	log    logr.Logger
	server acme.Server
}

func (s *svcAcmeServer) Start(ctx context.Context) error {
	s.log.Info("starting")
	if err := s.server.Listen(ctx.Done()); err != nil {
		return err
	}
	// TODO make server sync
	<-ctx.Done()
	s.log.Info("stopped")
	return nil
}

func initSvcAcmeClient(ctx context.Context, config *config.Config, logger *lfactory, cache acme.Cache, metrics types.Metrics, svcleader *svcLeader, checkCallback svcAcmeCheckFnc) *svcAcmeClient {
	signer := acme.NewSigner(logger.new("acme.client"), cache, metrics)
	queue := utils.NewFailureRateLimitingQueue(
		config.AcmeFailInitialDuration,
		config.AcmeFailMaxDuration,
		signer.Notify,
	)
	return &svcAcmeClient{
		log:    logr.FromContextOrDiscard(ctx).WithName("acme").WithName("client"),
		leader: svcleader,
		check:  checkCallback,
		config: config,
		signer: signer,
		queue:  queue,
	}
}

type svcAcmeClient struct {
	log    logr.Logger
	leader *svcLeader
	check  svcAcmeCheckFnc
	config *config.Config
	signer acme.Signer
	queue  utils.Queue
}

func (s *svcAcmeClient) Start(ctx context.Context) error {
	s.log.Info("starting")
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		s.queue.RunWithContext(ctx)
		wg.Done()
	}()
	go func() {
		period := s.config.AcmeCheckPeriod
		s.log.Info("checking expiring certificates", "period", period)
		// we start from the second check, the first one
		// is done during full sync, along with AcmeUpdate(),
		// just after the instance starts leading.
		select {
		case <-time.After(period):
		case <-ctx.Done():
		}
		wait.JitterUntilWithContext(ctx, func(ctx context.Context) {
			_, _ = s.check()
		}, period, 0, false)
		wg.Done()
	}()
	wg.Wait()
	s.log.Info("stopped")
	return nil
}

// implements utils.QueueFacade
func (s *svcAcmeClient) Add(item interface{}) {
	if s.leader.getIsLeader() {
		s.queue.Add(item)
	}
}

// implements utils.QueueFacade
func (s *svcAcmeClient) Remove(item interface{}) {
	s.queue.Remove(item)
}

// svcAcmeClient just satisfies LeaderElector interface. The new controller controls wether
// we're leading by other means, so from the instance perspective we're always the leader.

func (s *svcAcmeClient) IsLeader() bool             { return true }
func (s *svcAcmeClient) LeaderName() string         { return "<unknown>" }
func (s *svcAcmeClient) Run(stopCh <-chan struct{}) {}
