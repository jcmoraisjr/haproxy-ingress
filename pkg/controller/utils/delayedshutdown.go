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

package utils

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// DelayedShutdown adds a delay in the shutdown event, so the
// runnable has some time to listen to events from other runnables
// triggered during their shutdown
func DelayedShutdown(svc DelayedService) manager.Runnable {
	return &dsd{
		svc:           svc,
		startingDelay: 200 * time.Millisecond,
		poolingDelay:  200 * time.Millisecond,
	}
}

// DelayedService ...
type DelayedService interface {
	manager.Runnable
	CanShutdown() bool
}

type dsd struct {
	svc           DelayedService
	startingDelay time.Duration
	poolingDelay  time.Duration
}

// Start ...
func (d *dsd) Start(ctx context.Context) error {
	svcctx, cancel := context.WithCancel(context.Background())
	go func() {
		// All the runnables in the same group have their contexts canceled at the
		// same time, but some of them might have some job to do during other
		// runnables shutdown. This goroutine is delaying the shutdown of
		// this runnable in order to properly manage events from other ones.
		<-ctx.Done()
		// give some time to shutdown process of other runnables to send events to this one.
		// TODO maybe use a WaitGroup so we'd wait just the right amount of time.
		time.Sleep(d.startingDelay)
		// delaying to cancel the context while CanShutdown() doesn't authorize.
		for !d.svc.CanShutdown() {
			time.Sleep(d.poolingDelay)
		}
		cancel()
	}()
	return d.svc.Start(svcctx)
}
