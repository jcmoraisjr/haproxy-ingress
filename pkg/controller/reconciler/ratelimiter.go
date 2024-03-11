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
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/ratelimiter"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
)

func createRateLimiter(cfg *config.Config) ratelimiter.RateLimiter {
	return &rateLimiter{
		delta: time.Duration(float64(time.Second) / cfg.RateLimitUpdate),
		wait:  cfg.WaitBeforeUpdate,
	}
}

type rateLimiter struct {
	mu    sync.Mutex
	delta time.Duration
	wait  time.Duration
	last  time.Time
}

func (r *rateLimiter) When(_ interface{}) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()

	// within a time frame, return the remaining time
	if r.last.After(now) {
		return r.last.Sub(now)
	}

	// outside a time frame, rate allowed, return the short wait
	next := r.last.Add(r.delta)
	if next.Before(now) {
		r.last = now.Add(r.wait)
		return r.wait
	}

	// outside a time frame, rate not allowed, return the
	// remaining time to be allowed again
	r.last = next
	return next.Sub(now)
}

func (r *rateLimiter) NumRequeues(item interface{}) int {
	return 0
}

func (r *rateLimiter) Forget(item interface{}) {
}
