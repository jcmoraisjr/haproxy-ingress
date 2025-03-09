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

package workqueue

import (
	"sync"
	"time"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func IngressReconcilerRateLimiter(rateLimitUpdate float64, waitBeforeUpdate time.Duration) workqueue.TypedRateLimiter[reconcile.Request] {
	return &ingressReconciler{
		delta: time.Duration(float64(time.Second) / rateLimitUpdate),
		wait:  waitBeforeUpdate,
	}
}

func ReloadHAProxyRateLimiter(reloadInterval time.Duration) workqueue.TypedRateLimiter[any] {
	return &reloadHAProxy{
		interval: reloadInterval,
	}
}

func ExponentialFailureRateLimiter[T comparable](failInitialWait, failMaxWait time.Duration) workqueue.TypedRateLimiter[T] {
	return workqueue.NewTypedItemExponentialFailureRateLimiter[T](failInitialWait, failMaxWait)
}

type ingressReconciler struct {
	mu    sync.Mutex
	delta time.Duration
	wait  time.Duration
	last  time.Time
}

func (r *ingressReconciler) When(_ reconcile.Request) time.Duration {
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

func (r *ingressReconciler) NumRequeues(_ reconcile.Request) int {
	return 0
}

func (r *ingressReconciler) Forget(_ reconcile.Request) {
}

type reloadHAProxy struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func (r *reloadHAProxy) When(_ any) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	next := r.last.Add(r.interval)

	// not rate limited, allow to reload now
	if next.Before(now) {
		r.last = now
		return 0
	}

	// rate limited, return the remaining time to the next reload
	return time.Until(next)
}

func (r *reloadHAProxy) NumRequeues(_ any) int {
	return 0
}

func (r *reloadHAProxy) Forget(_ any) {
}
