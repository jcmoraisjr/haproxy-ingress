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

package utils

import (
	"time"

	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/workqueue"
)

// Queue ...
type Queue interface {
	Add(item interface{})
	Notify()
	Remove(item interface{})
	Run()
	ShuttingDown() bool
	ShutDown()
}

type queue struct {
	workqueue   workqueue.RateLimitingInterface
	rateLimiter flowcontrol.RateLimiter
	running     chan struct{}
	forget      set
	sync        func(item interface{})
	syncFailure func(item interface{}) error
}

type set map[iface]empty
type iface interface{}
type empty struct{}

// NewQueue ...
func NewQueue(sync func(item interface{})) Queue {
	return NewRateLimitingQueue(0, sync)
}

// NewRateLimitingQueue ...
func NewRateLimitingQueue(rate float32, sync func(item interface{})) Queue {
	var rateLimiter flowcontrol.RateLimiter
	if rate > 0 {
		rateLimiter = flowcontrol.NewTokenBucketRateLimiter(rate, 1)
	}
	return &queue{
		workqueue: workqueue.NewRateLimitingQueue(
			workqueue.DefaultItemBasedRateLimiter(),
		),
		rateLimiter: rateLimiter,
		sync:        sync,
	}
}

// NewFailureRateLimitingQueue ...
func NewFailureRateLimitingQueue(failInitialWait, failMaxWait time.Duration, sync func(item interface{}) error) Queue {
	return &queue{
		workqueue: workqueue.NewRateLimitingQueue(
			workqueue.NewItemExponentialFailureRateLimiter(failInitialWait, failMaxWait),
		),
		syncFailure: sync,
	}
}

func (q *queue) Add(item interface{}) {
	delete(q.forget, item)
	q.workqueue.Add(item)
}

func (q *queue) Notify() {
	//  When using with rateLimiter, `nil` will be deduplicated
	// and `queue.Get()` will release call to `sync()` just once
	delete(q.forget, nil)
	q.workqueue.Add(nil)
}

func (q *queue) Remove(item interface{}) {
	if q.forget == nil {
		q.forget = set{}
	}
	q.forget[item] = empty{}
}

func (q *queue) Run() {
	if q.running != nil {
		// queue already running
		return
	}
	q.running = make(chan struct{})
	for {
		if q.rateLimiter != nil {
			q.rateLimiter.Accept()
		}
		item, shutdown := q.workqueue.Get()
		if shutdown {
			close(q.running)
			return
		}
		if q.sync != nil {
			q.sync(item)
		} else if q.syncFailure != nil {
			if _, forget := q.forget[item]; forget {
				q.workqueue.Forget(item)
				delete(q.forget, item)
			} else if err := q.syncFailure(item); err != nil {
				q.workqueue.AddRateLimited(item)
			} else {
				q.workqueue.Forget(item)
			}
		}
		q.workqueue.Done(item)
	}
}

func (q *queue) ShuttingDown() bool {
	return q.workqueue.ShuttingDown()
}

func (q *queue) ShutDown() {
	q.workqueue.ShutDown()
	if q.running != nil {
		<-q.running
	}
}
