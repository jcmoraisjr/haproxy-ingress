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
	"context"
	"sync"
	"time"

	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/workqueue"
)

// Queue ...
type Queue interface {
	QueueFacade
	Clear()
	Notify()
	Run()
	RunWithContext(context.Context)
	Len() int
	ShuttingDown() bool
	ShutDown()
}

// QueueFacade ...
type QueueFacade interface {
	Add(item interface{})
	Remove(item interface{})
	Start(context.Context) error
}

type queue struct {
	mutex       sync.Mutex
	buildQueue  func() workqueue.TypedRateLimitingInterface[any]
	workqueue   workqueue.TypedRateLimitingInterface[any]
	rateLimiter flowcontrol.RateLimiter
	running     chan struct{}
	shutdown    chan bool
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
func NewRateLimitingQueue(rate float32, syncfn func(item interface{})) Queue {
	queue := newQueue(func() workqueue.TypedRateLimitingInterface[any] {
		return workqueue.NewTypedRateLimitingQueue(
			workqueue.DefaultTypedItemBasedRateLimiter[any](),
		)
	})
	queue.sync = syncfn
	if rate > 0 {
		queue.rateLimiter = flowcontrol.NewTokenBucketRateLimiter(rate, 1)
	}
	return queue
}

// NewFailureRateLimitingQueue ...
func NewFailureRateLimitingQueue(failInitialWait, failMaxWait time.Duration, syncfn func(item interface{}) error) Queue {
	queue := newQueue(func() workqueue.TypedRateLimitingInterface[any] {
		return workqueue.NewTypedRateLimitingQueue(
			workqueue.NewTypedItemExponentialFailureRateLimiter[any](failInitialWait, failMaxWait),
		)
	})
	queue.syncFailure = syncfn
	return queue
}

func newQueue(builder func() workqueue.TypedRateLimitingInterface[any]) *queue {
	return &queue{
		mutex:      sync.Mutex{},
		buildQueue: builder,
		workqueue:  builder(),
		shutdown:   make(chan bool, 1),
	}
}

func (q *queue) Add(item interface{}) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	delete(q.forget, item)
	q.workqueue.Add(item)
}

func (q *queue) Notify() {
	// When using with rateLimiter, `nil` will be deduplicated
	// and `queue.Get()` will release call to `sync()` just once
	q.mutex.Lock()
	defer q.mutex.Unlock()
	delete(q.forget, nil)
	q.workqueue.Add(nil)
}

func (q *queue) Remove(item interface{}) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if q.forget == nil {
		q.forget = set{}
	}
	q.forget[item] = empty{}
}

func (q *queue) Run() {
	q.RunWithContext(context.TODO())
}

func (q *queue) Start(ctx context.Context) error {
	q.RunWithContext(ctx)
	return nil
}

func (q *queue) RunWithContext(ctx context.Context) {
	if q.running != nil {
		// queue already running
		return
	}
	if ctx != nil && ctx != context.TODO() {
		// only start for contexts that have a chance to be canceled
		go func() {
			<-ctx.Done()
			q.ShutDown()
		}()
	}
	q.running = make(chan struct{})
	for {
		if q.rateLimiter != nil {
			if ctx == nil {
				q.rateLimiter.Accept()
			} else {
				err := q.rateLimiter.Wait(ctx)
				if err == context.Canceled {
					return
				}
			}
		}
		item, quit := q.workqueue.Get()
		if q.rateLimiter != nil {
			// waste a token if available, so Accept() can properly
			// rate limit two consecutive calls after Get() blocks
			// longer than the allowed rate
			_ = q.rateLimiter.TryAccept()
		}
		if quit {
			if !<-q.shutdown {
				continue
			}
			close(q.running)
			return
		}
		if q.sync != nil {
			q.sync(item)
		} else if q.syncFailure != nil {
			if q.forgotten(item) {
				// ignore, item was already removed from the queue
			} else if err := q.syncFailure(item); err != nil {
				q.workqueue.AddRateLimited(item)
			} else {
				q.workqueue.Forget(item)
			}
		}
		q.workqueue.Done(item)
	}
}

func (q *queue) forgotten(item interface{}) bool {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if _, forget := q.forget[item]; forget {
		q.workqueue.Forget(item)
		delete(q.forget, item)
		return true
	}
	return false
}

func (q *queue) Len() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	return q.workqueue.Len()
}

func (q *queue) Clear() {
	// this would be a lot easier if k8s' workqueue could be cleaned
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.workqueue.ShutDown()
	q.forget = nil
	q.workqueue = q.buildQueue()
	q.shutdown <- false
}

func (q *queue) ShuttingDown() bool {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	return q.workqueue.ShuttingDown()
}

func (q *queue) ShutDown() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.workqueue.ShutDown()
	q.shutdown <- true
	if q.running != nil {
		<-q.running
	}
	close(q.shutdown)
}
