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
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/workqueue"
)

// Queue ...
type Queue interface {
	Add(item interface{})
	Notify()
	Run()
	ShuttingDown() bool
	ShutDown()
}

type queue struct {
	workqueue   *workqueue.Type
	rateLimiter flowcontrol.RateLimiter
	running     chan struct{}
	sync        func(item interface{})
}

// NewQueue ...
func NewQueue(rate float32, sync func(item interface{})) Queue {
	var rateLimiter flowcontrol.RateLimiter
	if rate > 0 {
		rateLimiter = flowcontrol.NewTokenBucketRateLimiter(rate, 1)
	}
	return &queue{
		workqueue:   workqueue.New(),
		rateLimiter: rateLimiter,
		sync:        sync,
	}
}

func (q *queue) Add(item interface{}) {
	q.workqueue.Add(item)
}

func (q *queue) Notify() {
	//  When using with rateLimiter, `nil` will be deduplicated
	// and `queue.Get()` will release call to `sync()` just once
	q.workqueue.Add(nil)
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
		q.sync(item)
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
