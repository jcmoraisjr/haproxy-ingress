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
	"k8s.io/client-go/util/workqueue"
)

// Queue ...
type Queue interface {
	Add(item interface{})
	Run()
	ShuttingDown() bool
	ShutDown()
}

type queue struct {
	workqueue *workqueue.Type
	running   chan struct{}
	sync      func(item interface{})
}

// NewQueue ...
func NewQueue(sync func(item interface{})) Queue {
	return &queue{
		workqueue: workqueue.New(),
		sync:      sync,
	}
}

func (q *queue) Add(item interface{}) {
	q.workqueue.Add(item)
}

func (q *queue) Run() {
	if q.running != nil {
		// queue already running
		return
	}
	q.running = make(chan struct{})
	for {
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
