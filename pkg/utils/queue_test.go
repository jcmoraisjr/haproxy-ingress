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
	"fmt"
	"reflect"
	"testing"
	"time"
)

type task struct {
	steps []string
}

func TestQueueNotRunning(t *testing.T) {
	q := NewQueue(0, nil)
	q.ShutDown()
}

func TestQueueAlreadyRunning(t *testing.T) {
	q := NewQueue(0, nil)
	go q.Run()
	time.Sleep(100 * time.Millisecond)
	q.Run() // test fail if this call blocks, the test will timeout
	q.ShutDown()
}

func TestQueueShutdown(t *testing.T) {
	q := NewQueue(0, func(item interface{}) { time.Sleep(200 * time.Millisecond) })
	stopped := false
	go func() {
		q.Run()
		stopped = true
	}()
	q.Add(nil)
	time.Sleep(100 * time.Millisecond)
	q.ShutDown()
	if !stopped {
		t.Error("queue is still running")
	}
}

func TestQueueRun(t *testing.T) {
	var items []string
	q := NewQueue(0, func(item interface{}) {
		items = append(items, item.(string)+"-1")
		time.Sleep(250 * time.Millisecond)
		items = append(items, item.(string)+"-2")
	})
	go q.Run()
	q.Add("a1")
	time.Sleep(150 * time.Millisecond)
	items = append(items, "s1")
	q.Add("a2")
	time.Sleep(150 * time.Millisecond)
	items = append(items, "s2")
	q.ShutDown()
	items = append(items, "s3")
	expected := []string{"a1-1", "s1", "a1-2", "a2-1", "s2", "a2-2", "s3"}
	if !reflect.DeepEqual(items, expected) {
		t.Errorf("items differ, expected: %+v; actual: %+v", expected, items)
	}
}

func TestDeduplicate(t *testing.T) {
	var items []interface{}
	q := NewQueue(0, func(item interface{}) {
		items = append(items, item)
	})
	go q.Run()
	q.Add(nil)
	q.Add(nil)
	q.Add("")
	q.Add("")
	q.Add("")
	q.Add("1")
	q.Add("1")
	q.Add(1)
	q.Add(1)
	q.Add(1)
	q.Add(nil)
	q.Add("")
	time.Sleep(200 * time.Millisecond)
	q.ShutDown()
	expected := []interface{}{nil, "", "1", 1}
	if !reflect.DeepEqual(items, expected) {
		t.Errorf("items differ, expected: %+v; actual: %+v", expected, items)
	}
}

func TestRate(t *testing.T) {
	var items []string
	q := NewQueue(2, func(item interface{}) {
		items = append(items, fmt.Sprintf("%d=%s", item, time.Now().Format("15:04:05.000")))
	})
	go q.Run()
	start := time.Now()
	for i := 0; i < 4; i++ {
		q.Add(i + 1)
	}
	time.Sleep(200 * time.Millisecond)
	q.ShutDown()
	duration := time.Now().Sub(start)
	if len(items) != 4 {
		t.Errorf("expected 4 items but sync was called %d time(s)", len(items))
	}
	if duration.Seconds() < 1 {
		t.Errorf("expected time higher than 1s but was %s - timestamps: %v", duration.String(), items)
	}
}

func TestNotify(t *testing.T) {
	var items []interface{}
	q := NewQueue(10, func(item interface{}) {
		items = append(items, item)
	})
	go q.Run()
	for i := 0; i < 10; i++ {
		q.Notify()
	}
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 10; i++ {
		q.Notify()
	}
	q.ShutDown()
	if len(items) != 2 {
		t.Errorf("expected 2 items but sync was called %d time(s)", len(items))
	}
}
