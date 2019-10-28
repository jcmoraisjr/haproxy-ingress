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
	"reflect"
	"testing"
	"time"
)

type task struct {
	steps []string
}

func TestQueueNotRunning(t *testing.T) {
	q := NewQueue(nil)
	q.ShutDown()
}

func TestQueueAlreadyRunning(t *testing.T) {
	q := NewQueue(nil)
	go q.Run()
	time.Sleep(100 * time.Millisecond)
	q.Run() // test fail if this call blocks, the test will timeout
	q.ShutDown()
}

func TestQueueShutdown(t *testing.T) {
	q := NewQueue(func(item interface{}) { time.Sleep(200 * time.Millisecond) })
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
	items := []string{}
	q := NewQueue(func(item interface{}) {
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
	items := []interface{}{}
	q := NewQueue(func(item interface{}) { items = append(items, item) })
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
