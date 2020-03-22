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
	var items []string
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
	var items []interface{}
	q := NewQueue(func(item interface{}) {
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
	q := NewRateLimitingQueue(2, func(item interface{}) {
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
	q := NewQueue(func(item interface{}) {
		time.Sleep(200 * time.Millisecond)
		items = append(items, item)
	})
	go q.Run()
	for i := 0; i < 5; i++ {
		q.Notify()
		// t0ms - start the first notification
		time.Sleep(10 * time.Millisecond)
	}
	// t50ms - first notification running, one notification in the queue
	time.Sleep(200 * time.Millisecond)
	// t250ms - second notification running, zero notification in the queue
	for i := 0; i < 5; i++ {
		q.Notify()
		// t250ms - second notification running, one notification in the queue
		time.Sleep(10 * time.Millisecond)
	}
	// t300ms - second notification running, one notification in the queue
	time.Sleep(200 * time.Millisecond)
	// t500ms - third notification running, zero notification in the queue
	q.ShutDown()
	// t600ms - third notification finish - shutdown wait the callback to return
	if len(items) != 3 {
		t.Errorf("expected 3 items but sync was called %d time(s)", len(items))
	}
}

func TestRemove(t *testing.T) {
	var count int
	// retries on 20ms, +40ms(60ms), +80ms(140ms), +160ms(300ms) ... up to 1s
	q := NewFailureRateLimitingQueue(20*time.Millisecond, 1*time.Second, func(item interface{}) error {
		count++
		return fmt.Errorf("oops")
	})
	go q.Run()
	checkCount := func(c int) {
		if count != c {
			t.Errorf("expected count=%d but was %d", c, count)
		}
	}
	q.Add(1)
	// 100ms
	time.Sleep(100 * time.Millisecond)
	checkCount(3)
	q.Remove(1)
	// 320ms
	time.Sleep(220 * time.Millisecond)
	checkCount(3)
	q.ShutDown()
}

func TestAddRemoved(t *testing.T) {
	var count int
	// retries on 20ms, +40ms(60ms), +80ms(140ms), +160ms(300ms) ... up to 1s
	q := NewFailureRateLimitingQueue(20*time.Millisecond, 1*time.Second, func(item interface{}) error {
		count++
		return fmt.Errorf("oops")
	})
	go q.Run()
	checkCount := func(c int) {
		if count != c {
			t.Errorf("expected count=%d but was %d", c, count)
		}
	}
	q.Remove(1)
	q.Add(1)
	// 100ms
	time.Sleep(100 * time.Millisecond)
	checkCount(3)
	q.ShutDown()
}

func TestBackoffQueue(t *testing.T) {
	var count int
	// retries on 30ms, +60ms(90ms), +120ms(210ms), +240ms(450ms) ... up to 2s
	q := NewFailureRateLimitingQueue(30*time.Millisecond, 2*time.Second, func(item interface{}) error {
		count++
		if err, ok := item.(error); ok {
			if count >= 3 {
				return nil
			}
			return err
		}
		return nil
	})
	go q.Run()
	checkCount := func(c int) {
		if count != c {
			t.Errorf("expected count=%d but was %d", c, count)
		}
	}
	count = 0
	for i := 0; i < 5; i++ {
		q.Add(i)
	}
	time.Sleep(100 * time.Millisecond)
	checkCount(5)
	count = 0
	q.Add(fmt.Errorf("oops"))
	time.Sleep(60 * time.Millisecond)
	// 60ms
	checkCount(2)
	time.Sleep(90 * time.Millisecond)
	// 150ms
	checkCount(3)
	time.Sleep(180 * time.Millisecond)
	// 330ms
	checkCount(3)
	time.Sleep(180 * time.Millisecond)
	// 510ms
	checkCount(3)
	q.ShutDown()
}

func TestClearQueue(t *testing.T) {
	var count int
	// retries on 30ms, +60ms(90ms), +120ms(210ms), +240ms(450ms) ... up to 2s
	q := NewFailureRateLimitingQueue(30*time.Millisecond, 2*time.Second, func(item interface{}) error {
		count++
		return fmt.Errorf("fail")
	})
	go q.Run()
	checkCount := func(id, c int) {
		if count != c {
			t.Errorf("on %d, expected count=%d but was %d", id, c, count)
		}
	}
	q.Add(nil)
	time.Sleep(45 * time.Millisecond)
	checkCount(1, 2)
	q.Clear()
	count = 0
	time.Sleep(210 * time.Millisecond)
	checkCount(2, 0)
	count = 0
	q.Add(nil)
	time.Sleep(120 * time.Millisecond)
	checkCount(3, 3)
	q.ShutDown()
}

func TestConcurrency(t *testing.T) {
	q := NewFailureRateLimitingQueue(30*time.Millisecond, 2*time.Second, func(item interface{}) error {
		return fmt.Errorf("err")
	})
	go q.Run()
	go func() {
		for {
			q.Add(1)
			time.Sleep(35 * time.Microsecond)
		}
	}()
	go func() {
		for {
			q.Remove(1)
			time.Sleep(25 * time.Microsecond)
		}
	}()
	time.Sleep(5 * time.Second)
	q.ShutDown()
}
