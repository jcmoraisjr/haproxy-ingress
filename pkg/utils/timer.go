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
	"strings"
	"time"
)

// Timer ...
type Timer struct {
	Start    time.Time
	Ticks    []*Tick
	observer func(task string, duration time.Duration)
}

// Tick ...
type Tick struct {
	Event    string
	When     time.Time
	Duration time.Duration
}

// NewTimer ...
func NewTimer(observer func(task string, duration time.Duration)) *Timer {
	return &Timer{
		Start:    time.Now(),
		observer: observer,
	}
}

// Tick ...
func (t *Timer) Tick(eventLabel string) {
	now := time.Now()
	var last time.Time
	if len(t.Ticks) > 0 {
		last = t.Ticks[len(t.Ticks)-1].When
	} else {
		last = t.Start
	}
	duration := now.Sub(last)
	if t.observer != nil {
		t.observer(eventLabel, duration)
	}
	t.Ticks = append(t.Ticks, &Tick{
		Event:    eventLabel,
		When:     now,
		Duration: duration,
	})
}

// AsString ...
func (t *Timer) AsString(totalLabel string) string {
	out := make([]string, 0, len(t.Ticks)+1)
	var total time.Duration
	for _, tick := range t.Ticks {
		out = append(out, fmt.Sprintf("%s=%fms", tick.Event, tick.Duration.Seconds()*1000))
		total = total + tick.Duration
	}
	if totalLabel != "" {
		out = append(out, fmt.Sprintf("%s=%fms", totalLabel, total.Seconds()*1000))
	}
	return strings.Join(out, " ")
}

// AsValues ...
func (t *Timer) AsValues(totalLabel string) []interface{} {
	out := make([]interface{}, 0, 2*(len(t.Ticks)+1))
	var total time.Duration
	for _, tick := range t.Ticks {
		// AsValues() is used by structured logging, so changing
		// underscore `_` by dash `-` which is our key naming pattern.
		out = append(out, strings.ReplaceAll(tick.Event, "_", "-")+"-ms")
		out = append(out, float32(tick.Duration.Seconds()*1000))
		total = total + tick.Duration
	}
	if totalLabel != "" {
		out = append(out, strings.ReplaceAll(totalLabel, "_", "-")+"-ms")
		out = append(out, float32(total.Seconds()*1000))
	}
	return out
}
