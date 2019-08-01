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
	Start time.Time
	Ticks []*Tick
}

// Tick ...
type Tick struct {
	Event string
	When  time.Time
}

// NewTimer ...
func NewTimer() *Timer {
	return &Timer{
		Start: time.Now(),
	}
}

// Tick ...
func (t *Timer) Tick(eventLabel string) {
	t.Ticks = append(t.Ticks, &Tick{
		Event: eventLabel,
		When:  time.Now(),
	})
}

// AsString ...
func (t *Timer) AsString(totalLabel string) string {
	out := make([]string, 0, len(t.Ticks)+1)
	last := t.Start
	for _, tick := range t.Ticks {
		out = append(out, fmt.Sprintf("%s=%fms", tick.Event, tick.When.Sub(last).Seconds()*1000))
		last = tick.When
	}
	if totalLabel != "" {
		out = append(out, fmt.Sprintf("%s=%fms", totalLabel, last.Sub(t.Start).Seconds()*1000))
	}
	return strings.Join(out, " ")
}
