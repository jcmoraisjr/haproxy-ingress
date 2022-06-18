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

package legacy

import (
	"fmt"

	"k8s.io/klog/v2"
)

type logger struct {
	depth int
}

func (l *logger) build(msg string, args []interface{}) string {
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

func (l *logger) InfoV(v int, msg string, args ...interface{}) {
	if klog.V(klog.Level(v)).Enabled() {
		klog.InfoDepth(l.depth, l.build(msg, args))
	}
}

func (l *logger) Info(msg string, args ...interface{}) {
	klog.InfoDepth(l.depth, l.build(msg, args))
}

func (l *logger) Warn(msg string, args ...interface{}) {
	klog.WarningDepth(l.depth, l.build(msg, args))
}

func (l *logger) Error(msg string, args ...interface{}) {
	klog.ErrorDepth(l.depth, l.build(msg, args))
}

func (l *logger) Fatal(msg string, args ...interface{}) {
	klog.ExitDepth(l.depth, l.build(msg, args))
}
