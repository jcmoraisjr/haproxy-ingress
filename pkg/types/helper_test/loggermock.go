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

package helper_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
)

// LoggerMock ...
type LoggerMock struct {
	Logging []string
	T       *testing.T
}

// Info ...
func (l *LoggerMock) Info(msg string, args ...interface{}) {
	l.log("INFO", msg, args...)
}

// InfoV ...
func (l *LoggerMock) InfoV(v int, msg string, args ...interface{}) {
	l.log(fmt.Sprintf("INFO-V(%d)", v), msg, args...)
}

// Warn ...
func (l *LoggerMock) Warn(msg string, args ...interface{}) {
	l.log("WARN", msg, args...)
}

// Error ...
func (l *LoggerMock) Error(msg string, args ...interface{}) {
	l.log("ERROR", msg, args...)
}

// Fatal ...
func (l *LoggerMock) Fatal(msg string, args ...interface{}) {
	l.log("FATAL", msg, args...)
}

func (l *LoggerMock) log(level, msg string, args ...interface{}) {
	l.Logging = append(l.Logging, fmt.Sprintf(level+" "+msg, args...))
}

// CompareLogging ...
func (l *LoggerMock) CompareLogging(expected string) {
	l.compareText(strings.Join(l.Logging, "\n"), expected)
	l.Logging = []string{}
}

func (l *LoggerMock) compareText(actual, expected string) {
	txt1 := "\n" + strings.Trim(expected, "\n")
	txt2 := "\n" + strings.Trim(actual, "\n")
	if txt1 != txt2 {
		l.T.Error(diff.Diff(txt1, txt2))
	}
}
