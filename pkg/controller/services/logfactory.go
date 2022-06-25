/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package services

import (
	"context"
	"fmt"
	"os"

	"github.com/go-logr/logr"
)

func initLogFactory(ctx context.Context) *lfactory {
	return &lfactory{
		ctx: ctx,
	}
}

type lfactory struct {
	ctx context.Context
}

func (f *lfactory) new(name string) *l {
	logger := logr.FromContextOrDiscard(f.ctx).WithName(name).WithCallDepth(1)
	return &l{
		v1: logger,
		v2: logger.V(1),
		v3: logger.V(2),
	}
}

type l struct {
	v1 logr.Logger
	v2 logr.Logger
	v3 logr.Logger
}

func (l *l) InfoV(v int, msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	switch v {
	case 1:
		l.v1.Info(msg)
	case 2:
		l.v2.Info(msg)
	case 3:
		l.v3.Info(msg)
	default:
		l.v1.V(v - 1).Info(msg)
	}
}

func (l *l) Info(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	l.v1.Info(msg)
}

func (l *l) Warn(msg string, args ...interface{}) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	l.v1.Error(nil, msg)
}

func (l *l) Error(msg string, args ...interface{}) {
	l.v1.Error(fmt.Errorf(msg, args...), "")
}

func (l *l) Fatal(msg string, args ...interface{}) {
	l.v1.Error(fmt.Errorf(msg, args...), "")
	os.Exit(2)
}
