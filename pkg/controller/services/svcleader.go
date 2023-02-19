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

	"github.com/go-logr/logr"
)

// SvcLeaderChangedFnc ...
type SvcLeaderChangedFnc func(isLeader bool)

func initSvcLeader(ctx context.Context) *svcLeader {
	return &svcLeader{
		log: logr.FromContextOrDiscard(ctx).WithName("leader"),
	}
}

type svcLeader struct {
	isLeader    bool
	log         logr.Logger
	subscribers []SvcLeaderChangedFnc
}

func (s *svcLeader) addsubscriber(f SvcLeaderChangedFnc) {
	s.subscribers = append(s.subscribers, f)
}

func (s *svcLeader) getIsLeader() bool {
	return s.isLeader
}

func (s *svcLeader) Start(ctx context.Context) error {
	s.log.Info("leader acquired")
	s.isLeader = true
	for _, f := range s.subscribers {
		go f(true)
	}
	<-ctx.Done()
	s.isLeader = false
	for _, f := range s.subscribers {
		go f(false)
	}
	s.log.Info("stopped leading")
	return nil
}
