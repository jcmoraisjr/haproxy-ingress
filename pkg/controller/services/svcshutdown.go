/*
Copyright 2025 The HAProxy Ingress Controller Authors.

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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
)

type svcShutdown struct {
	instance haproxy.Instance
}

func (s *svcShutdown) Start(ctx context.Context) error {
	<-ctx.Done()
	// configuring it as a runnable makes controller-runtime to wait until haproxy finishes
	s.instance.Shutdown()
	return nil
}
