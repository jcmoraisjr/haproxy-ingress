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

package utils

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// DistributedService is a wrapper that configures a Runnable to run on every
// instance of a controller, despite being the leader or not.
func DistributedService(r manager.Runnable) DS {
	return &ds{r}
}

// DS ...
type DS interface {
	Start(context.Context) error
}

type ds struct {
	r manager.Runnable
}

// Start ...
func (d *ds) Start(ctx context.Context) error {
	return d.r.Start(ctx)
}

// NeedLeaderElection ...
func (d *ds) NeedLeaderElection() bool {
	return false
}
