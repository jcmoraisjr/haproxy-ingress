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
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// UpdaterMock ...
type UpdaterMock struct{}

// UpdateGlobalConfig ...
func (u *UpdaterMock) UpdateGlobalConfig(global *hatypes.Global, config *ingtypes.Config) {
}

// UpdateHostConfig ...
func (u *UpdaterMock) UpdateHostConfig(host *hatypes.Host, ann *ingtypes.HostAnnotations) {
	host.Timeout.Client = ann.TimeoutClient
	host.RootRedirect = ann.AppRoot
}

// UpdateBackendConfig ...
func (u *UpdaterMock) UpdateBackendConfig(backend *hatypes.Backend, ann *ingtypes.BackendAnnotations) {
	backend.MaxconnServer = ann.MaxconnServer
	backend.BalanceAlgorithm = ann.BalanceAlgorithm
}
