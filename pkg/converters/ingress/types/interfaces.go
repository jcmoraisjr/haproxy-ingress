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

package types

import (
	api "k8s.io/api/core/v1"
)

// Cache ...
type Cache interface {
	GetService(serviceName string) (*api.Service, error)
	GetEndpoints(service *api.Service) (*api.Endpoints, error)
	GetTerminatingPods(service *api.Service) ([]*api.Pod, error)
	GetPod(podName string) (*api.Pod, error)
	GetTLSSecretPath(secretName string) (File, error)
	GetCASecretPath(secretName string) (File, error)
	GetDHSecretPath(secretName string) (File, error)
	GetSecretContent(secretName, keyName string) ([]byte, error)
}
