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
	"fmt"
	"sort"
)

// FindPath ...
func (h *Host) FindPath(path string) *HostPath {
	for _, p := range h.Paths {
		if p.Path == path {
			return p
		}
	}
	return nil
}

// AddPath ...
func (h *Host) AddPath(backend *Backend, path string) {
	h.Paths = append(h.Paths, &HostPath{
		Path: path,
		Backend: HostBackend{
			ID:        backend.ID,
			Namespace: backend.Namespace,
			Name:      backend.Name,
			Port:      backend.Port,
		},
	})
	backend.AddHostPath(h.Hostname, path)
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(h.Paths, func(i, j int) bool {
		return h.Paths[i].Path > h.Paths[j].Path
	})
}

// HasTLSAuth ...
func (h *Host) HasTLSAuth() bool {
	return h.TLS.CAHash != ""
}

// String ...
func (h *Host) String() string {
	return fmt.Sprintf("%+v", *h)
}
