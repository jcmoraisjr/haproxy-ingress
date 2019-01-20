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
	"sort"
)

// FindPath ...
func (f *Frontend) FindPath(path string) *FrontendPath {
	for _, p := range f.Paths {
		if p.Path == path {
			return p
		}
	}
	return nil
}

// AddPath ...
func (f *Frontend) AddPath(backend *Backend, path string) {
	f.Paths = append(f.Paths, &FrontendPath{
		Path:      path,
		Backend:   *backend,
		BackendID: backend.ID,
	})
	sort.Slice(f.Paths, func(i, j int) bool {
		return f.Paths[i].Path > f.Paths[j].Path
	})
}
