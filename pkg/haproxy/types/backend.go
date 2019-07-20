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
	"strings"
)

// NewBackendPaths ...
func NewBackendPaths(paths ...*BackendPath) BackendPaths {
	b := BackendPaths{}
	b.Add(paths...)
	return b
}

// NewEndpoint ...
func (b *Backend) NewEndpoint(ip string, port int, targetRef string) *Endpoint {
	endpoint := &Endpoint{
		Name:      fmt.Sprintf("%s:%d", ip, port),
		IP:        ip,
		Port:      port,
		TargetRef: targetRef,
		Weight:    1,
	}
	b.Endpoints = append(b.Endpoints, endpoint)
	sort.Slice(b.Endpoints, func(i, j int) bool {
		return b.Endpoints[i].Name < b.Endpoints[j].Name
	})
	return endpoint
}

// FindPath ...
func (b *Backend) FindPath(path string) *BackendPath {
	for _, p := range b.Paths {
		if p.Path == path {
			return p
		}
	}
	return nil
}

// AddPath ...
func (b *Backend) AddPath(path string) *BackendPath {
	// add only unique paths
	backendPath := b.FindPath(path)
	if backendPath != nil {
		return backendPath
	}
	// host's paths that references this backend
	// used on RewriteURL config
	backendPath = &BackendPath{
		ID:   fmt.Sprintf("path%02d", len(b.Paths)+1),
		Path: path,
	}
	b.Paths = append(b.Paths, backendPath)
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(b.Paths, func(i, j int) bool {
		return b.Paths[i].Path > b.Paths[j].Path
	})
	return backendPath
}

// NeedACL ...
func (b *Backend) NeedACL() bool {
	return len(b.HSTS) > 1 || len(b.Whitelist) > 1
}

// IDList ...
func (p *BackendPaths) IDList() string {
	ids := make([]string, len(p.Items))
	for i, item := range p.Items {
		ids[i] = item.ID
	}
	return strings.Join(ids, " ")
}

// Add ...
func (p *BackendPaths) Add(paths ...*BackendPath) {
	for _, path := range paths {
		p.Items = append(p.Items, path)
	}
	sort.SliceStable(p.Items, func(i, j int) bool {
		return p.Items[i].Path < p.Items[j].Path
	})
}

// String ...
func (p *BackendPath) String() string {
	return fmt.Sprintf("%+v", *p)
}

// String ...
func (b *BackendConfigStr) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigHSTS) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigWhitelist) String() string {
	return fmt.Sprintf("%+v", *b)
}
