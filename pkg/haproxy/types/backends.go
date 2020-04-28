/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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

// CreateBackends ...
func CreateBackends() *Backends {
	return &Backends{
		itemsmap: map[string]*Backend{},
	}
}

// Items ...
func (b *Backends) Items() map[string]*Backend {
	return b.itemsmap
}

// BuildSortedItems ...
func (b *Backends) BuildSortedItems() []*Backend {
	items := make([]*Backend, len(b.itemsmap))
	var i int
	for _, item := range b.itemsmap {
		items[i] = item
		i++
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i] == b.defaultBackend {
			return false
		}
		if items[j] == b.defaultBackend {
			return true
		}
		return items[i].ID < items[j].ID
	})
	return items
}

// AcquireBackend ...
func (b *Backends) AcquireBackend(namespace, name, port string) *Backend {
	if backend := b.FindBackend(namespace, name, port); backend != nil {
		return backend
	}
	backend := createBackend(namespace, name, port)
	b.itemsmap[backend.ID] = backend
	return backend
}

// FindBackend ...
func (b *Backends) FindBackend(namespace, name, port string) *Backend {
	return b.itemsmap[buildID(namespace, name, port)]
}

// FindBackendID ...
func (b *Backends) FindBackendID(backendID BackendID) *Backend {
	return b.itemsmap[backendID.String()]
}

// RemoveAll ...
func (b *Backends) RemoveAll(backendID []BackendID) {
	for _, backend := range backendID {
		delete(b.itemsmap, backend.String())
	}
	// IMPLEMENT
	// track and remove unused userlist entries
}

// DefaultBackend ...
func (b *Backends) DefaultBackend() *Backend {
	return b.defaultBackend
}

// SetDefaultBackend ...
func (b *Backends) SetDefaultBackend(defaultBackend *Backend) {
	if b.defaultBackend != nil {
		def := b.defaultBackend
		def.ID = buildID(def.Namespace, def.Name, def.Port)
	}
	b.defaultBackend = defaultBackend
	if b.defaultBackend != nil {
		b.defaultBackend.ID = "_default_backend"
	}
}

func (b *BackendID) String() string {
	if b.id == "" {
		b.id = b.Namespace + "_" + b.Name + "_" + b.Port
	}
	return b.id
}

func createBackend(namespace, name, port string) *Backend {
	return &Backend{
		ID:        buildID(namespace, name, port),
		Namespace: namespace,
		Name:      name,
		Port:      port,
		Server:    ServerConfig{InitialWeight: 1},
	}
}

func buildID(namespace, name, port string) string {
	return namespace + "_" + name + "_" + port
}
