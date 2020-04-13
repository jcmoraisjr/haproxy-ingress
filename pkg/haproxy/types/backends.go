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
	"fmt"
	"sort"
)

// CreateBackends ...
func CreateBackends() *Backends {
	return &Backends{}
}

// Items ...
func (b *Backends) Items() []*Backend {
	return b.itemslist
}

// AcquireBackend ...
func (b *Backends) AcquireBackend(namespace, name, port string) *Backend {
	if backend := b.FindBackend(namespace, name, port); backend != nil {
		return backend
	}
	backend := createBackend(namespace, name, port)
	b.itemslist = append(b.itemslist, backend)
	b.sortBackends()
	return backend
}

// FindBackend ...
func (b *Backends) FindBackend(namespace, name, port string) *Backend {
	for _, b := range b.itemslist {
		if b.Namespace == namespace && b.Name == name && b.Port == port {
			return b
		}
	}
	return nil
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
	b.sortBackends()
}

func (b *Backends) sortBackends() {
	sort.Slice(b.itemslist, func(i, j int) bool {
		if b.itemslist[i] == b.defaultBackend {
			return false
		}
		if b.itemslist[j] == b.defaultBackend {
			return true
		}
		return b.itemslist[i].ID < b.itemslist[j].ID
	})
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
	return fmt.Sprintf("%s_%s_%s", namespace, name, port)
}
