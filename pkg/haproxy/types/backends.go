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
	"crypto/md5"
	"sort"
)

// CreateBackends ...
func CreateBackends(shardCount int) *Backends {
	shards := make([]map[string]*Backend, shardCount)
	for i := range shards {
		shards[i] = map[string]*Backend{}
	}
	return &Backends{
		items:         map[string]*Backend{},
		itemsAdd:      map[string]*Backend{},
		itemsDel:      map[string]*Backend{},
		shards:        shards,
		changedShards: map[int]bool{},
	}
}

// Items ...
func (b *Backends) Items() map[string]*Backend {
	return b.items
}

// ItemsAdd ...
func (b *Backends) ItemsAdd() map[string]*Backend {
	return b.itemsAdd
}

// ItemsDel ...
func (b *Backends) ItemsDel() map[string]*Backend {
	return b.itemsDel
}

// Commit ...
func (b *Backends) Commit() {
	b.itemsAdd = map[string]*Backend{}
	b.itemsDel = map[string]*Backend{}
	b.changedShards = map[int]bool{}
}

// Changed ...
func (b *Backends) Changed() bool {
	return len(b.itemsAdd) > 0 || len(b.itemsDel) > 0
}

// ChangedShards ...
func (b *Backends) ChangedShards() []int {
	changed := []int{}
	for i, c := range b.changedShards {
		if c {
			changed = append(changed, i)
		}
	}
	sort.Ints(changed)
	return changed
}

// BuildSortedItems ...
func (b *Backends) BuildSortedItems() []*Backend {
	// TODO BuildSortedItems() is currently used only by the backend template.
	// The main cfg template doesn't care if there are backend shards or not,
	// so the logic is here, but this doesn't seem to be a good place.
	if len(b.shards) == 0 {
		return b.buildSortedItems(b.items)
	}
	return nil
}

// BuildSortedShard ...
func (b *Backends) BuildSortedShard(shardRef int) []*Backend {
	return b.buildSortedItems(b.shards[shardRef])
}

func (b *Backends) buildSortedItems(backendItems map[string]*Backend) []*Backend {
	items := make([]*Backend, len(backendItems))
	var i int
	for _, item := range backendItems {
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
	shardCount := len(b.shards)
	backend := createBackend(shardCount, namespace, name, port)
	b.items[backend.ID] = backend
	b.itemsAdd[backend.ID] = backend
	if shardCount > 0 {
		b.shards[backend.shard][backend.ID] = backend
	}
	b.changedShards[backend.shard] = true
	return backend
}

// FindBackend ...
func (b *Backends) FindBackend(namespace, name, port string) *Backend {
	return b.items[buildID(namespace, name, port)]
}

// FindBackendID ...
func (b *Backends) FindBackendID(backendID BackendID) *Backend {
	return b.items[backendID.String()]
}

// RemoveAll ...
func (b *Backends) RemoveAll(backendID []BackendID) {
	for _, backend := range backendID {
		id := backend.String()
		if item, found := b.items[id]; found {
			if len(b.shards) > 0 {
				delete(b.shards[item.shard], id)
			}
			b.changedShards[item.shard] = true
			b.itemsDel[id] = item
			delete(b.items, id)
		}
	}
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

func (b BackendID) String() string {
	if b.id == "" {
		b.id = b.Namespace + "_" + b.Name + "_" + b.Port
	}
	return b.id
}

func createBackend(shards int, namespace, name, port string) *Backend {
	id := buildID(namespace, name, port)
	var shard int
	if shards > 0 {
		hash := md5.Sum([]byte(id))
		part0 := uint64(hash[0])<<56 |
			uint64(hash[1])<<48 |
			uint64(hash[2])<<40 |
			uint64(hash[3])<<32 |
			uint64(hash[4])<<24 |
			uint64(hash[5])<<16 |
			uint64(hash[6])<<8 |
			uint64(hash[7])
		part1 := uint64(hash[8])<<56 |
			uint64(hash[9])<<48 |
			uint64(hash[10])<<40 |
			uint64(hash[11])<<32 |
			uint64(hash[12])<<24 |
			uint64(hash[13])<<16 |
			uint64(hash[14])<<8 |
			uint64(hash[15])
		shard = int(uint64(part0^part1) % uint64(shards))
	}
	return &Backend{
		shard:     shard,
		ID:        id,
		Namespace: namespace,
		Name:      name,
		Port:      port,
		Server:    ServerConfig{InitialWeight: 1},
	}
}

func buildID(namespace, name, port string) string {
	return namespace + "_" + name + "_" + port
}
