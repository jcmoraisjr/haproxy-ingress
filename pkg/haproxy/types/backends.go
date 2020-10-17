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
	"reflect"
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

// Shrink compares deleted and added backends with the same name - ie changed
// objects - and remove both from the changing hashmap tracker when they match.
func (b *Backends) Shrink() {
	changed := false
	for name, del := range b.itemsDel {
		if add, found := b.itemsAdd[name]; found {
			if backendsMatch(add, del) {
				// Such changed backend, when removed from the tracking, need to
				// be reincluded into the current state hashmap `items` and also
				// into its shard hashmap when backend sharding is enabled.
				if len(b.shards) > 0 {
					b.shards[del.shard][del.ID] = del
				}
				b.items[name] = del
				delete(b.itemsAdd, name)
				delete(b.itemsDel, name)
				changed = true
			}
		}
	}
	// Backends removed from the changing tracker might clean a shard state if it
	// was the only one changed into the shard. Recalc changedShards if anything
	// was changed.
	if changed {
		b.changedShards = map[int]bool{}
		for _, back := range b.itemsAdd {
			b.changedShards[back.shard] = true
		}
		for _, back := range b.itemsDel {
			b.changedShards[back.shard] = true
		}
	}
}

// backendsMatch returns true if two backends match. This comparison
// ignores empty endpoints and its order and it's cheaper than leave
// the backend dirty.
func backendsMatch(back1, back2 *Backend) bool {
	if reflect.DeepEqual(back1, back2) {
		return true
	}
	b1copy := *back1
	b1copy.PathsMap = back2.PathsMap
	b1copy.Endpoints = back2.Endpoints
	if !reflect.DeepEqual(&b1copy, back2) {
		return false
	}
	epmap := make(map[Endpoint]bool, len(back1.Endpoints))
	for _, ep := range back1.Endpoints {
		if !ep.IsEmpty() {
			epmap[*ep] = false
		}
	}
	for _, ep := range back2.Endpoints {
		if !ep.IsEmpty() {
			if _, found := epmap[*ep]; !found {
				return false
			}
			epmap[*ep] = true
		}
	}
	for _, found := range epmap {
		if !found {
			return false
		}
	}
	return true
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

// SortChangedEndpoints ...
func (b *Backends) SortChangedEndpoints() {
	for _, backend := range b.itemsAdd {
		backend.sortEndpoints()
	}
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
