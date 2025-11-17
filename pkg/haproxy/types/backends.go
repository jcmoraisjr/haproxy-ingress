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
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// CreateBackends ...
func CreateBackends(shardCount int) *Backends {
	shards := make([]map[string]*Backend, shardCount)
	for i := range shards {
		shards[i] = map[string]*Backend{}
	}
	backends := &Backends{
		items:         map[string]*Backend{},
		itemsAdd:      map[string]*Backend{},
		itemsDel:      map[string]*Backend{},
		authBackends:  map[string]*Backend{},
		shards:        shards,
		changedShards: map[int]bool{},
	}
	backends.DefaultBackend = backends.AcquireNotFoundBackend()
	return backends
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

func (b *Backends) Clear() {
	nb := CreateBackends(len(b.shards))
	for i := range nb.shards {
		if len(nb.shards[i]) > 0 {
			// flag only shards with at least one backend associated,
			// so it has the chance to be updated (removed or cleaned)
			// in the case that the new state doesn't add any backends.
			b.backendShardChanged(i)
		}
	}
	nb.itemsDel = b.items
	*b = *nb
}

// Shrink compares deleted and added backends with the same name - ie changed
// objects - and remove both from the changing hashmap tracker when they match.
func (b *Backends) Shrink() {
	changed := false
	for name, del := range b.itemsDel {
		if add, found := b.itemsAdd[name]; found {
			if len(add.Endpoints) <= len(del.Endpoints) && backendsMatch(add, del) {
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
			b.BackendChanged(back)
		}
		for _, back := range b.itemsDel {
			b.BackendChanged(back)
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
	b1copy.pathsMaps = back2.pathsMaps
	b1copy.pathsConfigs = back2.pathsConfigs
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

// BackendChanged ...
func (b *Backends) BackendChanged(backend *Backend) {
	b.backendShardChanged(backend.shard)
}

func (b *Backends) backendShardChanged(shard int) {
	b.changedShards[shard] = true
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

// FillSourceIPs ...
func (b *Backends) FillSourceIPs() {
	for _, backend := range b.itemsAdd {
		backend.fillSourceIPs()
	}
}

// SortChangedEndpoints ...
func (b *Backends) SortChangedEndpoints(sortBy string) {
	for _, backend := range b.itemsAdd {
		backend.sortEndpoints(sortBy)
	}
}

// ShuffleAllEndpoints ...
func (b *Backends) ShuffleAllEndpoints() {
	for _, backend := range b.items {
		backend.shuffleEndpoints()
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
		return items[i].ID < items[j].ID
	})
	return items
}

// BuildUsedAuthBackends ...
func (b *Backends) BuildUsedAuthBackends() map[string]bool {
	usedNames := map[string]bool{}
	for _, backend := range b.items {
		for _, path := range backend.Paths {
			name := path.AuthExtBack.AuthBackendName
			if name != "" {
				usedNames[name] = true
			}
		}
	}
	return usedNames
}

func (b *Backends) BuildHTTPResponses() (responses []HTTPResponses) {
	// TODO this should be a bit noisy on deployments having tens of thousands of backends.
	// Cache? Need to handle partial update. Leave it simple? Make at least some performance tests.
	for _, backend := range b.items {
		res := &backend.CustomHTTPResponses
		res.ID = backend.ID
		if len(res.HAProxy) > 0 || len(res.Lua) > 0 {
			responses = append(responses, HTTPResponses{
				ID:      res.ID,
				HAProxy: res.HAProxy,
				Lua:     res.Lua,
			})
		}
	}
	// predictable response
	sort.Slice(responses, func(i, j int) bool {
		return responses[i].ID < responses[j].ID
	})
	return responses
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
	b.BackendChanged(backend)
	return backend
}

func (b *Backends) HasBackend(name string) bool {
	switch name {
	case "_redirect_https":
		return b.httpsRedir != nil
	case "_error404":
		return b.error404 != nil
	}
	return false
}

// AcquireHTTPSRedirectBackend ...
func (b *Backends) AcquireRedirectHTTPSBackend() *Backend {
	if b.httpsRedir == nil {
		b.httpsRedir = createBackend(0, "_redirect_https", "", "") // this is hardcoded in the template, outside the backend list
	}
	return b.httpsRedir
}

// AcquireNotFoundBackend ...
func (b *Backends) AcquireNotFoundBackend() *Backend {
	if b.error404 == nil {
		b.error404 = createBackend(0, "_error404", "", "") // this is also hardcoded in the template
	}
	return b.error404
}

// AcquireAuthBackend ...
func (b *Backends) AcquireAuthBackend(ipList []string, port int, hostname string) *Backend {
	sort.Strings(ipList)
	key := fmt.Sprintf("%s:%d:%s", strings.Join(ipList, ","), port, hostname)
	backend := b.authBackends[key]
	if backend == nil {
		name := fmt.Sprintf("backend%03d", len(b.authBackends)+1)
		backend = b.AcquireBackend("_auth", name, strconv.Itoa(port))
		if hostname != "" {
			backend.CustomConfigLate = []string{"http-request set-header Host " + hostname}
		}
		for _, ip := range ipList {
			_ = backend.AcquireEndpoint(ip, port, "")
		}
		b.authBackends[key] = backend
	}
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
func (b *Backends) RemoveAll(backendID []string) {
	for _, id := range backendID {
		if item, found := b.items[id]; found {
			if len(b.shards) > 0 {
				delete(b.shards[item.shard], id)
			}
			b.BackendChanged(item)
			b.itemsDel[id] = item
			if item == b.DefaultBackend {
				b.DefaultBackend = nil
			}
			delete(b.items, id)
		}
	}
}

// IsEmpty ...
func (b BackendID) IsEmpty() bool {
	return b.Name == ""
}

func (b BackendID) String() string {
	if b.id == "" {
		b.id = buildID(b.Namespace, b.Name, b.Port)
	}
	return b.id
}

func createBackend(shards int, namespace, name, port string) *Backend {
	id := buildID(namespace, name, port)
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
	hash64 := part0 ^ part1
	var shard int
	if shards > 0 {
		shard = int(hash64 % uint64(shards))
	}
	return &Backend{
		hash64:    hash64,
		shard:     shard,
		ID:        id,
		Namespace: namespace,
		Name:      name,
		Port:      port,
		Server:    ServerConfig{InitialWeight: 1},
	}
}

func buildID(namespace, name, port string) string {
	if name == "" && port == "" {
		return namespace
	}
	return namespace + "_" + name + "_" + port
}
