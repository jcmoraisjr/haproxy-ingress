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
	"reflect"
	"sort"
)

// CreateTCPBackends ...
func CreateTCPBackends() *TCPBackends {
	return &TCPBackends{
		items:    map[int]*TCPBackend{},
		itemsAdd: map[int]*TCPBackend{},
		itemsDel: map[int]*TCPBackend{},
	}
}

// Acquire ...
func (b *TCPBackends) Acquire(servicename string, port int) *TCPBackend {
	if backend, found := b.items[port]; found {
		backend.Name = servicename
		return backend
	}
	backend := &TCPBackend{
		Name: servicename,
		Port: port,
	}
	b.items[port] = backend
	b.itemsAdd[port] = backend
	return backend
}

// BuildSortedItems ...
func (b *TCPBackends) BuildSortedItems() []*TCPBackend {
	items := make([]*TCPBackend, len(b.items))
	var i int
	for _, item := range b.items {
		items[i] = item
		i++
	}
	sort.Slice(items, func(i, j int) bool {
		back1 := items[i]
		back2 := items[j]
		if back1.Name == back2.Name {
			return back1.Port < back2.Port
		}
		return back1.Name < back2.Name
	})
	if len(items) == 0 {
		return nil
	}
	return items
}

// Changed ...
func (b *TCPBackends) Changed() bool {
	return !reflect.DeepEqual(b.itemsAdd, b.itemsDel)
}

// Commit ...
func (b *TCPBackends) Commit() {
	b.itemsAdd = map[int]*TCPBackend{}
	b.itemsDel = map[int]*TCPBackend{}
}

// RemoveAll ...
func (b *TCPBackends) RemoveAll() {
	for port, item := range b.items {
		b.itemsDel[port] = item
		delete(b.items, port)
	}
}

// AddEndpoint ...
func (b *TCPBackend) AddEndpoint(ip string, port int) *TCPEndpoint {
	ep := &TCPEndpoint{
		Name:   fmt.Sprintf("srv%03d", len(b.Endpoints)+1),
		IP:     ip,
		Port:   port,
		Target: fmt.Sprintf("%s:%d", ip, port),
	}
	b.Endpoints = append(b.Endpoints, ep)
	return ep
}
