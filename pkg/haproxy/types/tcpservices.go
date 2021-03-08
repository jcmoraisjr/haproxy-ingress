/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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
	"strconv"
	"strings"
)

// CreateTCPServices ...
func CreateTCPServices() *TCPServices {
	return &TCPServices{
		items: map[int]*TCPService{},
	}
}

// AddTCPService ...
func (s *TCPServices) AddTCPService(port int) (*TCPService, error) {
	if _, found := s.items[port]; found {
		return nil, fmt.Errorf("port '%d' was already used", port)
	}
	service := &TCPService{port: port}
	s.items[port] = service
	return service, nil
}

// FindTCPService ...
func (s *TCPServices) FindTCPService(port int) *TCPService {
	return s.items[port]
}

// Items ...
func (s *TCPServices) Items() map[int]*TCPService {
	return s.items
}

// BuildSortedItems ...
func (s *TCPServices) BuildSortedItems() []*TCPService {
	items := make([]*TCPService, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].port < items[j].port
	})
	return items
}

// RemovePort ...
func (s *TCPServices) RemovePort(port int) {
	if _, found := s.items[port]; found {
		delete(s.items, port)
		s.changed = true
	}
}

// RemoveAll removes services declared as a slice of <hostname>:<port>
func (s *TCPServices) RemoveAll(services []string) {
	for _, svc := range services {
		pos := strings.Index(svc, ":")
		if pos >= 0 {
			port, _ := strconv.Atoi(svc[pos+1:])
			s.RemovePort(port)
		}
	}
}

// Changed ...
func (s *TCPServices) Changed() bool {
	return s.changed
}

// Commit ...
func (s *TCPServices) Commit() {
	s.changed = false
}

// Port ...
func (s *TCPService) Port() int {
	return s.port
}
