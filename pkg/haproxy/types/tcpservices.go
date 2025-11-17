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
	"sort"
	"strconv"
	"strings"
)

// CreateTCPServices ...
func CreateTCPServices() *TCPServices {
	return &TCPServices{
		items: map[int]*TCPServicePort{},
	}
}

// AcquireTCPService ...
func (s *TCPServices) AcquireTCPService(service string) (*TCPServicePort, *TCPServiceHost) {
	hostname, port := splitService(service)
	tcpPort := s.AcquireTCPPort(port)
	tcpHost := tcpPort.AcquireTLSHost(hostname)
	return tcpPort, tcpHost
}

func (s *TCPServices) AcquireTCPPort(port int) *TCPServicePort {
	tcpPort, found := s.items[port]
	if !found {
		tcpPort = &TCPServicePort{
			svc:   s,
			port:  port,
			hosts: make(map[string]*TCPServiceHost),
			TLS:   make(map[string]*TCPServiceTLSConfig),
		}
		s.items[port] = tcpPort
		s.changed = true
	}
	return tcpPort
}

// FindTCPPort ...
func (s *TCPServices) FindTCPPort(port int) *TCPServicePort {
	return s.items[port]
}

// Items ...
func (s *TCPServices) Items() map[int]*TCPServicePort {
	return s.items
}

// BuildSortedItems ...
func (s *TCPServices) BuildSortedItems() []*TCPServicePort {
	items := make([]*TCPServicePort, 0, len(s.items))
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

// The convention is to name tcp services as domain:port, all TCPServices receive
// service name or hostname in this format. This convention is mostly used by
// hostname tracking which is an ingress converter feature. Such convention and
// tracking stuff shouldn't be reflecting here. Time to use a proper type without
// conventions and assumptions.
// TODO Use a proper service name or hostname type
func splitService(service string) (hostname string, port int) {
	hostname = service
	if pos := strings.Index(hostname, ":"); pos >= 0 {
		hostname = service[:pos]
		port, _ = strconv.Atoi(service[pos+1:])
	}
	return hostname, port
}

// RemoveService ...
func (s *TCPServices) RemoveService(service string) {
	hostname, port := splitService(service)
	if item, found := s.items[port]; found {
		if _, hasHost := item.hosts[hostname]; hasHost {
			delete(item.hosts, hostname)
			s.changed = true
		}
		if hostname == DefaultHost {
			item.defaultHost = nil
			s.changed = true
		}
		if item.isEmpty() {
			delete(s.items, port)
			s.changed = true
		}
	}
}

// RemoveAll removes services declared as a slice of <hostname>:<port>
func (s *TCPServices) RemoveAll(services []string) {
	for _, svc := range services {
		s.RemoveService(svc)
	}
}

func (s *TCPServices) RemoveAllLinks(pathlinks ...*PathLink) {
	for _, link := range pathlinks {
		s.RemoveService(link.hostname)
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

func (s *TCPServicePort) isEmpty() bool {
	return s.defaultHost == nil && len(s.hosts) == 0
}

func (s *TCPServicePort) AcquireDefaultHost() *TCPServiceHost {
	return s.AcquireTLSHost(DefaultHost)
}

func (s *TCPServicePort) AcquireTLSHost(hostname string) *TCPServiceHost {
	if hostname == DefaultHost && s.defaultHost != nil {
		return s.defaultHost
	}
	tcpHost, found := s.hosts[hostname]
	if !found {
		tcpHost = &TCPServiceHost{tcpport: s, hostname: hostname}
		if hostname == DefaultHost {
			s.defaultHost = tcpHost
		} else {
			s.hosts[hostname] = tcpHost
		}
		s.svc.changed = true
	}
	return tcpHost
}

// Port ...
func (s *TCPServicePort) Port() int {
	return s.port
}

// Hosts ...
func (s *TCPServicePort) Hosts() map[string]*TCPServiceHost {
	return s.hosts
}

// BuildSortedItems ...
func (s *TCPServicePort) BuildSortedItems() []*TCPServiceHost {
	items := make([]*TCPServiceHost, 0, len(s.hosts))
	for _, item := range s.hosts {
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].hostname < items[j].hostname
	})
	return items
}

// BuildSortedTLSConfig ...
func (s *TCPServicePort) BuildSortedTLSConfig() []*TCPServiceTLSConfig {
	keys := make([]string, 0, len(s.TLS))
	for hostname := range s.TLS {
		keys = append(keys, hostname)
	}
	sort.Strings(keys)
	config := make([]*TCPServiceTLSConfig, 0, len(keys))
	for _, key := range keys {
		config = append(config, s.TLS[key])
	}
	return config
}

// HasTLS ...
func (s *TCPServicePort) HasTLS() bool {
	return len(s.TLS) > 0
}

// DefaultHost ...
func (s *TCPServicePort) DefaultHost() *TCPServiceHost {
	return s.defaultHost
}

// Hostname ...
func (s *TCPServiceHost) Hostname() string {
	return s.hostname
}
