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
)

// CreateHosts ...
func CreateHosts() *Hosts {
	return &Hosts{
		itemsmap: map[string]*Host{},
	}
}

// AcquireHost ...
func (h *Hosts) AcquireHost(hostname string) *Host {
	if host := h.FindHost(hostname); host != nil {
		return host
	}
	host := h.createHost(hostname)
	if host.Hostname != "*" {
		// Here we store a just created Host. Both slice and map.
		// The slice has the order and the map has the index.
		// TODO current approach is using the double of the memory
		// on behalf of speed. Map only is doable? Another approach?
		h.itemsmap[hostname] = host
		h.itemslist = append(h.itemslist, host)
		sort.Slice(h.itemslist, func(i, j int) bool {
			return h.itemslist[i].Hostname < h.itemslist[j].Hostname
		})
	} else {
		h.defaultHost = host
	}
	return host
}

// FindHost ...
func (h *Hosts) FindHost(hostname string) *Host {
	if hostname == "*" && h.defaultHost != nil {
		return h.defaultHost
	}
	return h.itemsmap[hostname]
}

func (h *Hosts) createHost(hostname string) *Host {
	return &Host{
		Hostname: hostname,
		hosts:    h,
	}
}

// Items ...
func (h *Hosts) Items() []*Host {
	return h.itemslist
}

// DefaultHost ...
func (h *Hosts) DefaultHost() *Host {
	return h.defaultHost
}

// HasSSLPassthrough ...
func (h *Hosts) HasSSLPassthrough() bool {
	return h.sslPassthroughCount > 0
}

// HasHTTP ...
func (h *Hosts) HasHTTP() bool {
	return len(h.itemslist) > h.sslPassthroughCount
}

// HasInvalidErrorPage ...
func (h *Hosts) HasInvalidErrorPage() bool {
	for _, host := range h.itemslist {
		if host.TLS.CAErrorPage != "" {
			return true
		}
	}
	return false
}

// HasNoCrtErrorPage ...
func (h *Hosts) HasNoCrtErrorPage() bool {
	// Use currently the same attribute
	return h.HasInvalidErrorPage()
}

// HasTLSAuth ...
func (h *Hosts) HasTLSAuth() bool {
	for _, host := range h.itemslist {
		if host.HasTLSAuth() {
			return true
		}
	}
	return false
}

// HasTLSMandatory ...
func (h *Hosts) HasTLSMandatory() bool {
	for _, host := range h.itemslist {
		if host.HasTLSAuth() && !host.TLS.CAVerifyOptional {
			return true
		}
	}
	return false
}

// HasVarNamespace ...
func (h *Hosts) HasVarNamespace() bool {
	for _, host := range h.itemslist {
		if host.VarNamespace {
			return true
		}
	}
	return false
}

// FindPath ...
func (h *Host) FindPath(path string) *HostPath {
	for _, p := range h.Paths {
		if p.Path == path {
			return p
		}
	}
	return nil
}

// AddPath ...
func (h *Host) AddPath(backend *Backend, path string) {
	var hback HostBackend
	if backend != nil {
		hback = HostBackend{
			ID:        backend.ID,
			Namespace: backend.Namespace,
			Name:      backend.Name,
			Port:      backend.Port,
		}
		backend.AddHostPath(h.Hostname, path)
	} else {
		hback = HostBackend{ID: "_error404"}
	}
	h.Paths = append(h.Paths, &HostPath{
		Path:    path,
		Backend: hback,
	})
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(h.Paths, func(i, j int) bool {
		return h.Paths[i].Path > h.Paths[j].Path
	})
}

// HasTLSAuth ...
func (h *Host) HasTLSAuth() bool {
	return h.TLS.CAHash != ""
}

// SSLPassthrough ...
func (h *Host) SSLPassthrough() bool {
	return h.sslPassthrough
}

// SetSSLPassthrough ...
func (h *Host) SetSSLPassthrough(value bool) {
	if h.sslPassthrough == value {
		return
	}
	if value {
		h.hosts.sslPassthroughCount++
	} else {
		h.hosts.sslPassthroughCount--
	}
	h.sslPassthrough = value
}

// String ...
func (h *Host) String() string {
	return fmt.Sprintf("%+v", *h)
}

// HasTLS ...
func (h *HostTLSConfig) HasTLS() bool {
	return h.TLSFilename != ""
}
