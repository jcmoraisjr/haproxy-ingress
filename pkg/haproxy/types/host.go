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

// AcquireHost ...
func (h *Hosts) AcquireHost(hostname string) *Host {
	if host := h.FindHost(hostname); host != nil {
		return host
	}
	host := createHost(hostname)
	if host.Hostname != "*" {
		h.Items = append(h.Items, host)
		sort.Slice(h.Items, func(i, j int) bool {
			return h.Items[i].Hostname < h.Items[j].Hostname
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
	for _, f := range h.Items {
		if f.Hostname == hostname {
			return f
		}
	}
	return nil
}

func createHost(hostname string) *Host {
	return &Host{
		Hostname: hostname,
	}
}

// DefaultHost ...
func (h *Hosts) DefaultHost() *Host {
	return h.defaultHost
}

// HasSSLPassthrough ...
func (h *Hosts) HasSSLPassthrough() bool {
	// TODO this is just another HasXXX() or FindXXX() which iterates over
	// thousands of items to find an answer. Sometimes this is done more
	// than once. This need to be improved.
	// We can find this answer (regarding HasSSLPassthrough) on
	// ssl-passthrough map but it is (currently) built on instance.update()
	// which would need some knowledge and synchronization from the caller.
	for _, host := range h.Items {
		if host.SSLPassthrough {
			return true
		}
	}
	return false
}

// HasHTTP ...
func (h *Hosts) HasHTTP() bool {
	for _, host := range h.Items {
		if !host.SSLPassthrough {
			return true
		}
	}
	return false
}

// HasInvalidErrorPage ...
func (h *Hosts) HasInvalidErrorPage() bool {
	for _, host := range h.Items {
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
	for _, host := range h.Items {
		if host.HasTLSAuth() {
			return true
		}
	}
	return false
}

// HasTLSMandatory ...
func (h *Hosts) HasTLSMandatory() bool {
	for _, host := range h.Items {
		if host.HasTLSAuth() && !host.TLS.CAVerifyOptional {
			return true
		}
	}
	return false
}

// HasVarNamespace ...
func (h *Hosts) HasVarNamespace() bool {
	for _, host := range h.Items {
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

// String ...
func (h *Host) String() string {
	return fmt.Sprintf("%+v", *h)
}

// HasTLS ...
func (h *HostTLSConfig) HasTLS() bool {
	return h.TLSFilename != ""
}
