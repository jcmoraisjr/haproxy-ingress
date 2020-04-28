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
	"strings"
)

// NewBackendPaths ...
func NewBackendPaths(paths ...*BackendPath) BackendPaths {
	b := BackendPaths{}
	b.Add(paths...)
	return b
}

// BackendID ...
func (b *Backend) BackendID() BackendID {
	return BackendID{
		Namespace: b.Namespace,
		Name:      b.Name,
		Port:      b.Port,
	}
}

// FindEndpoint ...
func (b *Backend) FindEndpoint(target string) *Endpoint {
	for _, endpoint := range b.Endpoints {
		if endpoint.Target == target {
			return endpoint
		}
	}
	return nil
}

// ClearEndpoints ...
func (b *Backend) ClearEndpoints() {
	b.Endpoints = nil
}

// AcquireEndpoint ...
func (b *Backend) AcquireEndpoint(ip string, port int, targetRef string) *Endpoint {
	endpoint := b.FindEndpoint(fmt.Sprintf("%s:%d", ip, port))
	if endpoint != nil {
		return endpoint
	}
	return b.addEndpoint(ip, port, targetRef)
}

// AddEmptyEndpoint ...
func (b *Backend) AddEmptyEndpoint() *Endpoint {
	endpoint := b.addEndpoint("127.0.0.1", 1023, "")
	endpoint.Enabled = false
	return endpoint
}

func (b *Backend) addEndpoint(ip string, port int, targetRef string) *Endpoint {
	var name string
	switch b.EpNaming {
	case EpTargetRef:
		names := strings.Split(targetRef, "/")
		name = names[len(names)-1]
	case EpIPPort:
		if ip != "127.0.0.1" {
			name = fmt.Sprintf("%s:%d", ip, port)
		}
	}
	if name == "" {
		name = fmt.Sprintf("srv%03d", len(b.Endpoints)+1)
	}
	endpoint := &Endpoint{
		Name:      name,
		IP:        ip,
		Port:      port,
		Target:    fmt.Sprintf("%s:%d", ip, port),
		Enabled:   true,
		TargetRef: targetRef,
		Weight:    b.Server.InitialWeight,
	}
	b.Endpoints = append(b.Endpoints, endpoint)
	return endpoint
}

// SortEndpoints ...
func (b *Backend) SortEndpoints() {
	sort.SliceStable(b.Endpoints, func(i, j int) bool {
		return b.Endpoints[i].Name < b.Endpoints[j].Name
	})
}

// FindHostPath ...
func (b *Backend) FindHostPath(hostpath string) *BackendPath {
	for _, p := range b.Paths {
		if p.Hostpath == hostpath {
			return p
		}
	}
	return nil
}

// AddHostPath ...
func (b *Backend) AddHostPath(hostname, path string) *BackendPath {
	hostpath := hostname + path
	// add only unique paths
	backendPath := b.FindHostPath(hostpath)
	if backendPath != nil {
		return backendPath
	}
	// host's paths that references this backend
	// used on RewriteURL and Shared Session Cookie config
	backendPath = &BackendPath{
		ID:       fmt.Sprintf("path%02d", len(b.Paths)+1),
		Hostname: hostname,
		Hostpath: hostpath,
		Path:     path,
	}
	b.Paths = append(b.Paths, backendPath)
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(b.Paths, func(i, j int) bool {
		return b.Paths[i].Hostpath > b.Paths[j].Hostpath
	})
	return backendPath
}

// Hostnames ...
func (b *Backend) Hostnames() []string {
	hmap := make(map[string]struct{}, len(b.Paths))
	for _, p := range b.Paths {
		hmap[p.Hostname] = struct{}{}
	}
	hosts := make([]string, len(hmap))
	i := 0
	for host := range hmap {
		hosts[i] = host
		i++
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i] < hosts[j]
	})
	return hosts
}

// CreateConfigBool ...
func (b *Backend) CreateConfigBool(value bool) []*BackendConfigBool {
	return []*BackendConfigBool{
		{
			Paths:  NewBackendPaths(b.Paths...),
			Config: value,
		},
	}
}

// CreateConfigInt ...
func (b *Backend) CreateConfigInt(value int64) []*BackendConfigInt {
	return []*BackendConfigInt{
		{
			Paths:  NewBackendPaths(b.Paths...),
			Config: value,
		},
	}
}

// HasCorsEnabled ...
func (b *Backend) HasCorsEnabled() bool {
	for _, cors := range b.Cors {
		if cors.Config.Enabled {
			return true
		}
	}
	return false
}

// HasModsec is a method to verify if a Backend has ModSecurity Enabled
func (b *Backend) HasModsec() bool {
	for _, waf := range b.WAF {
		if waf.Config.Module == "modsecurity" {
			return true
		}
	}
	return false
}

// HasSSLRedirect ...
func (b *Backend) HasSSLRedirect() bool {
	for _, sslredirect := range b.SSLRedirect {
		if sslredirect.Config {
			return true
		}
	}
	return false
}

// HasSSLRedirectHostpath ...
func (b *Backend) HasSSLRedirectHostpath(hostpath string) bool {
	for _, sslredirect := range b.SSLRedirect {
		for _, path := range sslredirect.Paths.Items {
			if path.Hostpath == hostpath {
				return sslredirect.Config
			}
		}
	}
	return false
}

// HasSSLRedirectPaths ...
func (b *Backend) HasSSLRedirectPaths(paths *BackendPaths) bool {
	for _, path := range paths.Items {
		if b.HasSSLRedirectHostpath(path.Hostpath) {
			return true
		}
	}
	return false
}

// NeedACL ...
func (b *Backend) NeedACL() bool {
	return len(b.HSTS) > 1 ||
		len(b.MaxBodySize) > 1 || len(b.RewriteURL) > 1 || len(b.WhitelistHTTP) > 1 ||
		len(b.Cors) > 1 || len(b.AuthHTTP) > 1 || len(b.WAF) > 1
}

// IsEmpty ...
func (ep *Endpoint) IsEmpty() bool {
	return ep.IP == "127.0.0.1"
}

// IDList ...
func (p *BackendPaths) IDList() string {
	ids := make([]string, len(p.Items))
	for i, item := range p.Items {
		ids[i] = item.ID
	}
	return strings.Join(ids, " ")
}

// Add ...
func (p *BackendPaths) Add(paths ...*BackendPath) {
	for _, path := range paths {
		if path == nil {
			panic("path cannot be nil")
		}
		p.Items = append(p.Items, path)
	}
	sort.SliceStable(p.Items, func(i, j int) bool {
		return p.Items[i].Hostpath < p.Items[j].Hostpath
	})
}

// String ...
func (b *TCPBackend) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (ep *TCPEndpoint) String() string {
	return fmt.Sprintf("%+v", *ep)
}

// String ...
func (p *BackendPath) String() string {
	return fmt.Sprintf("%+v", *p)
}

// String ...
func (h *BackendHeader) String() string {
	return fmt.Sprintf("%+v", *h)
}

// String ...
func (b *BackendConfigAuth) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigBool) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigInt) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigStr) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigCors) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigHSTS) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigWhitelist) String() string {
	return fmt.Sprintf("%+v", *b)
}

// String ...
func (b *BackendConfigWAF) String() string {
	return fmt.Sprintf("%+v", *b)
}
