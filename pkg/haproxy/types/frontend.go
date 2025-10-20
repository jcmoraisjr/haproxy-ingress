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
	"reflect"
	"slices"
	"sort"
)

func (f *Frontends) AcquireFrontend(port int32, isHTTPS bool) *Frontend {
	var has bool
	for _, frontend := range f.items {
		if frontend.port == port {
			return frontend
		}
		if !has && frontend.IsHTTPS == isHTTPS {
			has = true
		}
	}
	var name string
	if isHTTPS {
		name = "_front_https"
	} else {
		name = "_front_http"
	}
	if has {
		name = fmt.Sprintf("%s_%d", name, port)
	}
	frontend := &Frontend{
		Name:     name,
		Bind:     fmt.Sprintf(":%d", port),
		IsHTTPS:  isHTTPS,
		port:     port,
		hosts:    map[string]*Host{},
		hostsAdd: map[string]*Host{},
		hostsDel: map[string]*Host{},
	}
	f.items = append(f.items, frontend)
	return frontend
}

func (f *Frontends) FindFrontend(port int32) *Frontend {
	for _, frontend := range f.items {
		if frontend.port == port {
			return frontend
		}
	}
	return nil
}

func (f *Frontends) Items() []*Frontend {
	return f.items
}

func (f *Frontends) Commit() {
	for _, frontend := range f.items {
		frontend.Commit()
	}
	f.items = slices.DeleteFunc(f.items, func(f *Frontend) bool { return len(f.hosts) == 0 })
	f.AuthProxy.changed = false
}

func (f *Frontends) HasCommit() bool {
	for _, frontend := range f.items {
		if frontend.HasCommit() {
			return true
		}
	}
	return false
}

func (f *Frontends) Changed() bool {
	return f.AuthProxy.changed
}

func (f *Frontends) HasHTTPResponses() bool {
	for _, f := range f.items {
		for _, host := range f.hosts {
			res := &host.CustomHTTPResponses
			if len(res.HAProxy) > 0 || len(res.Lua) > 0 {
				return true
			}
		}
	}
	return false
}

func (f *Frontends) HasSomeFrontingProxy() bool {
	total := len(f.items)
	var count int
	for _, front := range f.items {
		if front.IsFrontingProxy {
			count++
		}
	}
	return count > 0 && count < total
}

func (f *Frontends) HasSomeFrontingUseProto() bool {
	total := len(f.items)
	var count int
	for _, front := range f.items {
		if front.IsFrontingProxy && front.IsFrontingUseProto {
			count++
		}
	}
	return count > 0 && count < total
}

func (f *Frontends) BuildHTTPResponses() (responses []HTTPResponses) {
	for _, f := range f.items {
		for _, host := range f.hosts {
			res := &host.CustomHTTPResponses
			res.ID = fmt.Sprintf("%s--%s", f.Name, host.Hostname)
			if len(res.HAProxy) > 0 || len(res.Lua) > 0 {
				responses = append(responses, HTTPResponses{
					ID:      res.ID,
					HAProxy: res.HAProxy,
					Lua:     res.Lua,
				})
			}
		}
	}
	// predictable response
	sort.Slice(responses, func(i, j int) bool {
		return responses[i].ID < responses[j].ID
	})
	return responses
}

func (f *Frontends) RemoveAllHosts(hostnames []string) {
	for _, frontend := range f.items {
		frontend.RemoveAllHosts(hostnames)
	}
}

func (f *Frontends) Shrink() {
	for _, frontend := range f.items {
		frontend.ShrinkHosts()
	}
}

// AcquireHost ...
func (f *Frontend) AcquireHost(hostname string) *Host {
	if host := f.FindHost(hostname); host != nil {
		return host
	}
	host := f.createHost(hostname)
	f.hosts[hostname] = host
	f.hostsAdd[hostname] = host
	return host
}

// FindHost ...
func (f *Frontend) FindHost(hostname string) *Host {
	return f.hosts[hostname]
}

// RemoveAllHosts ...
func (f *Frontend) RemoveAllHosts(hostnames []string) {
	for _, hostname := range hostnames {
		if item, found := f.hosts[hostname]; found {
			f.hostsDel[hostname] = item
			delete(f.hosts, hostname)
		}
	}
}

func (f *Frontend) RemoveAllLinks(pathlinks ...*PathLink) {
	for _, link := range pathlinks {
		h := f.FindHost(link.hostname)
		if h != nil {
			h.Paths = slices.DeleteFunc(h.Paths, func(p *Path) bool { return p.Link.Equals(link) })
			if len(h.Paths) == 0 {
				f.RemoveAllHosts([]string{link.hostname})
			}
		}
	}
}

// FindTargetRedirect ...
func (f *Frontend) FindTargetRedirect(redirfrom string, isRegex bool) *Host {
	if redirfrom == "" {
		return nil
	}
	// TODO this'd be somewhat expensive on full parsing,
	// tens of thousands of ingress and most of them using redirect
	if isRegex {
		for _, host := range f.hosts {
			if host.Redirect.RedirectHostRegex == redirfrom {
				return host
			}
		}
		return nil
	}
	for _, host := range f.hosts {
		if host.Redirect.RedirectHost == redirfrom {
			return host
		}
	}
	return nil
}

// ShrinkHosts removes matching added and deleted hosts from the changing hashmap
// tracker that has the same content. A matching added+deleted pair means
// that a hostname was reparsed but its content wasn't changed.
func (f *Frontend) ShrinkHosts() {
	for name, del := range f.hostsDel {
		if add, found := f.hostsAdd[name]; found {
			if reflect.DeepEqual(add, del) {
				f.hosts[name] = del
				delete(f.hostsAdd, name)
				delete(f.hostsDel, name)
			}
		}
	}
}

// Commit ...
func (f *Frontend) Commit() {
	f.hostsAdd = map[string]*Host{}
	f.hostsDel = map[string]*Host{}
	f.hasCommit = true
}

// HasCommit ...
func (f *Frontend) HasCommit() bool {
	return f.hasCommit
}

// HostsChanged ...
func (f *Frontend) HostsChanged() bool {
	return len(f.hostsAdd) > 0 || len(f.hostsDel) > 0
}

func (f *Frontend) createHost(hostname string) *Host {
	return &Host{
		Hostname: hostname,
		frontend: f,
	}
}

// BuildSortedHosts ...
func (f *Frontend) BuildSortedHosts() []*Host {
	items := make([]*Host, len(f.hosts))
	var i int
	for hostname, item := range f.hosts {
		if hostname != DefaultHost {
			items[i] = item
			i++
		}
	}
	items = items[:i]
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Hostname < items[j].Hostname
	})
	return items
}

func (f *Frontend) Port() int32 {
	return f.port
}

// Hosts ...
func (f *Frontend) Hosts() map[string]*Host {
	return f.hosts
}

// HostsAdd ...
func (f *Frontend) HostsAdd() map[string]*Host {
	return f.hostsAdd
}

// HostsDel ...
func (f *Frontend) HostsDel() map[string]*Host {
	return f.hostsDel
}

// DefaultHost ...
func (f *Frontend) DefaultHost() *Host {
	return f.hosts[DefaultHost]
}

// HasTLSAuth ...
func (f *Frontend) HasTLSAuth() bool {
	for _, host := range f.hosts {
		if host.HasTLSAuth() {
			return true
		}
	}
	return false
}

// HasSSLPassthrough ...
func (f *Frontend) HasSSLPassthrough() bool {
	for _, host := range f.hosts {
		if host.SSLPassthrough {
			return true
		}
	}
	return false
}

// HasVarNamespace ...
func (f *Frontend) HasVarNamespace() bool {
	for _, host := range f.hosts {
		if host.VarNamespace {
			return true
		}
	}
	return false
}

// AcquireAuthBackendName ...
func (proxy *AuthProxy) AcquireAuthBackendName(backend BackendID) (authBackendName string, err error) {
	freePort := proxy.RangeStart
	for _, bind := range proxy.BindList {
		if bind.Backend == backend {
			return bind.AuthBackendName, nil
		}
		if freePort == bind.LocalPort {
			freePort++
		}
	}
	if freePort > proxy.RangeEnd {
		return "", fmt.Errorf("auth proxy list is full")
	}
	socketID := 10000 + freePort
	bind := &AuthProxyBind{
		AuthBackendName: fmt.Sprintf("_auth_%d", freePort),
		Backend:         backend,
		LocalPort:       freePort,
		SocketID:        socketID,
	}
	proxy.BindList = append(proxy.BindList, bind)
	sort.Slice(proxy.BindList, func(i, j int) bool {
		return proxy.BindList[i].LocalPort < proxy.BindList[j].LocalPort
	})
	proxy.changed = true
	return bind.AuthBackendName, nil
}

// RemoveAuthBackendExcept ...
func (proxy *AuthProxy) RemoveAuthBackendExcept(used map[string]bool) {
	bindList := proxy.BindList
	var i int
	for _, bind := range bindList {
		if used[bind.AuthBackendName] {
			bindList[i] = bind
			i++
		}
	}
	proxy.BindList = bindList[:i]
}

// RemoveAuthBackendByTarget ...
func (proxy *AuthProxy) RemoveAuthBackendByTarget(backends []string) {
	bindList := proxy.BindList
	var i int
	for _, bind := range bindList {
		if !hasBackend(backends, bind.Backend.String()) {
			bindList[i] = bind
			i++
		}
	}
	proxy.BindList = bindList[:i]
}

func hasBackend(backends []string, backend string) bool {
	for _, back := range backends {
		if back == backend {
			return true
		}
	}
	return false
}

// String ...
func (f *Frontend) String() string {
	return fmt.Sprintf("%+v", *f)
}
