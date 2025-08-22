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
	"sort"
)

func CreateFrontends() *Frontends {
	return &Frontends{
		items: []*Frontend{{
			hosts:    map[string]*Host{},
			hostsAdd: map[string]*Host{},
			hostsDel: map[string]*Host{},
		}},
	}
}

func (f *Frontends) Default() *Frontend {
	return f.items[0]
}

func (f *Frontends) Commit() {
	f.items[0].Commit()
}

func (f *Frontends) FrontendsChanged() bool {
	return f.items[0].FrontendChanged()
}

func (f *Frontends) RemoveAllHosts(hostnames []string) {
	f.items[0].RemoveAllHosts(hostnames)
}

func (f *Frontends) RemoveAuthBackendByTarget(backends []string) {
	f.items[0].RemoveAuthBackendByTarget(backends)
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
	f.changed = false
}

// HasCommit ...
func (f *Frontend) HasCommit() bool {
	return f.hasCommit
}

// FrontendChanged ...
func (f *Frontend) FrontendChanged() bool {
	return f.changed
}

// HostsChanged ...
func (f *Frontend) HostsChanged() bool {
	return len(f.hostsAdd) > 0 || len(f.hostsDel) > 0
}

func (f *Frontend) createHost(hostname string) *Host {
	return &Host{
		Hostname: hostname,
		frontend: f,
		TLS: HostTLSConfig{
			// TODO revisit instance_test to allow change this default value to `false`
			UseDefaultCrt: true,
		},
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
	sort.Slice(items, func(i, j int) bool {
		return items[i].Hostname < items[j].Hostname
	})
	if len(items) == 0 {
		return nil
	}
	return items
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
		if host.TLS.CAFilename != "" {
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

func (f *Frontend) BuildHTTPResponses() (responses []HTTPResponses) {
	for _, host := range f.hosts {
		res := &host.CustomHTTPResponses
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

// AcquireAuthBackendName ...
func (f *Frontend) AcquireAuthBackendName(backend BackendID) (authBackendName string, err error) {
	proxy := &f.AuthProxy
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
	f.changed = true
	return bind.AuthBackendName, nil
}

// RemoveAuthBackendExcept ...
func (f *Frontend) RemoveAuthBackendExcept(used map[string]bool) {
	bindList := f.AuthProxy.BindList
	var i int
	for _, bind := range bindList {
		if used[bind.AuthBackendName] {
			bindList[i] = bind
			i++
		}
	}
	f.AuthProxy.BindList = bindList[:i]
}

// RemoveAuthBackendByTarget ...
func (f *Frontend) RemoveAuthBackendByTarget(backends []string) {
	bindList := f.AuthProxy.BindList
	var i int
	for _, bind := range bindList {
		if !hasBackend(backends, bind.Backend.String()) {
			bindList[i] = bind
			i++
		}
	}
	f.AuthProxy.BindList = bindList[:i]
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
