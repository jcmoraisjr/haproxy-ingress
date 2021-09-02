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
)

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

// Changed ...
func (f *Frontend) Changed() bool {
	return f.changed
}

// Commit ...
func (f *Frontend) Commit() {
	f.changed = false
}

// String ...
func (f *Frontend) String() string {
	return fmt.Sprintf("%+v", *f)
}
