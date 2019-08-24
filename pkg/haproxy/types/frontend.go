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
	"strings"
)

// AppendHostname ...
func (hm *HostsMap) AppendHostname(base, value string) {
	// always use case insensitive match
	base = strings.ToLower(base)
	isHostnameOnly := !strings.Contains(base, "/")
	if strings.HasPrefix(base, "*.") {
		// *.example.local
		key := "^" + strings.Replace(base, ".", "\\.", -1)
		key = strings.Replace(key, "*", "[^.]+", 1)
		if isHostnameOnly {
			// match eol if only the hostname is provided
			// if has /path, need to match the begining of the string, a la map_beg() converter
			key = key + "$"
		}
		hm.Regex = append(hm.Regex, &HostsMapEntry{
			Key:   key,
			Value: value,
		})
	} else {
		// sub.example.local
		hm.Match = append(hm.Match, &HostsMapEntry{
			Key:   base,
			Value: value,
		})
		// Hostnames are already in alphabetical order but Alias are not
		// Sort only hostname maps which uses ebtree search via map converter
		if isHostnameOnly {
			sort.Slice(hm.Match, func(i, j int) bool {
				return hm.Match[i].Key < hm.Match[j].Key
			})
		}
	}
}

// AppendAliasName ...
func (hm *HostsMap) AppendAliasName(base, value string) {
	if base != "" {
		hm.AppendHostname(base, value)
	}
}

// AppendAliasRegex ...
func (hm *HostsMap) AppendAliasRegex(base, value string) {
	if base != "" {
		hm.Regex = append(hm.Regex, &HostsMapEntry{
			Key:   base,
			Value: value,
		})
	}
}

// AppendPath ...
func (hm *HostsMap) AppendPath(path, id string) {
	hm.Match = append(hm.Match, &HostsMapEntry{
		Key:   path,
		Value: id,
	})
	sort.SliceStable(hm.Match, func(i, j int) bool {
		return hm.Match[i].Key > hm.Match[j].Key
	})
}

// HasRegex ...
func (hm *HostsMap) HasRegex() bool {
	return len(hm.Regex) > 0
}

// HasHost ...
func (hm *HostsMap) HasHost() bool {
	return len(hm.Regex) > 0 || len(hm.Match) > 0
}

// CreateMaps ...
func CreateMaps() *HostsMaps {
	return &HostsMaps{}
}

// AddMap ...
func (hm *HostsMaps) AddMap(filename string) *HostsMap {
	matchFile := filename
	regexFile := strings.Replace(filename, ".", "_regex.", 1)
	hmap := &HostsMap{
		MatchFile: matchFile,
		RegexFile: regexFile,
	}
	hm.Items = append(hm.Items, hmap)
	return hmap
}

// HasTCPProxy ...
func (fg *FrontendGroup) HasTCPProxy() bool {
	// short-circuit saves:
	// len(fg.Frontend) may be zero only if fg.HasSSLPassthrough is true
	return fg.HasSSLPassthrough || len(fg.Frontends) > 1 || len(fg.Frontends[0].Binds) > 1
}

// String ...
func (f *Frontend) String() string {
	return fmt.Sprintf("%+v", *f)
}

// HasTLSAuth ...
func (f *Frontend) HasTLSAuth() bool {
	for _, host := range f.Hosts {
		if host.HasTLSAuth() {
			return true
		}
	}
	return false
}

// HasInvalidErrorPage ...
func (f *Frontend) HasInvalidErrorPage() bool {
	for _, host := range f.Hosts {
		if host.TLS.CAErrorPage != "" {
			return true
		}
	}
	return false
}

// HasNoCrtErrorPage ...
func (f *Frontend) HasNoCrtErrorPage() bool {
	// Use currently the same attribute
	return f.HasInvalidErrorPage()
}

// HasTLSMandatory ...
func (f *Frontend) HasTLSMandatory() bool {
	for _, host := range f.Hosts {
		if host.HasTLSAuth() && !host.TLS.CAVerifyOptional {
			return true
		}
	}
	return false
}

// HasVarNamespace ...
func (f *Frontend) HasVarNamespace() bool {
	for _, host := range f.Hosts {
		if host.VarNamespace {
			return true
		}
	}
	return false
}

// HasMaxBody ...
func (f *Frontend) HasMaxBody() bool {
	return f.MaxBodySizeMap.HasHost()
}

// BuildRawFrontends ...
func BuildRawFrontends(hosts []*Host) (frontends []*Frontend, sslpassthrough []*Host, defaultBind *BindConfig) {
	if len(hosts) == 0 {
		return nil, nil, nil
	}
	// creating frontends and ssl-passthrough hosts
	for _, host := range hosts {
		if host.SSLPassthrough {
			// ssl-passthrough does not use a frontend
			sslpassthrough = append(sslpassthrough, host)
			continue
		}
		frontend := findMatchingFrontend(frontends, host)
		if frontend == nil {
			frontend = newFrontend(host)
			frontends = append(frontends, frontend)
		}
		frontend.Hosts = append(frontend.Hosts, host)
	}
	// creating binds
	for _, frontend := range frontends {
		var binds []*BindConfig
		for _, host := range frontend.Hosts {
			bind := findMatchingBind(binds, host)
			if bind == nil {
				bind = newFrontendBind(host)
				binds = append(binds, bind)
			}
			if defaultBind == nil && bind.supportDefault() {
				defaultBind = bind
			}
			bind.Hosts = append(bind.Hosts, host)
		}
		frontend.Binds = binds
	}
	// configuring the default bind
	if defaultBind == nil {
		var frontend *Frontend
		if len(frontends) == 0 {
			frontend = newFrontend(nil)
			frontends = append(frontends, frontend)
		} else {
			frontend = frontends[0]
		}
		defaultBind = newFrontendBind(nil)
		frontend.Binds = append(frontend.Binds, defaultBind)
	}
	// naming frontends
	var i int
	for _, frontend := range frontends {
		i++
		frontend.Name = fmt.Sprintf("_front%03d", i)
	}
	// sorting frontends
	sort.Slice(frontends, func(i, j int) bool {
		return frontends[i].Name < frontends[j].Name
	})
	return frontends, sslpassthrough, defaultBind
}

func findMatchingFrontend(frontends []*Frontend, host *Host) *Frontend {
	for _, frontend := range frontends {
		if frontend.match(host) {
			return frontend
		}
	}
	return nil
}

func findMatchingBind(binds []*BindConfig, host *Host) *BindConfig {
	for _, bind := range binds {
		if bind.match(host) {
			return bind
		}
	}
	return nil
}

// newFrontend and Frontend.Match should always sinchronize its attributes
func newFrontend(host *Host) *Frontend {
	if host == nil {
		return &Frontend{}
	}
	return &Frontend{
		Timeout: host.Timeout,
	}
}

// newFrontendBind and BindConfig.Match should always sinchronize its attributes
func newFrontendBind(host *Host) *BindConfig {
	if host == nil {
		return &BindConfig{}
	}
	return &BindConfig{
		TLS: BindTLSConfig{
			CAFilename: host.TLS.CAFilename,
			CAHash:     host.TLS.CAHash,
		},
	}
}

func (f *Frontend) match(host *Host) bool {
	if len(f.Hosts) == 0 {
		return true
	}
	return reflect.DeepEqual(f.Timeout, host.Timeout)
}

func (b *BindConfig) match(host *Host) bool {
	return b.TLS.CAHash == host.TLS.CAHash
}

func (b *BindConfig) supportDefault() bool {
	return b.TLS.CAHash == ""
}
