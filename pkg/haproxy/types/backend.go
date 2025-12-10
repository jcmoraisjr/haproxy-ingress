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
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// BackendID ...
func (b *Backend) BackendID() BackendID {
	// IMPLEMENT as pointer
	// TODO immutable internal state
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

// AcquireEndpoint ...
func (b *Backend) AcquireEndpoint(ip string, port int, targetRef string) *Endpoint {
	endpoint := b.FindEndpoint(fmt.Sprintf("%s:%d", ip, port))
	if endpoint != nil {
		return endpoint
	}
	return b.AddEndpoint(ip, port, targetRef)
}

// AddEmptyEndpoint ...
func (b *Backend) AddEmptyEndpoint() *Endpoint {
	endpoint := b.AddEndpoint("127.0.0.1", 1023, "")
	endpoint.Enabled = false
	// we need to set the cookie value to something here so that when dynamic
	// update enables these endpoints without a reload, they will use cookie
	// affinity (if it's enabled). This happens when session-cookie-preserve
	// is false.
	endpoint.CookieValue = endpoint.Name
	return endpoint
}

func (b *Backend) AddEndpoint(ip string, port int, targetRef string) *Endpoint {
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
	endpoint := &Endpoint{
		Name:      b.sanitizeName(name, 1),
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

func (b *Backend) sanitizeName(name string, idx int) string {
	if name == "" {
		return fmt.Sprintf("srv%03d", len(b.Endpoints)+1)
	}
	sname := name
	if idx > 1 {
		sname = fmt.Sprintf("%s__%d", name, idx)
	}
	for _, ep := range b.Endpoints {
		if ep.Name == sname {
			return b.sanitizeName(name, idx+1)
		}
	}
	return sname
}

func (b *Backend) fillSourceIPs() {
	l := len(b.SourceIPs)
	if l > 0 {
		i := int(b.hash64 % uint64(l))
		for _, ep := range b.Endpoints {
			ep.SourceIP = b.SourceIPs[i].String()
			i = (i + 1) % l
		}
	}
}

func (b *Backend) sortEndpoints(sortBy string) {
	ep := b.Endpoints
	switch sortBy {
	// ignoring "ep"/"endpoint" (use the k8s order) and "random" (shuffleEndpoints implements)
	case "name":
		sort.Slice(ep, func(i, j int) bool {
			return ep[i].Name < ep[j].Name
		})
	case "ip":
		sort.Slice(ep, func(i, j int) bool {
			return ep[i].IP < ep[j].IP
		})
	}
}

func (b *Backend) shuffleEndpoints() {
	ep := b.Endpoints
	rand.Shuffle(len(ep), func(i, j int) {
		ep[i], ep[j] = ep[j], ep[i]
	})
}

// CookieAffinity ...
func (b *Backend) CookieAffinity() bool {
	return !b.ModeTCP && b.Cookie.Name != "" && !b.Cookie.Dynamic
}

func (b *Backend) AddPath(path *Path) {
	path.ID = fmt.Sprintf("path%02d", len(b.Paths)+1)
	b.Paths = append(b.Paths, path)
	sortPaths(b.Paths, false)
}

// Hostnames ...
func (b *Backend) Hostnames() []string {
	hmap := make(map[string]struct{}, len(b.Paths))
	for _, p := range b.Paths {
		hmap[p.Link.hostname] = struct{}{}
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

func sortPaths(paths []*Path, pathReverse bool) {
	// Ascending order of frontend+hostnames and reverse order (if pathReverse) of paths within the same hostname
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(paths, func(i, j int) bool {
		l1 := paths[i].Link
		l2 := paths[j].Link
		if l1.frontend == l2.frontend {
			if l1.hostname == l2.hostname {
				if pathReverse {
					return l1.path > l2.path
				}
				return l1.path < l2.path
			}
			return l1.hostname < l2.hostname
		}
		return l1.frontend < l2.frontend
	})
}

// HasCorsEnabled ...
func (b *Backend) HasCorsEnabled() bool {
	for _, path := range b.Paths {
		if path.Cors.Enabled {
			return true
		}
	}
	return false
}

// HasHSTS ...
func (b *Backend) HasHSTS() bool {
	for _, path := range b.Paths {
		if path.HSTS.Enabled {
			return true
		}
	}
	return false
}

// HasModsec is a method to verify if a Backend has ModSecurity Enabled
func (b *Backend) HasModsec() bool {
	for _, path := range b.Paths {
		if path.WAF.Module == "modsecurity" {
			return true
		}
	}
	return false
}

func (b *Backend) HasHTTPRequests() bool {
	for _, path := range b.Paths {
		if !path.Host.Frontend.IsHTTPS {
			return true
		}
	}
	return false
}

// HasSSLRedirect ...
func (b *Backend) HasSSLRedirect() bool {
	for _, path := range b.Paths {
		if path.SSLRedirect {
			return true
		}
	}
	return false
}

// HasSSLRedirectPaths ...
func (b *Backend) HasSSLRedirectPaths(paths []*Path) bool {
	for _, path := range paths {
		if path.SSLRedirect {
			return true
		}
	}
	return false
}

func (b *Backend) HasTLSAuth() bool {
	for _, path := range b.Paths {
		if path.Host.HasTLSAuth() {
			return true
		}
	}
	return false
}

type Has int

// these same consts are also used in haproxy.tmpl, change there if changing here.
const (
	HasNone Has = iota
	HasSome
	HasOnly
)

func (b *Backend) HasHTTPPassthrough() Has {
	return b.hasInPath(func(path *Path) bool { return path.Host.Frontend.HTTPPassthrough })
}

func (b *Backend) HasHTTPPassUseProto() Has {
	return b.hasInPath(func(path *Path) bool { return path.Host.Frontend.HTTPPassUseProto })
}

func (b *Backend) hasInPath(has func(path *Path) bool) Has {
	var count int
	for i, path := range b.Paths {
		if has(path) {
			count++
		}
		if i > 0 && count > 0 && i >= count {
			return HasSome
		}
	}
	if count == 0 {
		return HasNone
	}
	return HasOnly
}

func (b *Backend) PathConfigs() map[string]*BackendPathConfig {
	if b.pathsConfigs == nil {
		b.pathsConfigs = b.createPathConfig()
	}
	return b.pathsConfigs
}

// PathConfig ...
func (b *Backend) PathConfig(attr string) *BackendPathConfig {
	if _, found := b.PathConfigs()[attr]; !found {
		panic(fmt.Errorf("field does not exist: %s", attr))
	}
	return b.pathsConfigs[attr]
}

// NeedACL ...
func (b *Backend) NeedACL() bool {
	for _, path := range b.PathConfigs() {
		if path.NeedACL() {
			return true
		}
	}
	return false
}

func (b *Backend) NeedFrontendACL() bool {
	return len(b.PathsMaps()) > 1
}

func (b *Backend) PathsMaps() []*BackendPathsMaps {
	if b.pathsMaps == nil {
		b.pathsMaps = b.createPathsMaps()
	}
	return b.pathsMaps
}

func (b *Backend) createPathsMaps() []*BackendPathsMaps {
	var pathsMaps []*BackendPathsMaps
	for _, path := range b.Paths {
		frontendName := path.Host.Frontend.Name
		i := slices.IndexFunc(pathsMaps, func(b *BackendPathsMaps) bool { return slices.Contains(b.Frontends, frontendName) })
		if i < 0 {
			i = len(pathsMaps)
			pathsMaps = append(pathsMaps, &BackendPathsMaps{
				Frontends: []string{frontendName},
			})
		}
		backMap := pathsMaps[i]
		backMap.Paths = append(backMap.Paths, path)
	}
	// Deduplicate maps with the exact same paths, a common pattern on models configured via Ingress API.
	// This deduplication reduces the size of the backend configuration.
	pathsMaps = slices.CompactFunc(pathsMaps, func(m1, m2 *BackendPathsMaps) bool {
		if slices.EqualFunc(m1.Paths, m2.Paths, func(p1, p2 *Path) bool { return p1.Equals(p2) }) {
			m2.Frontends = append(m2.Frontends, m1.Frontends...)
			return true
		}
		return false
	})
	sort.Slice(pathsMaps, func(i, j int) bool {
		return pathsMaps[i].Frontends[0] < pathsMaps[j].Frontends[0]
	})
	return pathsMaps
}

func (b *Backend) createPathConfig() map[string]*BackendPathConfig {
	pathconfig := make(map[string]*BackendPathConfig, len(b.Paths))
	pathType := reflect.TypeOf(Path{})
	for i := range pathType.NumField() {
		field := pathType.Field(i)
		if field.Tag.Get("class") != "core" {
			pathconfig[field.Name] = &BackendPathConfig{}
		}
	}
	for _, pathsMap := range b.PathsMaps() {
		for _, path := range pathsMap.Paths {
			pathValue := reflect.ValueOf(*path)
			for name, config := range pathconfig {
				newconfig := pathValue.FieldByName(name).Interface()
				hasconfig := false
				for _, item := range config.items {
					if reflect.DeepEqual(item.config, newconfig) {
						item.paths = append(item.paths, path)
						hasconfig = true
						break
					}
				}
				if !hasconfig {
					config.items = append(config.items, &BackendPathItem{
						paths:  []*Path{path},
						config: newconfig,
					})
				}
			}
		}
	}
	return pathconfig
}

// NeedACL ...
func (b *BackendPathConfig) NeedACL() bool {
	return len(b.items) > 1
}

// Items ...
func (b *BackendPathConfig) Items() []interface{} {
	items := make([]interface{}, len(b.items))
	for i, item := range b.items {
		items[i] = item.config
	}
	return items
}

// Paths ...
func (b *BackendPathConfig) Paths(index int) []*Path {
	return b.items[index].paths
}

// PathIDs ...
func (b *BackendPathConfig) PathIDs(index int) []string {
	// slice of one item in order to iterate once and output the haproxy's keyword.
	// template has `{{ if $pathIDs }}`, so empty string means to not build the ACL.
	if !b.NeedACL() {
		return []string{""}
	}
	paths := b.items[index].paths
	if len(paths) == 0 {
		return nil
	}
	ids := make([]string, len(paths))
	for i, path := range paths {
		ids[i] = path.ID
	}

	// pathIDs array is split into smaller chains of IDs to avoid "line too long"
	// from haproxy. A `maxTokensPerLine` as 30 will add at most 30 new words in
	// a single line whose limit is 64, and up to 2048 chars in length. Each ID
	// "path0000 " uses at most 9 chars, multiplied by 30 means 270 chars in the
	// whole line.
	//
	//   https://github.com/haproxy/haproxy/blob/v2.2.0/include/haproxy/defaults.h#L99
	//   https://github.com/haproxy/haproxy/blob/v2.2.0/include/haproxy/defaults.h#L104
	//
	// 30 is fair enough.
	maxTokensPerLine := 30

	sort.Strings(ids)
	pathIDs := make([]string, (len(ids)-1)/maxTokensPerLine+1)
	lower := 0
	for i := range pathIDs {
		upper := lower + maxTokensPerLine
		if upper > len(ids) {
			upper = len(ids)
		}
		pathIDs[i] = strings.Join(ids[lower:upper], " ")
		lower = lower + maxTokensPerLine
	}
	return pathIDs
}

// IsEmpty ...
func (ep *Endpoint) IsEmpty() bool {
	return ep.IP == "127.0.0.1"
}

func (p *Path) Equals(other *Path) bool {
	vthis := reflect.ValueOf(*p)
	vother := reflect.ValueOf(*other)
	pathType := reflect.TypeOf(Path{})
	for i := range pathType.NumField() {
		if pathType.Field(i).Tag.Get("class") == "core" {
			continue
		}
		if !reflect.DeepEqual(vthis.Field(i).Interface(), vother.Field(i).Interface()) {
			return false
		}
	}
	return true
}

// Hostname ...
func (p *Path) Hostname() string {
	return p.Link.hostname
}

// IsDefaultHost ...
func (p *Path) IsDefaultHost() bool {
	return p.Link.IsDefaultHost()
}

// Path ...
func (p *Path) Path() string {
	return p.Link.path
}

// Match ...
func (p *Path) Match() MatchType {
	return p.Link.match
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
func (p *Path) String() string {
	return fmt.Sprintf("%+v", *p)
}

// String ...
func (h *BackendHeader) String() string {
	return fmt.Sprintf("%+v", *h)
}
