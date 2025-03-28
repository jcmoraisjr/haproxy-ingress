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
)

// CreateHosts ...
func CreateHosts() *Hosts {
	return &Hosts{
		items:    map[string]*Host{},
		itemsAdd: map[string]*Host{},
		itemsDel: map[string]*Host{},
	}
}

// CreatePathLink ...
func CreatePathLink(path string, match MatchType) *PathLink {
	return CreateHostPathLink("", path, match)
}

// CreateHostPathLink ...
func CreateHostPathLink(hostname, path string, match MatchType) *PathLink {
	pathlink := &PathLink{
		hostname: hostname,
		path:     path,
		match:    match,
	}
	pathlink.updatehash()
	return pathlink
}

// AcquireHost ...
func (h *Hosts) AcquireHost(hostname string) *Host {
	if host := h.FindHost(hostname); host != nil {
		return host
	}
	host := h.createHost(hostname)
	h.items[hostname] = host
	h.itemsAdd[hostname] = host
	return host
}

// FindHost ...
func (h *Hosts) FindHost(hostname string) *Host {
	return h.items[hostname]
}

// RemoveAll ...
func (h *Hosts) RemoveAll(hostnames []string) {
	for _, hostname := range hostnames {
		if item, found := h.items[hostname]; found {
			h.releaseHost(item)
			h.itemsDel[hostname] = item
			delete(h.items, hostname)
		}
	}
}

// FindTargetRedirect ...
func (h *Hosts) FindTargetRedirect(redirfrom string, isRegex bool) *Host {
	if redirfrom == "" {
		return nil
	}
	// TODO this'd be somewhat expensive on full parsing,
	// tens of thousands of ingress and most of them using redirect
	if isRegex {
		for _, host := range h.items {
			if host.Redirect.RedirectHostRegex == redirfrom {
				return host
			}
		}
		return nil
	}
	for _, host := range h.items {
		if host.Redirect.RedirectHost == redirfrom {
			return host
		}
	}
	return nil
}

// Shrink removes matching added and deleted hosts from the changing hashmap
// tracker that has the same content. A matching added+deleted pair means
// that a hostname was reparsed but its content wasn't changed.
func (h *Hosts) Shrink() {
	for name, del := range h.itemsDel {
		if add, found := h.itemsAdd[name]; found {
			if reflect.DeepEqual(add, del) {
				h.items[name] = del
				delete(h.itemsAdd, name)
				delete(h.itemsDel, name)
			}
		}
	}
}

// Commit ...
func (h *Hosts) Commit() {
	h.itemsAdd = map[string]*Host{}
	h.itemsDel = map[string]*Host{}
	h.hasCommit = true
}

// HasCommit ...
func (h *Hosts) HasCommit() bool {
	return h.hasCommit
}

// Changed ...
func (h *Hosts) Changed() bool {
	return len(h.itemsAdd) > 0 || len(h.itemsDel) > 0
}

func (h *Hosts) createHost(hostname string) *Host {
	return &Host{
		Hostname: hostname,
		hosts:    h,
		TLS: HostTLSConfig{
			// TODO revisit instance_test to allow change this default value to `false`
			UseDefaultCrt: true,
		},
	}
}

// BuildSortedItems ...
func (h *Hosts) BuildSortedItems() []*Host {
	items := make([]*Host, len(h.items))
	var i int
	for hostname, item := range h.items {
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

// Items ...
func (h *Hosts) Items() map[string]*Host {
	return h.items
}

// ItemsAdd ...
func (h *Hosts) ItemsAdd() map[string]*Host {
	return h.itemsAdd
}

// ItemsDel ...
func (h *Hosts) ItemsDel() map[string]*Host {
	return h.itemsDel
}

// DefaultHost ...
func (h *Hosts) DefaultHost() *Host {
	return h.items[DefaultHost]
}

// releaseHost does a reverse update on the Hosts state
// due to the removal of a Host item
func (h *Hosts) releaseHost(host *Host) {
	if host.sslPassthrough {
		h.sslPassthroughCount--
	}
}

// HasTLSAuth ...
func (h *Hosts) HasTLSAuth() bool {
	for _, host := range h.items {
		if host.TLS.CAFilename != "" {
			return true
		}
	}
	return false
}

// HasSSLPassthrough ...
func (h *Hosts) HasSSLPassthrough() bool {
	return h.sslPassthroughCount > 0
}

// HasVarNamespace ...
func (h *Hosts) HasVarNamespace() bool {
	for _, host := range h.items {
		if host.VarNamespace {
			return true
		}
	}
	return false
}

// FindPath ...
func (h *Host) FindPath(path string, match ...MatchType) (paths []*HostPath) {
	for _, p := range h.Paths {
		if p.Link.path == path && p.Link.headers == nil && p.hasMatch(match) {
			paths = append(paths, p)
		}
	}
	return paths
}

// FindPathWithLink ...
func (h *Host) FindPathWithLink(link *PathLink) (path *HostPath) {
	for _, p := range h.Paths {
		if p.Link.Equals(link) {
			return p
		}
	}
	return nil
}

// AddPath ...
func (h *Host) AddPath(backend *Backend, path string, match MatchType) *HostPath {
	return h.addPath(path, match, backend, "")
}

// AddLink ...
func (h *Host) AddLink(backend *Backend, link *PathLink) *PathLink {
	newlink := *link
	newlink.WithHostname(h.Hostname)
	_ = h.addLink(backend, &newlink, "")
	return &newlink
}

// AddLinkRedirect ...
func (h *Host) AddLinkRedirect(link *PathLink, redirTo string) *PathLink {
	newlink := *link
	newlink.WithHostname(h.Hostname)
	_ = h.addLink(nil, &newlink, redirTo)
	return &newlink
}

// AddRedirect ...
func (h *Host) AddRedirect(path string, match MatchType, redirTo string) {
	_ = h.addPath(path, match, nil, redirTo)
}

type hostResolver struct {
	useDefaultCrt  *bool
	followRedirect *bool
	crtFilename    *string
}

func (h *Host) addPath(path string, match MatchType, backend *Backend, redirTo string) *HostPath {
	link := CreateHostPathLink(h.Hostname, path, match)
	return h.addLink(backend, link, redirTo)
}

func (h *Host) addLink(backend *Backend, link *PathLink, redirTo string) *HostPath {
	var hback HostBackend
	if backend != nil {
		hback = HostBackend{
			ID:        backend.ID,
			Namespace: backend.Namespace,
			Name:      backend.Name,
			Port:      backend.Port,
		}
		bpath := backend.AddBackendPath(link)
		bpath.Host = &hostResolver{
			useDefaultCrt:  &h.TLS.UseDefaultCrt,
			followRedirect: &h.TLS.FollowRedirect,
			crtFilename:    &h.TLS.TLSFilename,
		}
	} else if redirTo == "" {
		hback = HostBackend{ID: "_error404"}
	}
	path := &HostPath{
		Link:    link,
		Backend: hback,
		RedirTo: redirTo,
		order:   len(h.Paths),
	}
	h.Paths = append(h.Paths, path)
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(h.Paths, func(i, j int) bool {
		p1 := h.Paths[i]
		p2 := h.Paths[j]
		if p1.Link.path == p2.Link.path {
			return p1.order < p2.order
		}
		return p1.Link.path > p2.Link.path
	})
	return path
}

// RemovePath ...
func (h *Host) RemovePath(hpath *HostPath) {
	var j int
	for i := range h.Paths {
		if j < i {
			h.Paths[j] = h.Paths[i]
		}
		if h.Paths[i] != hpath {
			j++
		}
	}
	if j < len(h.Paths) {
		h.Paths = h.Paths[:j]
	}
}

// HasTLS ...
func (h *Host) HasTLS() bool {
	return h.TLS.UseDefaultCrt || h.TLS.TLSHash != ""
}

func (h *hostResolver) UseTLS() bool {
	// whether the ingress resource has the `tls:` entry for the host
	hasTLSEntry := *h.crtFilename != ""

	// whether the user has globally or locally configured auto TLS for the host
	autoTLSEnabled := *h.useDefaultCrt && *h.followRedirect

	return hasTLSEntry || autoTLSEnabled
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

// Path ...
func (h *HostPath) Path() string {
	return h.Link.path
}

// Headers ...
func (h *HostPath) Headers() HTTPHeaderMatch {
	return h.Link.headers
}

// Match ...
func (h *HostPath) Match() MatchType {
	return h.Link.match
}

func (h *HostPath) hasMatch(match []MatchType) bool {
	if len(match) == 0 {
		return true
	}
	for _, m := range match {
		if h.Link.match == m {
			return true
		}
	}
	return false
}

func (l *PathLink) updatehash() {
	hash := l.hostname + "\n" + l.path + "\n" + string(l.match)
	for _, h := range l.headers {
		hash += "\n" + "h:" + h.Name + ":" + h.Value
		if h.Regex {
			hash += "(regex)"
		}
	}
	l.hash = PathLinkHash(hash)
}

// Hash ...
func (l *PathLink) Hash() PathLinkHash {
	return l.hash
}

// Equals ...
func (l *PathLink) Equals(other *PathLink) bool {
	if l == nil || other == nil {
		return l == other
	}
	return l.hash == other.hash
}

// ComposeMatch returns true if the pathLink has composing match,
// by adding method, header or cookie match.
func (l *PathLink) ComposeMatch() bool {
	return len(l.headers) > 0
}

// WithHostname ...
func (l *PathLink) WithHostname(hostname string) *PathLink {
	l.hostname = hostname
	l.updatehash()
	return l
}

// WithHeadersMatch ...
func (l *PathLink) WithHeadersMatch(headers HTTPHeaderMatch) *PathLink {
	l.headers = headers
	l.updatehash()
	return l
}

// AddHeadersMatch ...
func (l *PathLink) AddHeadersMatch(headers HTTPHeaderMatch) *PathLink {
	l.headers = append(l.headers, headers...)
	l.updatehash()
	return l
}

// Hostname ...
func (l *PathLink) Hostname() string {
	return l.hostname
}

// IsEmpty ...
func (l *PathLink) IsEmpty() bool {
	return l.hostname == "" && l.path == ""
}

// IsDefaultHost ...
func (l *PathLink) IsDefaultHost() bool {
	return l.hostname == DefaultHost
}

// Less ...
func (l *PathLink) Less(other *PathLink, reversePath bool) bool {
	if l.hostname == other.hostname {
		if reversePath {
			return l.path > other.path
		}
		return l.path < other.path
	}
	return l.hostname < other.hostname
}

// HAMatch ...
func (l *PathLink) HAMatch() string {
	return haMatchMethod(l.match)
}

// Key ...
func (l *PathLink) Key() string {
	return buildMapKey(l.match, l.hostname, l.path)
}

// String ...
func (h *Host) String() string {
	return fmt.Sprintf("%+v", *h)
}

// CAVerifyOptional ...
func (tls *TLSConfig) CAVerifyOptional() bool {
	return tls.CAVerify == CAVerifyOptional || tls.CAVerify == CAVerifySkipCheck
}

// HasTLS ...
func (h *HostTLSConfig) HasTLS() bool {
	return h.TLSFilename != ""
}
