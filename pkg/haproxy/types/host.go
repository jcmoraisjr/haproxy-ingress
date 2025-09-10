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

	"k8s.io/utils/ptr"
)

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

// AddRedirect ...
func (h *Host) AddRedirect(path string, match MatchType, redirTo string) {
	_ = h.addPath(path, match, nil, redirTo)
}

// AddLink ...
func (h *Host) AddLink(backend *Backend, link *PathLink) *HostPath {
	return h.addLink(backend, link, "")
}

// AddLinkRedirect ...
func (h *Host) AddLinkRedirect(link *PathLink, redirTo string) *HostPath {
	return h.addLink(nil, link, redirTo)
}

type hostResolver struct {
	useDefaultCrt       *bool
	followRedirect      *bool
	crtFilename         *string
	hasFrontingProxy    *bool
	hasFrontingUseProto *bool
}

func (h *Host) addPath(path string, match MatchType, backend *Backend, redirTo string) *HostPath {
	link := CreatePathLink(path, match)
	return h.addLink(backend, link, redirTo)
}

func (h *Host) addLink(backend *Backend, link *PathLink, redirTo string) *HostPath {
	link = ptr.To(*link).WithHTTPHost(h)
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
			useDefaultCrt:       &h.TLS.UseDefaultCrt,
			followRedirect:      &h.TLS.FollowRedirect,
			crtFilename:         &h.TLS.TLSFilename,
			hasFrontingProxy:    &h.frontend.IsFrontingProxy,
			hasFrontingUseProto: &h.frontend.IsFrontingUseProto,
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

func (h *hostResolver) HasFrontingProxy() bool {
	return *h.hasFrontingProxy
}

func (h *hostResolver) HasFrontingUseProto() bool {
	return *h.hasFrontingUseProto
}

// HasTLSAuth ...
func (h *Host) HasTLSAuth() bool {
	return h.TLS.CAHash != ""
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
