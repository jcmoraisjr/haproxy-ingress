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

	"k8s.io/utils/ptr"
)

// FindPath ...
func (h *Host) FindPath(path string, match ...MatchType) (paths []*Path) {
	for _, p := range h.Paths {
		if p.Link.path == path && p.Link.headers == nil && p.hasMatch(match) {
			paths = append(paths, p)
		}
	}
	return paths
}

// FindPathWithLink ...
func (h *Host) FindPathWithLink(link *PathLink) (path *Path) {
	for _, p := range h.Paths {
		if p.Link.Equals(link) {
			return p
		}
	}
	return nil
}

// AddPath ...
func (h *Host) AddPath(backend *Backend, path string, match MatchType) *Path {
	return h.addLink(backend, CreatePathLink(path, match), "")
}

// AddRedirect ...
func (h *Host) AddRedirect(path string, match MatchType, redirTo string) *Path {
	return h.addLink(nil, CreatePathLink(path, match), redirTo)
}

// AddLink ...
func (h *Host) AddLink(backend *Backend, link *PathLink) *Path {
	return h.addLink(backend, link, "")
}

// AddLinkRedirect ...
func (h *Host) AddLinkRedirect(link *PathLink, redirTo string) *Path {
	return h.addLink(nil, link, redirTo)
}

func (h *Host) addLink(backend *Backend, link *PathLink, redirTo string) *Path {
	link = ptr.To(*link).WithHTTPHost(h)
	path := &Path{
		Link:    link,
		Host:    h,
		RedirTo: redirTo,
		order:   len(h.Paths),
	}
	if backend != nil {
		backend.AddPath(path)
		path.Backend = backend
	}
	h.Paths = append(h.Paths, path)
	// paths must be sorted to avoid misbehavior due to overlap,
	// this is happening later on maps.go/rebuildMatchFiles()
	return path
}

// RemovePath ...
func (h *Host) RemovePath(hpath *Path) {
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

// HasTLSAuth ...
func (h *Host) HasTLSAuth() bool {
	return h.TLS.CAHash != ""
}

// Headers ...
func (h *Path) Headers() HTTPHeaderMatch {
	return h.Link.headers
}

func (h *Path) hasMatch(match []MatchType) bool {
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
