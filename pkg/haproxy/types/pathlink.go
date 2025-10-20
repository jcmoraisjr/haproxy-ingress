/*
Copyright 2025 The HAProxy Ingress Controller Authors.

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
)

func CreatePathLink(path string, match MatchType) *PathLink {
	pathlink := &PathLink{
		hostname: DefaultHost,
		path:     path,
		match:    match,
	}
	pathlink.updatehash()
	return pathlink
}

func (l *PathLink) updatehash() {
	hash := l.frontend + "\n" + l.hostname + "\n" + l.path + "\n" + string(l.match)
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

// IsComposeMatch returns true if the pathLink has composing match,
// by adding method, header or cookie match.
func (l *PathLink) IsComposeMatch() bool {
	return len(l.headers) > 0
}

// WithHTTPFront ...
func (l *PathLink) WithHTTPFront(front *Frontend) *PathLink {
	l.frontend = front.Name
	l.updatehash()
	return l
}

// WithHTTPHost ...
func (l *PathLink) WithHTTPHost(host *Host) *PathLink {
	l.frontend = host.frontend.Name
	l.hostname = host.Hostname
	l.updatehash()
	return l
}

// WithTCPHost ...
func (l *PathLink) WithTCPHost(tcphost *TCPServiceHost) *PathLink {
	l.frontend = fmt.Sprintf("_tcp_%d", tcphost.tcpport.port)
	l.hostname = fmt.Sprintf("%s:%d", tcphost.hostname, tcphost.tcpport.port)
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
