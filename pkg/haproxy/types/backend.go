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
)

// NewEndpoint ...
func (b *Backend) NewEndpoint(ip string, port int, targetRef string) *Endpoint {
	endpoint := &Endpoint{
		Name:      fmt.Sprintf("%s:%d", ip, port),
		IP:        ip,
		Port:      port,
		TargetRef: targetRef,
		Weight:    1,
	}
	b.Endpoints = append(b.Endpoints, endpoint)
	sort.Slice(b.Endpoints, func(i, j int) bool {
		return b.Endpoints[i].Name < b.Endpoints[j].Name
	})
	return endpoint
}

// AddPath ...
func (b *Backend) AddPath(path string) {
	for _, p := range b.Paths {
		if p == path {
			// add only unique paths
			return
		}
	}
	// host's paths that references this backend
	// used on RewriteURL config
	b.Paths = append(b.Paths, path)
	// reverse order in order to avoid overlap of sub-paths
	sort.Slice(b.Paths, func(i, j int) bool {
		return b.Paths[i] > b.Paths[j]
	})
}

// HreqValidateUserlist ...
func (b *Backend) HreqValidateUserlist(userlist *Userlist) {
	// TODO implement
	b.HTTPRequests = append(b.HTTPRequests, &HTTPRequest{})
}

func (h *HTTPRequest) String() string {
	return fmt.Sprintf("%+v", *h)
}
