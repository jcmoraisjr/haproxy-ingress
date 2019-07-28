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
)

// AddEndpoint ...
func (b *TCPBackend) AddEndpoint(ip string, port int) *TCPEndpoint {
	ep := &TCPEndpoint{
		Name:   fmt.Sprintf("srv%03d", len(b.Endpoints)+1),
		IP:     ip,
		Port:   port,
		Target: fmt.Sprintf("%s:%d", ip, port),
	}
	b.Endpoints = append(b.Endpoints, ep)
	return ep
}
