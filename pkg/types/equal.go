/*
Copyright 2018 The Kubernetes Authors.

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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/utils"
	"reflect"
)

// Equal return the equality between two ControllerConfig
func (c1 *ControllerConfig) Equal(c2 *ControllerConfig) bool {
	if c1 == nil || c2 == nil {
		return c1 == c2
	}
	// diffing only source of data: Backends, Servers, TCPEndpoints and PassthroughBackends
	// TODO: move them to a single IngressConfig field
	if !utils.DeepEqualUnsorted(c1.Backends, c2.Backends, func(i1, i2 int) bool {
		return c1.Backends[i1].Equal(c2.Backends[i2])
	}) {
		return false
	}
	if !utils.DeepEqualUnsorted(c1.Servers, c2.Servers, func(i1, i2 int) bool {
		return c1.Servers[i1].Equal(c2.Servers[i2])
	}) {
		return false
	}
	if !utils.DeepEqualUnsorted(c1.TCPEndpoints, c2.TCPEndpoints, func(i1, i2 int) bool {
		return c1.TCPEndpoints[i1].Equal(&c2.TCPEndpoints[i2])
	}) {
		return false
	}
	if !utils.DeepEqualUnsorted(c1.PassthroughBackends, c2.PassthroughBackends, func(i1, i2 int) bool {
		return c1.PassthroughBackends[i1].Equal(c2.PassthroughBackends[i2])
	}) {
		return false
	}
	if !reflect.DeepEqual(c1.Cfg, c2.Cfg) {
		return false
	}
	if !c1.StatsSSLCert.Equal(c2.StatsSSLCert) {
		return false
	}
	return true
}
