/*
Copyright 2026 The HAProxy Ingress Controller Authors.

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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIP(t *testing.T) {
	type ipClass int
	const (
		ipv4 ipClass = iota
		ipv6
		ipNone
	)
	testCases := map[string]struct {
		addr     string
		expClass ipClass
	}{
		"ipv4-loopback": {
			addr:     "127.0.0.1",
			expClass: ipv4,
		},
		"ipv4-loopback-prefix": {
			addr:     "127.0.0.1/8",
			expClass: ipv4,
		},
		"ipv4-public": {
			addr:     "200.0.0.10",
			expClass: ipv4,
		},
		"ipv4-public-prefix": {
			addr:     "200.0.0.10/24",
			expClass: ipv4,
		},
		"ipv4-private": {
			addr:     "10.0.0.10",
			expClass: ipv4,
		},
		"ipv4-private-prefix": {
			addr:     "10.0.0.10/24",
			expClass: ipv4,
		},
		"ipv4-in-ipv6": {
			addr:     "::ffff:fa00:fa01",
			expClass: ipv6,
		},
		"ipv4-in-ipv6-prefix": {
			addr:     "::ffff:fa00:fa01/24",
			expClass: ipv6,
		},
		"ipv6-loopback": {
			addr:     "::1",
			expClass: ipv6,
		},
		"ipv6-loopback-prefix": {
			addr:     "::1/128",
			expClass: ipv6,
		},
		"ipv6-public": {
			addr:     "fa00::fa01",
			expClass: ipv6,
		},
		"ipv6-public-prefix": {
			addr:     "fa00::fa01/128",
			expClass: ipv6,
		},
		"hostname-example": {
			addr:     "host.example.com",
			expClass: ipNone,
		},
		"hostname-valid": {
			addr:     "haproxy-ingress.github.io",
			expClass: ipNone,
		},
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			v4, v6 := parseIP(test.addr)
			assert.Equal(t, test.expClass == ipv4, v4, "is-ipv4")
			assert.Equal(t, test.expClass == ipv6, v6, "is-ipv6")
		})
	}
}
