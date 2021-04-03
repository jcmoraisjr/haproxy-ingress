/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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
	"testing"
)

func TestRemoveAll(t *testing.T) {
	testCases := []struct {
		input      []string
		remove     []string
		expItems   []string
		expDefault []string
		changed    bool
	}{
		// 0
		{
			remove: []string{"local:7001"},
		},
		// 1
		{
			input:    []string{":7001", ":7002"},
			remove:   []string{"local:7001"},
			expItems: []string{":7001", ":7002"},
		},
		// 2
		{
			input:    []string{":7001", ":7002"},
			remove:   []string{"local"},
			expItems: []string{":7001", ":7002"},
		},
		// 3
		{
			input:    []string{":7001", ":7002"},
			remove:   []string{"local:"},
			expItems: []string{":7001", ":7002"},
		},
		// 4
		{
			input:    []string{":7001", ":7002"},
			remove:   []string{"7001"},
			expItems: []string{":7001", ":7002"},
		},
		// 5
		{
			input:    []string{":7001", ":7002"},
			remove:   []string{":7002"},
			expItems: []string{":7001"},
			changed:  true,
		},
		// 6
		{
			input:    []string{":7001", ":7002"},
			remove:   []string{":7003"},
			expItems: []string{":7001", ":7002"},
		},
		// 7
		{
			input:    []string{":7001", ":7002", ":7003"},
			remove:   []string{":7001", ":7002"},
			expItems: []string{":7003"},
			changed:  true,
		},
		// 8
		{
			input:    []string{":7001"},
			remove:   []string{":7001"},
			expItems: nil,
			changed:  true,
		},
		// 9
		{
			input:    []string{"local1:7001", "local2:7001", "local3:7001"},
			remove:   []string{"local1:7001"},
			expItems: []string{"local2:7001", "local3:7001"},
			changed:  true,
		},
		// 10
		{
			input:    []string{"local1:7001"},
			remove:   []string{"local1:7002"},
			expItems: []string{"local1:7001"},
		},
		// 11
		{
			input:    []string{"local1:7001"},
			remove:   []string{"local2:7001"},
			expItems: []string{"local1:7001"},
		},
		// 12
		{
			input:      []string{"<default>:7001"},
			remove:     []string{},
			expItems:   nil,
			expDefault: []string{"<default>"},
		},
		// 13
		{
			input:      []string{"<default>:7001"},
			remove:     []string{"<default>:7001"},
			expItems:   nil,
			expDefault: nil,
			changed:    true,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		f := CreateTCPServices()
		for _, input := range test.input {
			f.AcquireTCPService(input)
		}
		f.changed = false
		f.RemoveAll(test.remove)
		var expItems, expDefault []string
		for _, tcpPort := range f.Items() {
			for _, tcpHost := range tcpPort.hosts {
				expItems = append(expItems, fmt.Sprintf("%s:%d", tcpHost.hostname, tcpPort.port))
			}
			if tcpPort.defaultHost != nil {
				expDefault = append(expDefault, tcpPort.defaultHost.hostname)
			}
		}
		sort.Strings(expItems)
		sort.Strings(expDefault)
		c.compareObjects("tcpservices items", i, expItems, test.expItems)
		c.compareObjects("tcpservices default", i, expDefault, test.expDefault)
		c.compareObjects("tcpservices changed", i, f.changed, test.changed)
		c.teardown()
	}
}
