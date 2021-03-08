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
	"sort"
	"testing"
)

func TestRemoveAll(t *testing.T) {
	testCases := []struct {
		input    []int
		remove   []string
		expItems []int
		changed  bool
	}{
		// 0
		{
			remove: []string{"local:7001"},
		},
		// 1
		{
			input:    []int{7001, 7002},
			remove:   []string{"local:7001"},
			expItems: []int{7002},
			changed:  true,
		},
		// 2
		{
			input:    []int{7001, 7002},
			remove:   []string{"local"},
			expItems: []int{7001, 7002},
		},
		// 3
		{
			input:    []int{7001, 7002},
			remove:   []string{"local:"},
			expItems: []int{7001, 7002},
		},
		// 4
		{
			input:    []int{7001, 7002},
			remove:   []string{"7001"},
			expItems: []int{7001, 7002},
		},
		// 5
		{
			input:    []int{7001, 7002},
			remove:   []string{":7002"},
			expItems: []int{7001},
			changed:  true,
		},
		// 6
		{
			input:    []int{7001, 7002},
			remove:   []string{":7003"},
			expItems: []int{7001, 7002},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		f := CreateTCPServices()
		for _, input := range test.input {
			f.AddTCPService(input)
		}
		f.RemoveAll(test.remove)
		var expItems []int
		for port := range f.Items() {
			expItems = append(expItems, port)
		}
		sort.Ints(expItems)
		c.compareObjects("tcpservices items", i, expItems, test.expItems)
		c.compareObjects("tcpservices changed", i, f.changed, test.changed)
		c.teardown()
	}
}
