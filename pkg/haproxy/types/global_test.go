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
	"reflect"
	"testing"
)

func TestAcmeAddDomain(t *testing.T) {
	testCases := []struct {
		certs    [][]string
		expected map[string]map[string]struct{}
	}{
		// 0
		{
			certs: [][]string{
				{"cert1", "d1.local"},
			},
			expected: map[string]map[string]struct{}{
				"cert1": {"d1.local": {}},
			},
		},
		// 1
		{
			certs: [][]string{
				{"cert1", "d1.local", "d2.local"},
				{"cert1", "d2.local", "d3.local"},
			},
			expected: map[string]map[string]struct{}{
				"cert1": {"d1.local": {}, "d2.local": {}, "d3.local": {}},
			},
		},
		// 2
		{
			certs: [][]string{
				{"cert1", "d1.local", "d2.local"},
				{"cert2", "d2.local", "d3.local"},
			},
			expected: map[string]map[string]struct{}{
				"cert1": {"d1.local": {}, "d2.local": {}},
				"cert2": {"d2.local": {}, "d3.local": {}},
			},
		},
	}
	for i, test := range testCases {
		acme := AcmeData{}
		for _, cert := range test.certs {
			acme.AddDomains(cert[0], cert[1:])
		}
		if !reflect.DeepEqual(acme.Certs, test.expected) {
			t.Errorf("acme certs differs on %d - expected: %+v, actual: %+v", i, test.expected, acme.Certs)
		}
	}
}
