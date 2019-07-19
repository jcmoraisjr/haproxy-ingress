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

func TestAddPath(t *testing.T) {
	testCases := []struct {
		input    []string
		expected []*BackendPath
	}{
		// 0
		{
			input: []string{"/"},
			expected: []*BackendPath{
				{"path01", "/"},
			},
		},
		// 1
		{
			input: []string{"/app", "/app"},
			expected: []*BackendPath{
				{"path01", "/app"},
			},
		},
		// 2
		{
			input: []string{"/app", "/root"},
			expected: []*BackendPath{
				{"path02", "/root"},
				{"path01", "/app"},
			},
		},
		// 3
		{
			input: []string{"/app", "/root", "/root"},
			expected: []*BackendPath{
				{"path02", "/root"},
				{"path01", "/app"},
			},
		},
		// 4
		{
			input: []string{"/app", "/root", "/app"},
			expected: []*BackendPath{
				{"path02", "/root"},
				{"path01", "/app"},
			},
		},
		// 5
		{
			input: []string{"/", "/app", "/root"},
			expected: []*BackendPath{
				{"path03", "/root"},
				{"path02", "/app"},
				{"path01", "/"},
			},
		},
	}
	for i, test := range testCases {
		b := &Backend{}
		for _, p := range test.input {
			b.AddPath(p)
		}
		if !reflect.DeepEqual(b.Paths, test.expected) {
			t.Errorf("backend.Paths differs on %d - actual: %v - expected: %v", i, b.Paths, test.expected)
		}
	}
}
