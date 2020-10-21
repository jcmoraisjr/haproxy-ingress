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
				{"path01", PathLink{"d1.local", "/"}},
			},
		},
		// 1
		{
			input: []string{"/app", "/app"},
			expected: []*BackendPath{
				{"path01", PathLink{"d1.local", "/app"}},
			},
		},
		// 2
		{
			input: []string{"/app", "/root"},
			expected: []*BackendPath{
				{"path02", PathLink{"d1.local", "/root"}},
				{"path01", PathLink{"d1.local", "/app"}},
			},
		},
		// 3
		{
			input: []string{"/app", "/root", "/root"},
			expected: []*BackendPath{
				{"path02", PathLink{"d1.local", "/root"}},
				{"path01", PathLink{"d1.local", "/app"}},
			},
		},
		// 4
		{
			input: []string{"/app", "/root", "/app"},
			expected: []*BackendPath{
				{"path02", PathLink{"d1.local", "/root"}},
				{"path01", PathLink{"d1.local", "/app"}},
			},
		},
		// 5
		{
			input: []string{"/", "/app", "/root"},
			expected: []*BackendPath{
				{"path03", PathLink{"d1.local", "/root"}},
				{"path02", PathLink{"d1.local", "/app"}},
				{"path01", PathLink{"d1.local", "/"}},
			},
		},
	}
	for i, test := range testCases {
		b := &Backend{}
		for _, p := range test.input {
			b.AddBackendPath(CreatePathLink("d1.local", p))
		}
		if !reflect.DeepEqual(b.Paths, test.expected) {
			t.Errorf("backend.Paths differs on %d - actual: %v - expected: %v", i, b.Paths, test.expected)
		}
	}
}

func TestIDList(t *testing.T) {
	testCases := []struct {
		paths    []string
		expected []string
	}{
		// 0
		{
			paths:    []string{},
			expected: []string{},
		},
		// 1
		{
			paths:    []string{"p1"},
			expected: []string{"p1"},
		},
		// 2
		{
			paths:    []string{"p1", "p2", "p3"},
			expected: []string{"p1 p2 p3"},
		},
		// 3
		{
			paths:    []string{"p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24", "p25", "p26", "p27", "p28", "p29"},
			expected: []string{"p01 p02 p03 p04 p05 p06 p07 p08 p09 p10 p11 p12 p13 p14 p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28 p29"},
		},
		// 4
		{
			paths:    []string{"p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24", "p25", "p26", "p27", "p28", "p29", "p30"},
			expected: []string{"p01 p02 p03 p04 p05 p06 p07 p08 p09 p10 p11 p12 p13 p14 p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28 p29 p30"},
		},
		// 5
		{
			paths:    []string{"p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24", "p25", "p26", "p27", "p28", "p29", "p30", "p31"},
			expected: []string{"p01 p02 p03 p04 p05 p06 p07 p08 p09 p10 p11 p12 p13 p14 p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28 p29 p30", "p31"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		paths := make([]*BackendPath, len(test.paths))
		for j, path := range test.paths {
			paths[j] = &BackendPath{ID: path}
		}
		b := BackendPaths{
			Items: paths,
		}
		pathIDs := b.IDList()
		if len(pathIDs) > 0 || len(test.expected) > 0 {
			c.compareObjects("pathIDs", i, pathIDs, test.expected)
		}
		c.teardown()
	}
}
