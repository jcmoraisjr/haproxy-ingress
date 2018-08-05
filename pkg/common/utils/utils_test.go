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

package utils

import (
	"testing"
)

func TestDeepEqualUnsortedMatch(t *testing.T) {
	a1 := []string{"a", "b", "c"}
	a2 := []string{"c", "a", "b"}
	if !DeepEqualUnsorted(a1, a2, func(i1, i2 int) bool {
		return a1[i1] == a2[i2]
	}) {
		t.Errorf("expected a1 and a2 equals")
	}

	a3 := []string{"1", "2", "3"}
	a4 := []string{"1", "2", "3"}
	if !DeepEqualUnsorted(a3, a4, func(i1, i2 int) bool {
		return a4[i1] == a4[i2]
	}) {
		t.Errorf("expected a3 and a4 equals")
	}
}

func TestDeepEqualUnsortedUnmatch(t *testing.T) {
	a1 := []string{"a", "b", "c"}
	a2 := []string{"a", "b", "d"}
	if DeepEqualUnsorted(a1, a2, func(i1, i2 int) bool {
		return a1[i1] == a2[i2]
	}) {
		t.Errorf("expected a1 and a2 not equals")
	}

	a3 := []string{"1", "2", "3"}
	a4 := []string{"1", "2", "2", "3"}
	if DeepEqualUnsorted(a3, a4, func(i1, i2 int) bool {
		return a4[i1] == a4[i2]
	}) {
		t.Errorf("expected a3 and a4 not equals")
	}
}

func TestSliceMin(t *testing.T) {
	testCases := []struct {
		data      string
		separator string
		min       int
		expected  []string
	}{
		{"a,b,c", ",", 3, []string{"a", "b", "c"}},
		{"a-b", "-", 3, []string{"a", "b", ""}},
		{"a;b", ";", 1, []string{"a", "b"}},
		{"a;b", ",", 1, []string{"a;b"}},
	}
	for _, test := range testCases {
		split := SplitMin(test.data, test.separator, test.min)
		if len(split) != len(test.expected) {
			t.Errorf("expected len(%v),%v == %v but was %v", test.data, test.min, len(test.expected), len(split))
		}
		for i := range split {
			if i >= len(test.expected) {
				if split[i] != "" {
					t.Errorf("expected empty string but was %v", split[i])
				} else if split[i] != test.expected[i] {
					t.Errorf("'%v' and '%v' should be equals", split[i], test.expected[i])
				}
			}
		}
	}
}

func TestGCD(t *testing.T) {
	testCases := []struct {
		a        int
		b        int
		expected int
	}{
		{10, 1, 1},
		{10, 3, 1},
		{10, 4, 2},
		{10, 5, 5},
		{10, 10, 10},
		{10, 12, 2},
		{10, 15, 5},
		{10, 20, 10},
	}
	for _, test := range testCases {
		res := GCD(test.a, test.b)
		if res != test.expected {
			t.Errorf("expected %v from %v and %v, but was %v", test.expected, test.a, test.b, res)
		}
	}
}

func TestLCM(t *testing.T) {
	testCases := []struct {
		a        int
		b        int
		expected int
	}{
		{10, 1, 10},
		{10, 3, 30},
		{10, 4, 20},
		{10, 5, 10},
		{10, 10, 10},
		{10, 12, 60},
		{10, 15, 30},
		{10, 20, 20},
	}
	for _, test := range testCases {
		res := LCM(test.a, test.b)
		if res != test.expected {
			t.Errorf("expected %v from %v and %v, but was %v", test.expected, test.a, test.b, res)
		}
	}
}
