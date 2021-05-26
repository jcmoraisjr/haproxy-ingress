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

package utils

import (
	"testing"
)

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
		res := gcd(test.a, test.b)
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
		res := lcm(test.a, test.b)
		if res != test.expected {
			t.Errorf("expected %v from %v and %v, but was %v", test.expected, test.a, test.b, res)
		}
	}
}
