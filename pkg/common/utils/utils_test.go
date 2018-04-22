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
