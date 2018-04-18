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
	"reflect"
)

// DeepEqualUnsorted check equality of unsorted arrays.
// Panic if p1 or p2 isn't array
func DeepEqualUnsorted(p1, p2 interface{}, equal func(i1, i2 int) bool) bool {
	v1 := reflect.ValueOf(p1)
	v2 := reflect.ValueOf(p2)
	if v1.Len() != v2.Len() {
		return false
	}
	for i1 := 0; i1 < v1.Len(); i1++ {
		found := false
		for i2 := 0; i2 < v2.Len(); i2++ {
			if equal(i1, i2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
