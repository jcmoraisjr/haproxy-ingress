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
	"strings"
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

// StringInSlice check whether string a is a member of slice.
func StringInSlice(a string, slice []string) bool {
	for _, b := range slice {
		if b == a {
			return true
		}
	}
	return false
}

// SplitMin slices string in at least min items
func SplitMin(str string, sub string, min int) []string {
	slice := strings.Split(str, sub)
	if len(slice) >= min {
		return slice
	}
	minSlice := make([]string, min)
	for i := range slice {
		minSlice[i] = slice[i]
	}
	return minSlice
}
