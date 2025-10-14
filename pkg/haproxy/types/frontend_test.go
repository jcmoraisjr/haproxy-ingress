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
	"testing"
)

func TestAcquireAuthFrontendLocalPort(t *testing.T) {
	testCases := []struct {
		rangeStart int
		rangeEnd   int
		backends   []string
		expBacks   []string
		expErrors  []string
	}{
		// 0
		{
			rangeStart: 0,
			rangeEnd:   -1,
			backends:   []string{"back1"},
			expBacks:   []string{""},
			expErrors:  []string{"auth proxy list is full"},
		},
		// 1
		{
			rangeStart: 1001,
			rangeEnd:   1001,
			backends:   []string{"back1", "back2"},
			expBacks:   []string{"_auth_1001", ""},
			expErrors:  []string{"", "auth proxy list is full"},
		},
		// 2
		{
			rangeStart: 1001,
			rangeEnd:   1010,
			backends:   []string{"back1", "back2", "back1"},
			expBacks:   []string{"_auth_1001", "_auth_1002", "_auth_1001"},
			expErrors:  []string{"", "", ""},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		authProxy := AuthProxy{
			RangeStart: test.rangeStart,
			RangeEnd:   test.rangeEnd,
		}
		authBackendNames := make([]string, len(test.backends))
		errs := make([]string, len(test.backends))
		for j, back := range test.backends {
			authBackendName, err := authProxy.AcquireAuthBackendName(BackendID{Name: back})
			authBackendNames[j] = authBackendName
			if err != nil {
				errs[j] = err.Error()
			}
		}
		c.compareObjects("auth frontend ports", i, authBackendNames, test.expBacks)
		c.compareObjects("auth frontend errs", i, errs, test.expErrors)
		c.teardown()
	}
}

func TestRemoveAuthBackendExcept(t *testing.T) {
	testCases := []struct {
		input    []string
		used     map[string]bool
		expected []string
	}{
		// 0
		{
			input:    []string{"backend1", "backend2"},
			used:     map[string]bool{"backend2": true},
			expected: []string{"backend2"},
		},
		// 1
		{
			input:    []string{},
			used:     map[string]bool{"backend2": true},
			expected: []string{},
		},
		// 2
		{
			input:    []string{"backend1", "backend2"},
			used:     map[string]bool{"backend1": true, "backend2": true},
			expected: []string{"backend1", "backend2"},
		},
		// 3
		{
			input:    []string{"backend1", "backend2"},
			used:     map[string]bool{},
			expected: []string{},
		},
		// 4
		{
			input:    []string{"backend1", "backend2"},
			used:     map[string]bool{"backend0": true, "backend2": true},
			expected: []string{"backend2"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		authProxy := AuthProxy{}
		for _, input := range test.input {
			authProxy.BindList = append(authProxy.BindList, &AuthProxyBind{
				AuthBackendName: input,
			})
		}
		authProxy.RemoveAuthBackendExcept(test.used)
		actual := []string{}
		for _, item := range authProxy.BindList {
			actual = append(actual, item.AuthBackendName)
		}
		c.compareObjects("remove", i, actual, test.expected)
		c.teardown()
	}
}

func TestRemoveAuthBackendByTarget(t *testing.T) {
	back0 := BackendID{Namespace: "default", Name: "backend0", Port: "8080"}
	back1 := BackendID{Namespace: "default", Name: "backend1", Port: "8080"}
	back2 := BackendID{Namespace: "default", Name: "backend2", Port: "8080"}
	testCases := []struct {
		input    []BackendID
		removed  []string
		expected []BackendID
	}{
		// 0
		{
			input:    []BackendID{back1, back2},
			removed:  []string{back2.String()},
			expected: []BackendID{back1},
		},
		// 1
		{
			input:    []BackendID{},
			removed:  []string{back2.String()},
			expected: []BackendID{},
		},
		// 2
		{
			input:    []BackendID{back1, back2},
			removed:  []string{back1.String(), back2.String()},
			expected: []BackendID{},
		},
		// 3
		{
			input:    []BackendID{back1, back2},
			removed:  []string{},
			expected: []BackendID{back1, back2},
		},
		// 4
		{
			input:    []BackendID{back1, back2},
			removed:  []string{back0.String(), back2.String()},
			expected: []BackendID{back1},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		authProxy := AuthProxy{}
		for _, input := range test.input {
			authProxy.BindList = append(authProxy.BindList, &AuthProxyBind{
				Backend: input,
			})
		}
		authProxy.RemoveAuthBackendByTarget(test.removed)
		actual := []BackendID{}
		for _, item := range authProxy.BindList {
			actual = append(actual, item.Backend)
		}
		c.compareObjects("remove", i, actual, test.expected)
		c.teardown()
	}
}
