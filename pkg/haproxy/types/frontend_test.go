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
		frontend := &Frontend{
			AuthProxy: AuthProxy{
				RangeStart: test.rangeStart,
				RangeEnd:   test.rangeEnd,
			},
		}
		authBackendNames := make([]string, len(test.backends))
		errs := make([]string, len(test.backends))
		for j, back := range test.backends {
			authBackendName, err := frontend.AcquireAuthBackendName(BackendID{Name: back})
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
