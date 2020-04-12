/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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

func TestBuildID(t *testing.T) {
	testCases := []struct {
		namespace string
		name      string
		port      string
		expected  string
	}{
		{
			"default", "echo", "8080", "default_echo_8080",
		},
	}
	for _, test := range testCases {
		if actual := buildID(test.namespace, test.name, test.port); actual != test.expected {
			t.Errorf("expected '%s' but was '%s'", test.expected, actual)
		}
	}
}
