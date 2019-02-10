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

package haproxy

import (
	"testing"
)

func TestAcquireHostDiff(t *testing.T) {
	c := createConfig()
	f1 := c.AcquireHost("h1")
	f2 := c.AcquireHost("h2")
	if f1.Hostname != "h1" {
		t.Errorf("expected %v but was %v", "h1", f1.Hostname)
	}
	if f2.Hostname != "h2" {
		t.Errorf("expected %v but was %v", "h2", f2.Hostname)
	}
}

func TestAcquireHostSame(t *testing.T) {
	c := createConfig()
	f1 := c.AcquireHost("h1")
	f2 := c.AcquireHost("h1")
	if f1 != f2 {
		t.Errorf("expected same host but was different")
	}
}

func TestBuildID(t *testing.T) {
	testCases := []struct {
		namespace string
		name      string
		port      int
		expected  string
	}{
		{
			"default", "echo", 8080, "default_echo_8080",
		},
	}
	for _, test := range testCases {
		if actual := buildID(test.namespace, test.name, test.port); actual != test.expected {
			t.Errorf("expected '%s' but was '%s'", test.expected, actual)
		}
	}
}
