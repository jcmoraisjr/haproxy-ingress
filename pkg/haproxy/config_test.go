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

	ha_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/helper_test"
)

func TestEmptyFrontend(t *testing.T) {
	c := createConfig(&ha_helper.BindUtilsMock{}, options{})
	if err := c.BuildFrontendGroup(); err == nil {
		t.Error("expected error creating empty frontend")
	}
	c.AcquireHost("empty")
	if err := c.BuildFrontendGroup(); err != nil {
		t.Errorf("error creating frontends: %v", err)
	}
}

func TestAcquireHostDiff(t *testing.T) {
	c := createConfig(&ha_helper.BindUtilsMock{}, options{})
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
	c := createConfig(&ha_helper.BindUtilsMock{}, options{})
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

func TestEqual(t *testing.T) {
	c1 := createConfig(&ha_helper.BindUtilsMock{}, options{})
	c2 := createConfig(&ha_helper.BindUtilsMock{}, options{})
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (empty)")
	}
	c1.ConfigDefaultX509Cert("/var/default.pem")
	if c1.Equals(c2) {
		t.Error("c1 and c2 should not be equals (one default cert)")
	}
	c2.ConfigDefaultX509Cert("/var/default.pem")
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (default cert)")
	}
	b1 := c1.AcquireBackend("d", "app1", "8080")
	c1.AcquireBackend("d", "app2", "8080")
	if c1.Equals(c2) {
		t.Error("c1 and c2 should not be equals (backends on one side)")
	}
	c2.AcquireBackend("d", "app2", "8080")
	b2 := c2.AcquireBackend("d", "app1", "8080")
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (with backends)")
	}
	h1 := c1.AcquireHost("d")
	h1.AddPath(b1, "/")
	if c1.Equals(c2) {
		t.Error("c1 and c2 should not be equals (hosts on one side)")
	}
	h2 := c2.AcquireHost("d")
	h2.AddPath(b2, "/")
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (with hosts)")
	}
	err1 := c1.BuildFrontendGroup()
	err2 := c2.BuildFrontendGroup()
	if err1 != nil {
		t.Errorf("error building c1: %v", err1)
	}
	if err2 != nil {
		t.Errorf("error building c2: %v", err2)
	}
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (after building frontends)")
	}
}
