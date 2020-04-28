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

func TestEmptyFrontend(t *testing.T) {
	c := createConfig(options{})
	if err := c.WriteFrontendMaps(); err != nil {
		t.Errorf("error creating frontends: %v", err)
	}
	if maps := c.frontend.Maps; maps == nil {
		t.Error("expected frontend.Maps != nil")
	}
	c.hosts.AcquireHost("empty")
	if err := c.WriteFrontendMaps(); err != nil {
		t.Errorf("error creating frontends: %v", err)
	}
	maps := c.frontend.Maps
	if maps == nil {
		t.Error("expected frontend.Maps != nil")
	}
}

func TestAcquireHostDiff(t *testing.T) {
	c := createConfig(options{})
	f1 := c.hosts.AcquireHost("h1")
	f2 := c.hosts.AcquireHost("h2")
	if f1.Hostname != "h1" {
		t.Errorf("expected %v but was %v", "h1", f1.Hostname)
	}
	if f2.Hostname != "h2" {
		t.Errorf("expected %v but was %v", "h2", f2.Hostname)
	}
}

func TestAcquireHostSame(t *testing.T) {
	c := createConfig(options{})
	f1 := c.hosts.AcquireHost("h1")
	f2 := c.hosts.AcquireHost("h1")
	if f1 != f2 {
		t.Errorf("expected same host but was different")
	}
}

func TestEqual(t *testing.T) {
	c1 := createConfig(options{})
	c2 := createConfig(options{})
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (empty)")
	}
	c1.frontend.DefaultCert = "/var/default.pem"
	if c1.Equals(c2) {
		t.Error("c1 and c2 should not be equals (one default cert)")
	}
	c2.frontend.DefaultCert = "/var/default.pem"
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (default cert)")
	}
	b1 := c1.Backends().AcquireBackend("d", "app1", "8080")
	c1.Backends().AcquireBackend("d", "app2", "8080")
	if c1.Equals(c2) {
		t.Error("c1 and c2 should not be equals (backends on one side)")
	}
	c2.Backends().AcquireBackend("d", "app2", "8080")
	b2 := c2.Backends().AcquireBackend("d", "app1", "8080")
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (with backends)")
	}
	h1 := c1.hosts.AcquireHost("d")
	h1.AddPath(b1, "/")
	if c1.Equals(c2) {
		t.Error("c1 and c2 should not be equals (hosts on one side)")
	}
	h2 := c2.hosts.AcquireHost("d")
	h2.AddPath(b2, "/")
	if !c1.Equals(c2) {
		t.Error("c1 and c2 should be equals (with hosts)")
	}
	err1 := c1.WriteFrontendMaps()
	err2 := c2.WriteFrontendMaps()
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

func TestClear(t *testing.T) {
	c := createConfig(options{
		mapsDir: "/tmp/maps",
	})
	c.Hosts().AcquireHost("app.local")
	c.Backends().AcquireBackend("default", "app", "8080")
	if c.mapsDir != "/tmp/maps" {
		t.Error("expected mapsDir == /tmp/maps")
	}
	if len(c.Hosts().Items()) != 1 {
		t.Error("expected len(hosts) == 1")
	}
	if len(c.Backends().Items()) != 1 {
		t.Error("expected len(backends) == 1")
	}
	c.Clear()
	if c.mapsDir != "/tmp/maps" {
		t.Error("expected mapsDir == /tmp/maps")
	}
	if len(c.Hosts().Items()) != 0 {
		t.Error("expected len(hosts) == 0")
	}
	if len(c.Backends().Items()) != 0 {
		t.Error("expected len(backends) == 0")
	}
}
