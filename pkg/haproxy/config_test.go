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
	c := createConfig(options{})
	f := c.frontends.AcquireFrontend(8000, false)
	h1 := f.AcquireHost("h1")
	h2 := f.AcquireHost("h2")
	if h1.Hostname != "h1" {
		t.Errorf("expected %v but was %v", "h1", h1.Hostname)
	}
	if h2.Hostname != "h2" {
		t.Errorf("expected %v but was %v", "h2", h2.Hostname)
	}
}

func TestAcquireHostSame(t *testing.T) {
	c := createConfig(options{})
	f := c.frontends.AcquireFrontend(8000, false)
	h1 := f.AcquireHost("h1")
	h2 := f.AcquireHost("h1")
	if h1 != h2 {
		t.Errorf("expected same host but was different")
	}
}

func TestClear(t *testing.T) {
	c := createConfig(options{
		mapsDir: "/tmp/maps",
	})
	f := c.frontends.AcquireFrontend(8000, false)
	_ = f.AcquireHost("app.local")
	c.Backends().AcquireBackend("default", "app", "8080")
	if c.options.mapsDir != "/tmp/maps" {
		t.Error("expected mapsDir == /tmp/maps")
	}
	if len(f.Hosts()) != 1 {
		t.Error("expected len(hosts) == 1")
	}
	if len(c.Backends().Items()) != 1 {
		t.Error("expected len(backends) == 1")
	}
	c.Clear()
	if c.options.mapsDir != "/tmp/maps" {
		t.Error("expected mapsDir == /tmp/maps")
	}
	if len(c.Frontends().Items()) != 0 {
		t.Error("expected len(Frontends) == 0")
	}
	if len(c.Backends().Items()) != 0 {
		t.Error("expected len(backends) == 0")
	}
}
