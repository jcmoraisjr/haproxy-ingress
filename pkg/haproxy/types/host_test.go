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
	"strings"
	"testing"
)

func TestCreatePathLink(t *testing.T) {
	f := (&Frontends{}).AcquireFrontend(8000, false)
	h0 := f.AcquireHost("domain.local")
	h1 := f.AcquireHost("domain1.local")
	h2 := f.AcquireHost("domain2.local")
	l1 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h0)
	l2 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h0)
	if !l1.Equals(l2) {
		t.Errorf("two distinct path links with same host and path should match")
	}
	l3 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h1)
	l4 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h2)
	if l3.Equals(l4) {
		t.Errorf("path links with distinct domains should not match")
	}
	l5 := CreatePathLink("/app1", MatchBegin).WithHTTPHost(h0)
	l6 := CreatePathLink("/app2", MatchBegin).WithHTTPHost(h0)
	if l5.Equals(l6) {
		t.Errorf("path links with distinct paths should not match")
	}
	l7 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h0)
	l7.WithHeadersMatch(HTTPHeaderMatch{
		{Name: "h1", Value: "v1", Regex: true},
	})
	l8 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h0)
	l8.WithHeadersMatch(HTTPHeaderMatch{
		{Name: "h1", Value: "v1", Regex: true},
	})
	if !l7.Equals(l8) {
		t.Errorf("path links with same headers should match")
	}
	l9 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h0)
	l9.WithHeadersMatch(HTTPHeaderMatch{
		{Name: "h1", Value: "v1", Regex: true},
	})
	l10 := CreatePathLink("/app", MatchBegin).WithHTTPHost(h0)
	l10.WithHeadersMatch(HTTPHeaderMatch{
		{Name: "h1", Value: "v2", Regex: true},
	})
	if l9.Equals(l10) {
		t.Errorf("path links with distinct headers should not match")
	}
}

func TestShrinkHosts(t *testing.T) {
	app1 := &Host{Hostname: "app1.localdomain"}
	app2 := &Host{Hostname: "app2.localdomain"}
	testCases := []struct {
		add, del       []*Host
		expAdd, expDel []*Host
	}{
		// 0
		{},
		// 1
		{
			add:    []*Host{app1},
			expAdd: []*Host{app1},
		},
		// 2
		{
			add: []*Host{app1},
			del: []*Host{app1},
		},
		// 3
		{
			add:    []*Host{app1, app2},
			del:    []*Host{app2},
			expAdd: []*Host{app1},
		},
		// 4
		{
			add:    []*Host{app1},
			del:    []*Host{app1, app2},
			expDel: []*Host{app2},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		f := (&Frontends{}).AcquireFrontend(8000, false)
		for _, add := range test.add {
			f.hostsAdd[add.Hostname] = add
		}
		for _, del := range test.del {
			f.hostsDel[del.Hostname] = del
		}
		expAdd := map[string]*Host{}
		for _, add := range test.expAdd {
			expAdd[add.Hostname] = add
		}
		expDel := map[string]*Host{}
		for _, del := range test.expDel {
			expDel[del.Hostname] = del
		}
		f.ShrinkHosts()
		c.compareObjects("add", i, f.hostsAdd, expAdd)
		c.compareObjects("del", i, f.hostsDel, expDel)
		c.teardown()
	}
}

func TestAddFindPath(t *testing.T) {
	b := CreateBackends(0)
	b1 := b.AcquireBackend("default", "b1", "8080")
	b2 := b.AcquireBackend("default", "b2", "8080")
	b3 := b.AcquireBackend("default", "b3", "8080")
	type path struct {
		backend *Backend
		path    string
		match   MatchType
	}
	testCases := []struct {
		paths     []path
		findPath  string
		findMatch []MatchType
		found     []string
	}{
		// 0
		{
			paths: []path{
				{backend: b1, path: "/", match: MatchBegin},
				{backend: b2, path: "/app", match: MatchBegin},
				{backend: b3, path: "/login", match: MatchBegin},
			},
			findPath:  "/",
			findMatch: []MatchType{MatchExact},
			found:     []string{},
		},
		// 1
		{
			paths: []path{
				{backend: b1, path: "/", match: MatchBegin},
				{backend: b2, path: "/", match: MatchExact},
				{backend: b3, path: "/login", match: MatchExact},
			},
			findPath:  "/",
			findMatch: []MatchType{MatchBegin},
			found:     []string{"b1"},
		},
		// 2
		{
			paths: []path{
				{backend: b1, path: "/", match: MatchBegin},
				{backend: b2, path: "/", match: MatchExact},
				{backend: b3, path: "/login", match: MatchExact},
			},
			findPath:  "/",
			findMatch: []MatchType{},
			found:     []string{"b1", "b2"},
		},
		// 3
		{
			paths: []path{
				{backend: b1, path: "/", match: MatchBegin},
				{backend: b2, path: "/", match: MatchBegin},
				{backend: b3, path: "/login", match: MatchBegin},
			},
			findPath:  "/",
			findMatch: []MatchType{MatchBegin},
			found:     []string{"b1", "b2"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		f := (&Frontends{}).AcquireFrontend(8000, false)
		h := f.AcquireHost("d1.local")
		for _, p := range test.paths {
			h.AddPath(p.backend, p.path, p.match)
		}
		actualFound := []string{}
		for _, p := range h.FindPath(test.findPath, test.findMatch...) {
			actualFound = append(actualFound, p.Backend.Name)
		}
		c.compareObjects("find", i, actualFound, test.found)
		c.teardown()
	}
}

func TestRemovePath(t *testing.T) {
	testCases := []struct {
		addPaths    string
		removePaths string
		expPaths    string
	}{
		// 0
		{
			addPaths:    "/app1",
			removePaths: "/app1",
			expPaths:    "",
		},
		// 1
		{
			addPaths:    "/app1,/app2",
			removePaths: "/app1",
			expPaths:    "/app2",
		},
		// 2
		{
			addPaths:    "/app1,/app2",
			removePaths: "/app2",
			expPaths:    "/app1",
		},
		// 3
		{
			addPaths:    "/app2,/app1",
			removePaths: "/app1",
			expPaths:    "/app2",
		},
		// 4
		{
			addPaths:    "/app2,/app1",
			removePaths: "/app1",
			expPaths:    "/app2",
		},
		// 5
		{
			addPaths:    "/app1,/app2",
			removePaths: "/app3",
			expPaths:    "/app1,/app2",
		},
		// 6
		{
			addPaths:    "/app1,/app2",
			removePaths: "/app1,/app2",
			expPaths:    "",
		},
	}
	for i, test := range testCases {
		c := setup(t)
		f := (&Frontends{}).AcquireFrontend(8000, false)
		b := CreateBackends(0).AcquireBackend("default", "b", "8080")
		h := f.AcquireHost("d1.local")
		for _, path := range strings.Split(test.addPaths, ",") {
			h.AddPath(b, path, MatchPrefix)
		}
		for _, path := range strings.Split(test.removePaths, ",") {
			p := h.FindPath(path)
			if len(p) == 1 {
				h.RemovePath(p[0])
			}
		}
		var paths []string
		for _, path := range h.Paths {
			paths = append(paths, path.Path())
		}
		var expected []string
		if test.expPaths != "" {
			expected = strings.Split(test.expPaths, ",")
		}
		c.compareObjects("paths", i, paths, expected)
		c.teardown()
	}
}
