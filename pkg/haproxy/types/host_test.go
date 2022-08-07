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
	l1 := CreatePathLink("domain.local", "/app", MatchBegin)
	l2 := CreatePathLink("domain.local", "/app", MatchBegin)
	if l1 != l2 {
		t.Errorf("two distinct path links with same host and path should match")
	}
	l3 := CreatePathLink("domain1.local", "/app", MatchBegin)
	l4 := CreatePathLink("domain2.local", "/app", MatchBegin)
	if l3 == l4 {
		t.Errorf("path links with distinct domains should not match")
	}
	l5 := CreatePathLink("domain.local", "/app1", MatchBegin)
	l6 := CreatePathLink("domain.local", "/app2", MatchBegin)
	if l5 == l6 {
		t.Errorf("path links with distinct paths should not match")
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
		h := CreateHosts()
		for _, add := range test.add {
			h.itemsAdd[add.Hostname] = add
		}
		for _, del := range test.del {
			h.itemsDel[del.Hostname] = del
		}
		expAdd := map[string]*Host{}
		for _, add := range test.expAdd {
			expAdd[add.Hostname] = add
		}
		expDel := map[string]*Host{}
		for _, del := range test.expDel {
			expDel[del.Hostname] = del
		}
		h.Shrink()
		c.compareObjects("add", i, h.itemsAdd, expAdd)
		c.compareObjects("del", i, h.itemsDel, expDel)
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
		order     []string
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
			order:     []string{"b3", "b2", "b1"},
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
			order:     []string{"b3", "b1", "b2"},
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
			order:     []string{"b3", "b1", "b2"},
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
			order:     []string{"b3", "b1", "b2"},
			findPath:  "/",
			findMatch: []MatchType{MatchBegin},
			found:     []string{"b1", "b2"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		h := CreateHosts().AcquireHost("d1.local")
		for _, p := range test.paths {
			h.AddPath(p.backend, p.path, p.match)
		}
		actualOrder := []string{}
		for _, p := range h.Paths {
			actualOrder = append(actualOrder, p.Backend.Name)
		}
		actualFound := []string{}
		for _, p := range h.FindPath(test.findPath, test.findMatch...) {
			actualFound = append(actualFound, p.Backend.Name)
		}
		c.compareObjects("order", i, actualOrder, test.order)
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
			expPaths:    "/app2,/app1",
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
		b := CreateBackends(0).AcquireBackend("default", "b", "8080")
		h := CreateHosts().AcquireHost("d1.local")
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
