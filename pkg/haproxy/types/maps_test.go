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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
)

var matchOrder = []MatchType{MatchExact, MatchPrefix, MatchBegin, MatchRegex}

func TestAddHostnameMapping(t *testing.T) {
	testCases := []struct {
		filename string
		hostname string
		expmatch MatchType
		expected string
	}{
		// 0
		{
			hostname: "example.Local",
			expmatch: MatchExact,
			expected: "example.local",
		},
		// 1
		{
			hostname: "Example.Local",
			expmatch: MatchExact,
			expected: "example.local",
		},
		// 2
		{
			hostname: "*.example.Local",
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local$",
		},
		// 3
		{
			hostname: "*.Example.Local",
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local$",
		},
	}
	for i, test := range testCases {
		hm := CreateMaps(matchOrder).AddMap(test.filename)
		hm.AddHostnameMapping(test.hostname, "backend")
		entries := hm.rawfiles[test.expmatch].entries
		if len(entries) != 1 {
			t.Errorf("item %d, invalid match or value: %v", i, hm.rawfiles)
			continue
		}
		if entries[0].Key != test.expected {
			t.Errorf("item %d, expected key '%s' but was '%s'", i, test.expected, entries[0].Key)
			continue
		}
	}
}

func TestAddHostnamePathMapping(t *testing.T) {
	testCases := []struct {
		filename string
		hostname string
		path     string
		match    MatchType
		expmatch MatchType
		expected string
	}{
		// 0
		{
			hostname: "example.local",
			path:     "/",
			match:    MatchBegin,
			expmatch: MatchBegin,
			expected: "example.local#/",
		},
		// 1
		{
			hostname: "*.example.local",
			path:     "/",
			match:    MatchBegin,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local#/",
		},
		// 2
		{
			hostname: "*.example.local",
			path:     "/path",
			match:    MatchBegin,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local#/path",
		},
		// 3
		{
			hostname: "example.local",
			path:     "/path",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^example\\.local#/path",
		},
		// 4
		{
			hostname: "example.local",
			path:     "/path[0-9]$",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^example\\.local#/path[0-9]$",
		},
		// 5
		{
			hostname: "example.local",
			path:     "/path/",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^example\\.local#/path/",
		},
		// 6
		{
			hostname: "*.example.local",
			path:     "/.*path$",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local#/.*path$",
		},
		// 7
		{
			hostname: "example.local",
			path:     "/path",
			match:    MatchPrefix,
			expmatch: MatchPrefix,
			expected: "example.local#/path",
		},
		// 8
		{
			hostname: "*.example.local",
			path:     "/path.new",
			match:    MatchPrefix,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local#/path\\.new(/.*)?",
		},
		// 9
		{
			hostname: "*.example.local",
			path:     "/path/",
			match:    MatchPrefix,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local#/path/",
		},
		// 10
		{
			hostname: "example.local",
			path:     "/path",
			match:    MatchExact,
			expmatch: MatchExact,
			expected: "example.local#/path",
		},
		// 11
		{
			hostname: "*.example.local",
			path:     "/path",
			match:    MatchExact,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local#/path$",
		},
	}
	for i, test := range testCases {
		hm := CreateMaps(matchOrder).AddMap(test.filename)
		path := &Path{
			Link: CreatePathLink(test.path, test.match),
		}
		hm.AddHostnamePathMapping(test.hostname, path, "backend")
		entries := hm.rawfiles[test.expmatch].entries
		if len(entries) != 1 {
			t.Errorf("item %d, invalid match or value: %v", i, hm.rawfiles)
			continue
		}
		if entries[0].Key != test.expected {
			t.Errorf("item %d, expected key '%s' but was '%s'", i, test.expected, entries[0].Key)
			continue
		}
	}
}

func TestAddAliasPathMapping(t *testing.T) {
	testCases := []struct {
		filename   string
		aliasName  string
		aliasRegex string
		path       string
		match      MatchType
		expected   map[MatchType][]string
	}{
		// 0
		{
			aliasName: "example.local",
			path:      "/",
			match:     MatchBegin,
			expected: map[MatchType][]string{
				MatchBegin: {"example.local#/"},
			},
		},
		// 1
		{
			aliasName: "*.example.local",
			path:      "/",
			match:     MatchBegin,
			expected: map[MatchType][]string{
				MatchRegex: {"^[^.]+\\.example\\.local#/"},
			},
		},
		// 2
		{
			aliasRegex: ".*\\.local",
			path:       "/",
			match:      MatchBegin,
			expected: map[MatchType][]string{
				MatchRegex: {".*\\.local[^/]*#/"},
			},
		},
		// 3
		{
			aliasRegex: "^.*\\.local",
			path:       "/",
			match:      MatchExact,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local[^/]*#/$"},
			},
		},
		// 4
		{
			aliasRegex: "^.*\\.local$",
			path:       "/",
			match:      MatchPrefix,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local#/"},
			},
		},
		// 5
		{
			aliasRegex: "\\.local$",
			path:       "/path",
			match:      MatchPrefix,
			expected: map[MatchType][]string{
				MatchRegex: {"\\.local#/path(/.*)?"},
			},
		},
		// 6
		{
			aliasRegex: "^.*\\.local$",
			path:       "/path/",
			match:      MatchPrefix,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local#/path/"},
			},
		},
		// 7
		{
			aliasName:  "example.local",
			aliasRegex: "\\.local$",
			path:       "/path",
			match:      MatchBegin,
			expected: map[MatchType][]string{
				MatchBegin: {"example.local#/path"},
				MatchRegex: {"\\.local#/path"},
			},
		},
	}
	for i, test := range testCases {
		hm := CreateMaps(matchOrder).AddMap(test.filename)
		path := &Path{
			Link: CreatePathLink(test.path, test.match),
		}
		alias := HostAliasConfig{
			AliasName:  test.aliasName,
			AliasRegex: test.aliasRegex,
		}
		hm.AddAliasPathMapping(alias, path, "backend")
		actual := map[MatchType][]string{}
		for match := range hm.rawfiles {
			for _, entry := range hm.rawfiles[match].entries {
				actual[match] = append(actual[match], entry.Key)
			}
		}
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("item %d, expected values '%v' but was '%v'", i, test.expected, actual)
			continue
		}
	}
}

func TestOverlap(t *testing.T) {
	type data struct {
		hostname string
		path     string
		match    MatchType
		headers  HTTPHeaderMatch
		target   string
	}
	testCases := []struct {
		data     []data
		expected string
	}{
		// 0
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local1.tld", path: "/ab", match: MatchBegin},
			},
			expected: `
hosts__begin.map first:true,lower:true,method:beg
local1.tld /ab begin
local1.tld /a begin
`,
		},
		// 1
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local1.tld", path: "/ab", match: MatchPrefix},
			},
			expected: `
hosts__prefix_01.map first:true,lower:false,method:dir
local1.tld /ab prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin
`,
		},
		// 2
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local1.tld", path: "/ab.*", match: MatchRegex},
			},
			expected: `
hosts__begin.map first:true,lower:true,method:beg
local1.tld /a begin

hosts__regex.map first:false,lower:false,method:reg
^local1\.tld$ /ab.* regex
`,
		},
		// 3
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local2.tld", path: "/ab", match: MatchPrefix},
			},
			expected: `
hosts__prefix.map first:true,lower:false,method:dir
local2.tld /ab prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin
`,
		},
		// 4
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local1.tld", path: "/abc", match: MatchBegin},
				{hostname: "local1.tld", path: "/ab", match: MatchPrefix},
				{hostname: "local2.tld", path: "/a", match: MatchExact},
			},
			expected: `
hosts__exact.map first:true,lower:false,method:str
local2.tld /a exact

hosts__begin_02.map first:false,lower:true,method:beg
local1.tld /abc begin

hosts__prefix_03.map first:false,lower:false,method:dir
local1.tld /ab prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin
`,
		},
		// 5
		{
			data: []data{
				{hostname: "local1.tld", path: "/abc", match: MatchBegin},
				{hostname: "local1.tld", path: "/ab", match: MatchPrefix},
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local2.tld", path: "/a", match: MatchExact},
				{hostname: "local2.tld", path: "/abc", match: MatchExact},
				{hostname: "local2.tld", path: "/ab", match: MatchExact},
			},
			expected: `
hosts__exact.map first:true,lower:false,method:str
local2.tld /a exact
local2.tld /ab exact
local2.tld /abc exact

hosts__begin_02.map first:false,lower:true,method:beg
local1.tld /abc begin

hosts__prefix_03.map first:false,lower:false,method:dir
local1.tld /ab prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin
`,
		},
		// 6
		{
			data: []data{
				{hostname: "local1.tld", path: "/abc", match: MatchBegin},
				{hostname: "local1.tld", path: "/ab", match: MatchPrefix},
				{hostname: "local1.tld", path: "/abcd", match: MatchExact},
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
			},
			expected: `
hosts__exact.map first:true,lower:false,method:str
local1.tld /abcd exact

hosts__begin_02.map first:false,lower:true,method:beg
local1.tld /abc begin

hosts__prefix_03.map first:false,lower:false,method:dir
local1.tld /ab prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin
`,
		},
		// 7
		{
			data: []data{
				{hostname: "local1.tld", path: "/ab", match: MatchPrefix},
				{hostname: "local1.tld", path: "/abc", match: MatchBegin},
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local1.tld", path: "/abcd", match: MatchExact},
			},
			expected: `
hosts__exact.map first:true,lower:false,method:str
local1.tld /abcd exact

hosts__begin_02.map first:false,lower:true,method:beg
local1.tld /abc begin

hosts__prefix_03.map first:false,lower:false,method:dir
local1.tld /ab prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin
`,
		},
		// 8
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchPrefix},
				{hostname: "local1.tld", path: "/", match: MatchBegin},
				{hostname: "local2.tld", path: "/a", match: MatchPrefix},
				{hostname: "local2.tld", path: "/", match: MatchBegin},
				{hostname: "local3.tld", path: "/a", match: MatchPrefix},
				{hostname: "local4.tld", path: "/a", match: MatchPrefix},
				{hostname: "local4.tld", path: "/", match: MatchBegin},
			},
			expected: `
hosts__prefix_01.map first:true,lower:false,method:dir
local1.tld /a prefix
local2.tld /a prefix
local4.tld /a prefix

hosts__prefix.map first:false,lower:false,method:dir
local3.tld /a prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld / begin
local2.tld / begin
local4.tld / begin
`,
		},
		// 9
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchPrefix},
				{hostname: "local2.tld", path: "/a", match: MatchPrefix},
				{hostname: "local2.tld", path: "/", match: MatchBegin},
				{hostname: "local3.tld", path: "/a", match: MatchPrefix},
				{hostname: "local3.tld", path: "/", match: MatchBegin},
				{hostname: "local4.tld", path: "/a", match: MatchPrefix},
				{hostname: "local4.tld", path: "/", match: MatchBegin},
			},
			expected: `
hosts__prefix_01.map first:true,lower:false,method:dir
local2.tld /a prefix
local3.tld /a prefix
local4.tld /a prefix

hosts__prefix.map first:false,lower:false,method:dir
local1.tld /a prefix

hosts__begin.map first:false,lower:true,method:beg
local2.tld / begin
local3.tld / begin
local4.tld / begin
`,
		},
		// 10
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchPrefix},
				{hostname: "local1.tld", path: "/", match: MatchBegin},
				{hostname: "local2.tld", path: "/a", match: MatchPrefix},
				{hostname: "local2.tld", path: "/", match: MatchBegin},
				{hostname: "local3.tld", path: "/a", match: MatchPrefix},
				{hostname: "local3.tld", path: "/", match: MatchBegin},
				{hostname: "local4.tld", path: "/a", match: MatchPrefix},
			},
			expected: `
hosts__prefix_01.map first:true,lower:false,method:dir
local1.tld /a prefix
local2.tld /a prefix
local3.tld /a prefix

hosts__prefix.map first:false,lower:false,method:dir
local4.tld /a prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld / begin
local2.tld / begin
local3.tld / begin
`,
		},
		// 11
		{
			data: []data{
				{hostname: "local1.tld", path: "/a", match: MatchRegex},
				{hostname: "local1.tld", path: "/a", match: MatchBegin},
				{hostname: "local1.tld", path: "/a", match: MatchPrefix},
				{hostname: "local1.tld", path: "/a", match: MatchExact},
			},
			expected: `
hosts__exact.map first:true,lower:false,method:str
local1.tld /a exact

hosts__prefix.map first:false,lower:false,method:dir
local1.tld /a prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a begin

hosts__regex.map first:false,lower:false,method:reg
^local1\.tld$ /a regex
`,
		},
		// 12
		{
			data: []data{
				{hostname: "local1.tld", path: "/a3", match: MatchExact, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a2", match: MatchExact},
				{hostname: "local1.tld", path: "/a1", match: MatchExact, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a0", match: MatchExact},
			},
			expected: `
hosts__exact_01.map first:true,lower:false,method:str headers=['x-user':'myname1',regex:false]
local1.tld /a1 exact
local1.tld /a3 exact

hosts__exact.map first:false,lower:false,method:str
local1.tld /a0 exact
local1.tld /a2 exact
`,
		},
		// 13
		{
			data: []data{
				{hostname: "local1.tld", path: "/a3", match: MatchExact, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a2", match: MatchExact, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a1", match: MatchExact},
				{hostname: "local1.tld", path: "/a0", match: MatchExact},
			},
			expected: `
hosts__exact_01.map first:true,lower:false,method:str headers=['x-user':'myname1',regex:false]
local1.tld /a2 exact
local1.tld /a3 exact

hosts__exact.map first:false,lower:false,method:str
local1.tld /a0 exact
local1.tld /a1 exact
`,
		},
		// 14
		{
			data: []data{
				{hostname: "local1.tld", path: "/a3", match: MatchExact},
				{hostname: "local1.tld", path: "/a2", match: MatchExact},
				{hostname: "local1.tld", path: "/a1", match: MatchExact, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a0", match: MatchExact, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname2"}}},
			},
			expected: `
hosts__exact_01.map first:true,lower:false,method:str headers=['x-user':'myname2',regex:false]
local1.tld /a0 exact

hosts__exact_02.map first:false,lower:false,method:str headers=['x-user':'myname1',regex:false]
local1.tld /a1 exact

hosts__exact.map first:false,lower:false,method:str
local1.tld /a2 exact
local1.tld /a3 exact
`,
		},
		// 15
		{
			data: []data{
				{hostname: "local1.tld", path: "/a3", match: MatchBegin},
				{hostname: "local1.tld", path: "/a2", match: MatchPrefix},
				{hostname: "local1.tld", path: "/a1", match: MatchBegin, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a0", match: MatchPrefix, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
			},
			expected: `
hosts__begin_01.map first:true,lower:true,method:beg headers=['x-user':'myname1',regex:false]
local1.tld /a1 begin

hosts__prefix_02.map first:false,lower:false,method:dir headers=['x-user':'myname1',regex:false]
local1.tld /a0 prefix

hosts__prefix.map first:false,lower:false,method:dir
local1.tld /a2 prefix

hosts__begin.map first:false,lower:true,method:beg
local1.tld /a3 begin
`,
		},
		// 16
		{
			data: []data{
				{hostname: "local1.tld", path: "/a0", match: MatchPrefix, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
			},
			expected: `
hosts__prefix_01.map first:true,lower:false,method:dir headers=['x-user':'myname1',regex:false]
local1.tld /a0 prefix
`,
		},
		// 17
		{
			data: []data{
				{hostname: "local1.tld", path: "/a2", match: MatchPrefix, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname2"}}},
				{hostname: "local1.tld", path: "/a1", match: MatchPrefix, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
				{hostname: "local1.tld", path: "/a0", match: MatchPrefix, headers: HTTPHeaderMatch{{Name: "x-user", Value: "myname1"}}},
			},
			expected: `
hosts__prefix_01.map first:true,lower:false,method:dir headers=['x-user':'myname1',regex:false]
local1.tld /a1 prefix
local1.tld /a0 prefix

hosts__prefix_02.map first:false,lower:false,method:dir headers=['x-user':'myname2',regex:false]
local1.tld /a2 prefix
`,
		},
	}
	for i, test := range testCases {
		hm := CreateMaps(matchOrder).AddMap("hosts.map")
		for _, item := range test.data {
			if item.path == "" {
				hm.AddHostnameMapping(item.hostname, item.target)
			} else {
				hm.AddHostnamePathMapping(item.hostname, &Path{Link: CreatePathLink(item.path, item.match).WithHeadersMatch(item.headers)}, item.target)
			}
		}
		var output string
		for _, m := range hm.MatchFiles() {
			output += fmt.Sprintf("\n%s first:%t,lower:%t,method:%s", m.Filename(), m.First(), m.Lower(), m.Method())
			if m.Headers() != nil {
				output += " headers=["
				for _, v := range m.Headers() {
					output += fmt.Sprintf("'%s':'%s',regex:%t;", v.Name, v.Value, v.Regex)
				}
				output = strings.TrimRight(output, ";") + "]"
			}
			for _, v := range m.Values() {
				output += fmt.Sprintf("\n%s %s %s", v.hostname, v.path, v.match)
			}
			output += "\n"
		}
		if output != test.expected {
			t.Errorf("item %d: \n%s", i, diff.Diff(test.expected, output))
		}
	}
}
