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
	"reflect"
	"strings"
	"testing"
)

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
		hm := CreateMaps().AddMap(test.filename)
		hm.AddHostnameMapping(test.hostname, "backend")
		values := hm.values[test.expmatch]
		if len(values) != 1 {
			t.Errorf("item %d, invalid match or value: %v", i, hm.values)
			continue
		}
		if values[0].Key != test.expected {
			t.Errorf("item %d, expected key '%s' but was '%s'", i, test.expected, values[0].Key)
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
			expected: "example.local/",
		},
		// 1
		{
			hostname: "*.example.local",
			path:     "/",
			match:    MatchBegin,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local/",
		},
		// 2
		{
			hostname: "*.example.local",
			path:     "/path",
			match:    MatchBegin,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local/path",
		},
		// 3
		{
			hostname: "example.local",
			path:     "/path",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^example\\.local/path$",
		},
		// 4
		{
			hostname: "example.local",
			path:     "/path[0-9]",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^example\\.local/path[0-9]$",
		},
		// 5
		{
			hostname: "example.local",
			path:     "/path/.*",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^example\\.local/path/.*$",
		},
		// 6
		{
			hostname: "*.example.local",
			path:     "/.*path",
			match:    MatchRegex,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local/.*path$",
		},
		// 7
		{
			hostname: "example.local",
			path:     "/path",
			match:    MatchPrefix,
			expmatch: MatchPrefix,
			expected: "example.local/path",
		},
		// 8
		{
			hostname: "*.example.local",
			path:     "/path.new",
			match:    MatchPrefix,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local/path\\.new(/.*)?$",
		},
		// 9
		{
			hostname: "*.example.local",
			path:     "/path/",
			match:    MatchPrefix,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local/path/",
		},
		// 10
		{
			hostname: "example.local",
			path:     "/path",
			match:    MatchExact,
			expmatch: MatchExact,
			expected: "example.local/path",
		},
		// 11
		{
			hostname: "*.example.local",
			path:     "/path",
			match:    MatchExact,
			expmatch: MatchRegex,
			expected: "^[^.]+\\.example\\.local/path$",
		},
	}
	for i, test := range testCases {
		hm := CreateMaps().AddMap(test.filename)
		hostPath := &HostPath{
			Path:  test.path,
			Match: test.match,
		}
		hm.AddHostnamePathMapping(test.hostname, hostPath, "backend")
		values := hm.values[test.expmatch]
		if len(values) != 1 {
			t.Errorf("item %d, invalid match or value: %v", i, hm.values)
			continue
		}
		if values[0].Key != test.expected {
			t.Errorf("item %d, expected key '%s' but was '%s'", i, test.expected, values[0].Key)
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
				MatchBegin: {"example.local/"},
			},
		},
		// 1
		{
			aliasName: "*.example.local",
			path:      "/",
			match:     MatchBegin,
			expected: map[MatchType][]string{
				MatchRegex: {"^[^.]+\\.example\\.local/"},
			},
		},
		// 2
		{
			aliasRegex: ".*\\.local",
			path:       "/",
			match:      MatchBegin,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local/"},
			},
		},
		// 3
		{
			aliasRegex: ".*\\.local",
			path:       "/",
			match:      MatchExact,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local/$"},
			},
		},
		// 4
		{
			aliasRegex: ".*\\.local",
			path:       "/",
			match:      MatchPrefix,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local/"},
			},
		},
		// 5
		{
			aliasRegex: ".*\\.local",
			path:       "/path",
			match:      MatchPrefix,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local/path(/.*)?$"},
			},
		},
		// 6
		{
			aliasRegex: ".*\\.local",
			path:       "/path/",
			match:      MatchPrefix,
			expected: map[MatchType][]string{
				MatchRegex: {"^.*\\.local/path/"},
			},
		},
		// 7
		{
			aliasName:  "example.local",
			aliasRegex: ".*\\.local",
			path:       "/path",
			match:      MatchBegin,
			expected: map[MatchType][]string{
				MatchBegin: {"example.local/path"},
				MatchRegex: {"^.*\\.local/path"},
			},
		},
	}
	for i, test := range testCases {
		hm := CreateMaps().AddMap(test.filename)
		hostPath := &HostPath{
			Path:  test.path,
			Match: test.match,
		}
		backend := "backend"
		alias := HostAliasConfig{
			AliasName:  test.aliasName,
			AliasRegex: test.aliasRegex,
		}
		hm.AddAliasPathMapping(alias, hostPath, backend)
		expvalues := map[MatchType][]*HostsMapEntry{}
		for match := range test.expected {
			for _, key := range test.expected[match] {
				uri := strings.SplitN(key, "/", 2)
				expvalues[match] = append(expvalues[match], &HostsMapEntry{
					hostname: uri[0],
					path:     "/" + uri[1],
					Key:      key,
					Value:    backend,
				})
			}
		}
		if !reflect.DeepEqual(hm.values, expvalues) {
			t.Errorf("item %d, expected values '%v' but was '%v'", i, expvalues, hm.values)
			continue
		}
	}
}
