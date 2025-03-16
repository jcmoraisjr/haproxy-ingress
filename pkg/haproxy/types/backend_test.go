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

package types

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestAddBackendPath(t *testing.T) {
	testCases := []struct {
		input    []string
		expected []*BackendPath
	}{
		// 0
		{
			input: []string{"/"},
			expected: []*BackendPath{
				{ID: "path01", Link: CreateHostPathLink("d1.local", "/", MatchBegin)},
			},
		},
		// 1
		{
			input: []string{"/app", "/app"},
			expected: []*BackendPath{
				{ID: "path01", Link: CreateHostPathLink("d1.local", "/app", MatchBegin)},
			},
		},
		// 2
		{
			input: []string{"/app", "/root"},
			expected: []*BackendPath{
				{ID: "path01", Link: CreateHostPathLink("d1.local", "/app", MatchBegin)},
				{ID: "path02", Link: CreateHostPathLink("d1.local", "/root", MatchBegin)},
			},
		},
		// 3
		{
			input: []string{"/app", "/root", "/root"},
			expected: []*BackendPath{
				{ID: "path01", Link: CreateHostPathLink("d1.local", "/app", MatchBegin)},
				{ID: "path02", Link: CreateHostPathLink("d1.local", "/root", MatchBegin)},
			},
		},
		// 4
		{
			input: []string{"/app", "/root", "/app"},
			expected: []*BackendPath{
				{ID: "path01", Link: CreateHostPathLink("d1.local", "/app", MatchBegin)},
				{ID: "path02", Link: CreateHostPathLink("d1.local", "/root", MatchBegin)},
			},
		},
		// 5
		{
			input: []string{"/", "/app", "/root"},
			expected: []*BackendPath{
				{ID: "path01", Link: CreateHostPathLink("d1.local", "/", MatchBegin)},
				{ID: "path02", Link: CreateHostPathLink("d1.local", "/app", MatchBegin)},
				{ID: "path03", Link: CreateHostPathLink("d1.local", "/root", MatchBegin)},
			},
		},
	}
	for i, test := range testCases {
		b := &Backend{}
		for _, p := range test.input {
			b.AddBackendPath(CreateHostPathLink("d1.local", p, MatchBegin))
		}
		if !reflect.DeepEqual(b.Paths, test.expected) {
			t.Errorf("backend.Paths differs on %d - actual: %v - expected: %v", i, b.Paths, test.expected)
		}
	}
}

func TestFillSourceIPs(t *testing.T) {
	testCases := []struct {
		name string
		ep   []string
		src  []string
		exp  []string
	}{
		// 0
		{
			name: "echoserver",
			ep:   []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"},
			exp:  []string{"", "", ""},
		},
		// 1
		{
			name: "echoserver",
			ep:   []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "", ""},
			src:  []string{"10.0.0.102", "10.0.0.103", "10.0.0.104"},
			exp:  []string{"10.0.0.104", "10.0.0.102", "10.0.0.103", "10.0.0.104", "10.0.0.102"},
		},
		// 2
		{
			name: "other",
			ep:   []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "", ""},
			src:  []string{"10.0.0.102", "10.0.0.103", "10.0.0.104"},
			exp:  []string{"10.0.0.102", "10.0.0.103", "10.0.0.104", "10.0.0.102", "10.0.0.103"},
		},
		// 3
		{
			name: "echoserver",
			ep:   []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"},
			src:  []string{"10.0.0.102"},
			exp:  []string{"10.0.0.102", "10.0.0.102", "10.0.0.102"},
		},
		// 4
		{
			name: "echoserver",
			ep:   []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"},
			src:  []string{"10.0.0.102", "10.0.0.103"},
			exp:  []string{"10.0.0.103", "10.0.0.102", "10.0.0.103"},
		},
		// 5
		{
			name: "echoserver",
			ep:   []string{"10.0.0.2", "10.0.0.3"},
			src:  []string{"10.0.0.102", "10.0.0.103", "10.0.0.104"},
			exp:  []string{"10.0.0.104", "10.0.0.102"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		b := createBackend(0, "default", test.name, "8080")
		for _, e := range test.ep {
			if e != "" {
				b.AcquireEndpoint(e, 8080, "")
			} else {
				b.AddEmptyEndpoint()
			}
		}
		for _, s := range test.src {
			b.SourceIPs = append(b.SourceIPs, net.ParseIP(s))
		}
		b.fillSourceIPs()
		var src []string
		for _, ep := range b.Endpoints {
			src = append(src, ep.SourceIP)
		}
		c.compareObjects("ip", i, src, test.exp)
		c.teardown()
	}
}

func TestCreatePathConfig(t *testing.T) {
	type pathConfig struct {
		paths  string
		config interface{}
	}
	testCases := []struct {
		paths    []*BackendPath
		filter   string
		expected map[string][]pathConfig
	}{
		// 0
		{
			filter: "SSLRedirect",
			expected: map[string][]pathConfig{
				"SSLRedirect": nil,
			},
		},
		// 1
		{
			paths:  []*BackendPath{{ID: "path1"}},
			filter: "SSLRedirect",
			expected: map[string][]pathConfig{
				"SSLRedirect": {
					{paths: "path1", config: false},
				},
			},
		},
		// 2
		{
			paths: []*BackendPath{
				{ID: "path1", HSTS: HSTS{Enabled: true, MaxAge: 10}},
				{ID: "path2", HSTS: HSTS{Enabled: true, MaxAge: 10}},
				{ID: "path3", HSTS: HSTS{Enabled: true, MaxAge: 20}},
			},
			filter: "HSTS",
			expected: map[string][]pathConfig{
				"HSTS": {
					{
						paths:  "path1,path2",
						config: HSTS{Enabled: true, MaxAge: 10},
					},
					{
						paths:  "path3",
						config: HSTS{Enabled: true, MaxAge: 20},
					},
				},
			},
		},
		// 3
		{
			paths: []*BackendPath{
				{ID: "path1", HSTS: HSTS{Enabled: true, MaxAge: 10}, AllowedIPHTTP: AccessConfig{Rule: []string{"10.0.0.0/8"}}},
				{ID: "path2", HSTS: HSTS{Enabled: true, MaxAge: 20}, AllowedIPHTTP: AccessConfig{Rule: []string{"10.0.0.0/8"}}},
				{ID: "path3", HSTS: HSTS{Enabled: true, MaxAge: 20}},
			},
			filter: "HSTS,AllowedIPHTTP",
			expected: map[string][]pathConfig{
				"HSTS": {
					{
						paths:  "path1",
						config: HSTS{Enabled: true, MaxAge: 10},
					},
					{
						paths:  "path2,path3",
						config: HSTS{Enabled: true, MaxAge: 20},
					},
				},
				"AllowedIPHTTP": {
					{
						paths:  "path1,path2",
						config: AccessConfig{Rule: []string{"10.0.0.0/8"}},
					},
					{
						paths:  "path3",
						config: AccessConfig{},
					},
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		backend := Backend{Paths: test.paths}
		actualConfig := map[string][]pathConfig{}
		for _, attr := range strings.Split(test.filter, ",") {
			config := backend.PathConfig(attr)
			pathConfigs := actualConfig[attr]
			for _, item := range config.items {
				paths := []string{}
				for _, p := range item.paths {
					paths = append(paths, p.ID)
				}
				itemConfig := item.config
				configValue := reflect.ValueOf(itemConfig)
				if configValue.Kind() == reflect.Slice && configValue.Len() == 0 {
					// empty slices and nil are semantically identical but DeepEquals disagrees
					itemConfig = nil
				}
				pathConfigs = append(pathConfigs, pathConfig{paths: strings.Join(paths, ","), config: itemConfig})
			}
			actualConfig[attr] = pathConfigs
		}
		c.compareObjects("pathconfig", i, actualConfig, test.expected)
		c.teardown()
	}
}

func TestPathIDs(t *testing.T) {
	testCases := []struct {
		paths    []string
		expected []string
	}{
		// 0
		{
			paths:    []string{},
			expected: []string{},
		},
		// 1
		{
			paths:    []string{"p1"},
			expected: []string{"p1"},
		},
		// 2
		{
			paths:    []string{"p1", "p2", "p3"},
			expected: []string{"p1 p2 p3"},
		},
		// 3
		{
			paths:    []string{"p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24", "p25", "p26", "p27", "p28", "p29"},
			expected: []string{"p01 p02 p03 p04 p05 p06 p07 p08 p09 p10 p11 p12 p13 p14 p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28 p29"},
		},
		// 4
		{
			paths:    []string{"p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24", "p25", "p26", "p27", "p28", "p29", "p30"},
			expected: []string{"p01 p02 p03 p04 p05 p06 p07 p08 p09 p10 p11 p12 p13 p14 p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28 p29 p30"},
		},
		// 5
		{
			paths:    []string{"p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12", "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24", "p25", "p26", "p27", "p28", "p29", "p30", "p31"},
			expected: []string{"p01 p02 p03 p04 p05 p06 p07 p08 p09 p10 p11 p12 p13 p14 p15 p16 p17 p18 p19 p20 p21 p22 p23 p24 p25 p26 p27 p28 p29 p30", "p31"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		paths := make([]*BackendPath, len(test.paths))
		for j, path := range test.paths {
			paths[j] = &BackendPath{ID: path}
		}
		b := BackendPathConfig{
			items: []*BackendPathItem{{paths: paths}, {}},
		}
		pathIDs := b.PathIDs(0)
		if len(pathIDs) > 0 || len(test.expected) > 0 {
			c.compareObjects("pathIDs", i, pathIDs, test.expected)
		}
		c.teardown()
	}
}

func TestEndpointDeduplication(t *testing.T) {
	c := setup(t)
	b := createBackend(0, "default", "echoserver", "8080")
	b.EpNaming = EpIPPort
	testCases := []struct {
		ip   string
		port int
		name string
	}{
		{
			ip:   "10.0.0.1",
			port: 8080,
			name: "10.0.0.1:8080",
		},
		{
			ip:   "10.0.0.2",
			port: 8080,
			name: "10.0.0.2:8080",
		},
		{
			ip:   "10.0.0.1",
			port: 8080,
			name: "10.0.0.1:8080__2",
		},
		{
			ip:   "10.0.0.1",
			port: 8080,
			name: "10.0.0.1:8080__3",
		},
		{
			ip:   "10.0.0.2",
			port: 8080,
			name: "10.0.0.2:8080__2",
		},
		{
			ip:   "10.0.0.3",
			port: 8080,
			name: "10.0.0.3:8080",
		},
	}
	for i, test := range testCases {
		ep := b.AddEndpoint(test.ip, test.port, "")
		c.compareObjects("ep", i, ep.Name, test.name)
	}
	c.compareObjects("len(ep)", 0, len(b.Endpoints), 6)
	c.teardown()
}
