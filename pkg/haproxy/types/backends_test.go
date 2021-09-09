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
	"sort"
	"strings"
	"testing"
)

func TestBackendCrud(t *testing.T) {
	testCases := []struct {
		shardCnt  int
		add       []string
		del       []string
		expected  []string
		expAdd    []string
		expDel    []string
		expShards [][]string
	}{
		// 0
		{},
		// 1
		{
			add:      []string{"default_app_8080"},
			expected: []string{"default_app_8080"},
			expAdd:   []string{"default_app_8080"},
		},
		// 2
		{
			add:    []string{"default_app_8080"},
			del:    []string{"default_app_8080"},
			expAdd: []string{"default_app_8080"},
			expDel: []string{"default_app_8080"},
		},
		// 3
		{
			add:      []string{"default_app1_8080", "default_app2_8080"},
			del:      []string{"default_app1_8080"},
			expected: []string{"default_app2_8080"},
			expAdd:   []string{"default_app1_8080", "default_app2_8080"},
			expDel:   []string{"default_app1_8080"},
		},
		// 4
		{
			shardCnt: 3,
			add:      []string{"default_app1_8080", "default_app2_8080", "default_app3_8080", "default_app4_8080"},
			expected: []string{"default_app1_8080", "default_app2_8080", "default_app3_8080", "default_app4_8080"},
			expAdd:   []string{"default_app1_8080", "default_app2_8080", "default_app3_8080", "default_app4_8080"},
			expShards: [][]string{
				{"default_app2_8080"},
				{"default_app1_8080", "default_app4_8080"},
				{"default_app3_8080"},
			},
		},
		// 5
		{
			shardCnt: 3,
			add:      []string{"default_app1_8080", "default_app2_8080", "default_app3_8080", "default_app4_8080"},
			del:      []string{"default_app1_8080", "default_app2_8080"},
			expected: []string{"default_app3_8080", "default_app4_8080"},
			expAdd:   []string{"default_app1_8080", "default_app2_8080", "default_app3_8080", "default_app4_8080"},
			expDel:   []string{"default_app1_8080", "default_app2_8080"},
			expShards: [][]string{
				{},
				{"default_app4_8080"},
				{"default_app3_8080"},
			},
		},
	}
	toarray := func(items map[string]*Backend) []string {
		if len(items) == 0 {
			return nil
		}
		result := make([]string, len(items))
		var i int
		for item := range items {
			result[i] = item
			i++
		}
		sort.Strings(result)
		return result
	}
	for i, test := range testCases {
		c := setup(t)
		backends := CreateBackends(test.shardCnt)
		for _, add := range test.add {
			p := strings.Split(add, "_")
			backends.AcquireBackend(p[0], p[1], p[2])
		}
		var backendIDs []string
		for _, del := range test.del {
			p := strings.Split(del, "_")
			if b := backends.FindBackend(p[0], p[1], p[2]); b != nil {
				backendIDs = append(backendIDs, b.ID)
			}
		}
		backends.RemoveAll(backendIDs)
		c.compareObjects("items", i, toarray(backends.items), test.expected)
		c.compareObjects("itemsAdd", i, toarray(backends.itemsAdd), test.expAdd)
		c.compareObjects("itemsDel", i, toarray(backends.itemsDel), test.expDel)
		var shards [][]string
		for _, shard := range backends.shards {
			names := []string{}
			for name := range shard {
				names = append(names, name)
			}
			sort.Strings(names)
			shards = append(shards, names)
		}
		c.compareObjects("shards", i, shards, test.expShards)
		c.teardown()
	}
}

func TestAcquireAuthBackend(t *testing.T) {
	type bk struct {
		iplist   []string
		port     int
		hostname string
	}
	testCases := []struct {
		backends []bk
		expBack  map[string]string
	}{
		// 0
		{
			backends: []bk{
				{iplist: []string{"10.0.0.1", "10.0.0.2"}, port: 8080},
			},
			expBack: map[string]string{
				"10.0.0.1,10.0.0.2:8080:": "_auth_backend001_8080",
			},
		},
		// 1
		{
			backends: []bk{
				{iplist: []string{"10.0.0.1"}, port: 8080},
				{iplist: []string{"10.0.0.1"}, port: 8081},
			},
			expBack: map[string]string{
				"10.0.0.1:8080:": "_auth_backend001_8080",
				"10.0.0.1:8081:": "_auth_backend002_8081",
			},
		},
		// 2
		{
			backends: []bk{
				{iplist: []string{"10.0.0.1"}, port: 8080},
				{iplist: []string{"10.0.0.2"}, port: 8080},
				{iplist: []string{"10.0.0.1"}, port: 8080},
			},
			expBack: map[string]string{
				"10.0.0.1:8080:": "_auth_backend001_8080",
				"10.0.0.2:8080:": "_auth_backend002_8080",
			},
		},
		// 3
		{
			backends: []bk{
				{iplist: []string{"10.0.0.1"}, port: 8080},
				{iplist: []string{"10.0.0.2"}, port: 8080},
				{iplist: []string{"10.0.0.1"}, port: 8080, hostname: "app1.local"},
			},
			expBack: map[string]string{
				"10.0.0.1:8080:":           "_auth_backend001_8080",
				"10.0.0.2:8080:":           "_auth_backend002_8080",
				"10.0.0.1:8080:app1.local": "_auth_backend003_8080",
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		backends := CreateBackends(0)
		for _, b := range test.backends {
			_ = backends.AcquireAuthBackend(b.iplist, b.port, b.hostname)
		}
		actual := map[string]string{}
		for n, b := range backends.authBackends {
			actual[n] = b.ID
		}
		c.compareObjects("auth backend", i, actual, test.expBack)
		c.teardown()
	}
}

func TestShrinkBackends(t *testing.T) {
	ep0 := &Endpoint{IP: "127.0.0.1"}
	ep11 := &Endpoint{IP: "192.168.0.11"}
	ep21 := &Endpoint{IP: "192.168.0.21"}
	app11 := &Backend{Name: "default_app1_8080", Endpoints: []*Endpoint{ep11}}
	app12 := &Backend{Name: "default_app1_8080", Endpoints: []*Endpoint{ep11, ep0}}
	app21 := &Backend{Name: "default_app2_8080", Endpoints: []*Endpoint{ep21}}
	testCases := []struct {
		add, del       []*Backend
		expAdd, expDel []*Backend
	}{
		// 0
		{},
		// 1
		{
			add:    []*Backend{app11},
			expAdd: []*Backend{app11},
		},
		// 2
		{
			add: []*Backend{app11},
			del: []*Backend{app11},
		},
		// 3
		{
			add:    []*Backend{app11, app21},
			del:    []*Backend{app21},
			expAdd: []*Backend{app11},
		},
		// 4
		{
			add:    []*Backend{app11},
			del:    []*Backend{app11, app21},
			expDel: []*Backend{app21},
		},
		// 5
		{
			add: []*Backend{app11},
			del: []*Backend{app12},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		b := CreateBackends(0)
		for _, add := range test.add {
			b.itemsAdd[add.Name] = add
		}
		for _, del := range test.del {
			b.itemsDel[del.Name] = del
		}
		expAdd := map[string]*Backend{}
		for _, add := range test.expAdd {
			expAdd[add.Name] = add
		}
		expDel := map[string]*Backend{}
		for _, del := range test.expDel {
			expDel[del.Name] = del
		}
		b.Shrink()
		c.compareObjects("add", i, b.itemsAdd, expAdd)
		c.compareObjects("del", i, b.itemsDel, expDel)
		c.teardown()
	}
}

func TestBackendsMatch(t *testing.T) {
	ep0_1 := &Endpoint{IP: "127.0.0.1"}
	ep0_2 := &Endpoint{IP: "127.0.0.1"}
	ep1_1 := &Endpoint{IP: "192.168.0.1"}
	ep1_2 := &Endpoint{IP: "192.168.0.1"}
	ep2_1 := &Endpoint{IP: "192.168.0.2"}
	ep2_2 := &Endpoint{IP: "192.168.0.2"}
	testCases := []struct {
		back1, back2 *Backend
		expected     bool
	}{
		// 0
		{
			expected: true,
		},
		// 1
		{
			back1:    &Backend{},
			back2:    &Backend{},
			expected: true,
		},
		// 2
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep0_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep0_2}},
			expected: true,
		},
		// 3
		{
			back1:    &Backend{CustomConfig: []string{"http-request"}, Endpoints: []*Endpoint{ep0_1}},
			back2:    &Backend{CustomConfig: []string{"http-response"}, Endpoints: []*Endpoint{ep0_2}},
			expected: false,
		},
		// 4
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep0_1, ep1_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep0_2, ep1_2}},
			expected: true,
		},
		// 5
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep0_1, ep1_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep0_2, ep2_2}},
			expected: false,
		},
		// 6
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep0_1, ep1_1, ep2_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep0_2, ep2_2, ep1_2}},
			expected: true,
		},
		// 7
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep2_1, ep1_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep1_2, ep2_2}},
			expected: true,
		},
		// 8
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep2_1, ep0_1, ep1_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep1_2, ep2_2, ep0_2}},
			expected: true,
		},
		// 9
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep2_1, ep0_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep1_2, ep2_2, ep0_2}},
			expected: false,
		},
		// 10
		{
			back1:    &Backend{Endpoints: []*Endpoint{ep2_1, ep0_1, ep1_1}},
			back2:    &Backend{Endpoints: []*Endpoint{ep1_2, ep0_2}},
			expected: false,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		result := backendsMatch(test.back1, test.back2)
		c.compareObjects("match", i, result, test.expected)
		c.teardown()
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

func BenchmarkBuildIDFmt(b *testing.B) {
	namespace := "default"
	name := "app"
	port := "8080"
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("%s_%s_%s", namespace, name, port)
	}
}

func BenchmarkBuildIDConcat(b *testing.B) {
	namespace := "default"
	name := "app"
	port := "8080"
	for i := 0; i < b.N; i++ {
		_ = namespace + "_" + name + "_" + port
	}
}
