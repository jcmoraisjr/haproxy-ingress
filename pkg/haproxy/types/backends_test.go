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
		var backendIDs []BackendID
		for _, del := range test.del {
			p := strings.Split(del, "_")
			if b := backends.FindBackend(p[0], p[1], p[2]); b != nil {
				backendIDs = append(backendIDs, b.BackendID())
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
