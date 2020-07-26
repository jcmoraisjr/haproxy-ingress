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
	"testing"
)

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
