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
	"reflect"
	"sort"
	"testing"
)

func TestBuildAcmeStorages(t *testing.T) {
	testCases := []struct {
		certs    [][]string
		expected []string
	}{
		// 0
		{
			certs: [][]string{
				{"cert1", "d1.local"},
			},
			expected: []string{
				"cert1,d1.local",
			},
		},
		// 1
		{
			certs: [][]string{
				{"cert1", "d1.local", "d2.local"},
				{"cert1", "d2.local", "d3.local"},
			},
			expected: []string{
				"cert1,d1.local,d2.local,d3.local",
			},
		},
		// 2
		{
			certs: [][]string{
				{"cert1", "d1.local", "d2.local"},
				{"cert2", "d2.local", "d3.local"},
			},
			expected: []string{
				"cert1,d1.local,d2.local",
				"cert2,d2.local,d3.local",
			},
		},
	}
	for i, test := range testCases {
		acme := AcmeData{}
		for _, cert := range test.certs {
			acme.Storages().Acquire(cert[0]).AddDomains(cert[1:])
		}
		storages := acme.Storages().BuildAcmeStorages()
		sort.Strings(storages)
		if !reflect.DeepEqual(storages, test.expected) {
			t.Errorf("acme certs differs on %d - expected: %+v, actual: %+v", i, test.expected, storages)
		}
	}
}

func TestShrink(t *testing.T) {
	d1 := map[string]struct{}{"d1.local": {}}
	d2 := map[string]struct{}{"d2.local": {}}
	testCases := []struct {
		itemAdd, itemDel map[string]*AcmeCerts
		expAdd, expDel   map[string]*AcmeCerts
	}{
		// 0
		{
			expAdd: map[string]*AcmeCerts{},
			expDel: map[string]*AcmeCerts{},
		},
		// 1
		{
			itemAdd: map[string]*AcmeCerts{"cert1": {d1}},
			expAdd:  map[string]*AcmeCerts{"cert1": {d1}},
			expDel:  map[string]*AcmeCerts{},
		},
		// 2
		{
			itemAdd: map[string]*AcmeCerts{"cert1": {d1}},
			itemDel: map[string]*AcmeCerts{"cert1": {d1}},
			expAdd:  map[string]*AcmeCerts{},
			expDel:  map[string]*AcmeCerts{},
		},
		// 3
		{
			itemAdd: map[string]*AcmeCerts{
				"cert1": {d1},
				"cert2": {d1},
			},
			itemDel: map[string]*AcmeCerts{
				"cert1": {d1},
				"cert2": {d2},
			},
			expAdd: map[string]*AcmeCerts{
				"cert2": {d1},
			},
			expDel: map[string]*AcmeCerts{
				"cert2": {d2},
			},
		},
		// 4
		{
			itemAdd: map[string]*AcmeCerts{
				"cert1": {d1},
				"cert2": {d1},
			},
			itemDel: map[string]*AcmeCerts{
				"cert1": {d1},
			},
			expAdd: map[string]*AcmeCerts{
				"cert2": {d1},
			},
			expDel: map[string]*AcmeCerts{},
		},
	}
	for i, test := range testCases {
		acme := AcmeData{}
		storages := acme.Storages()
		if test.itemAdd != nil {
			storages.itemsAdd = test.itemAdd
		}
		if test.itemDel != nil {
			storages.itemsDel = test.itemDel
		}
		storages.shrink()
		if !reflect.DeepEqual(storages.itemsAdd, test.expAdd) {
			t.Errorf("itemAdd differs on %d - expected: %+v, actual: %+v", i, test.expAdd, storages.itemsAdd)
		}
		if !reflect.DeepEqual(storages.itemsDel, test.expDel) {
			t.Errorf("itemDel differs on %d - expected: %+v, actual: %+v", i, test.expDel, storages.itemsDel)
		}
	}
}
