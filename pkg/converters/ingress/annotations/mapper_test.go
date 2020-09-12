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

package annotations

import (
	"reflect"
	"testing"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

type ann struct {
	src         *Source
	path        hatypes.PathLink
	key         string
	val         string
	expConflict bool
}

var (
	srcing1 = &Source{
		Type:      "ingress",
		Namespace: "default",
		Name:      "ing1",
	}
	srcing2 = &Source{
		Type:      "ingress",
		Namespace: "default",
		Name:      "ing2",
	}
	srcing3 = &Source{
		Type:      "ingress",
		Namespace: "default",
		Name:      "ing3",
	}
	srcing4 = &Source{
		Type:      "ingress",
		Namespace: "default",
		Name:      "ing4",
	}
)

func TestAddAnnotation(t *testing.T) {
	pathRoot := hatypes.CreatePathLink("domain.local", "/")
	pathApp := hatypes.CreatePathLink("domain.local", "/app")
	pathPath := hatypes.CreatePathLink("domain.local", "/path")
	pathURL := hatypes.CreatePathLink("domain.local", "/url")
	testCases := []struct {
		ann       []ann
		annPrefix string
		getKey    string
		expMiss   bool
		expVal    string
		expLog    string
	}{
		// 0
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathURL, "auth-basic", "default/basic2", false},
			},
			annPrefix: "ing/",
			getKey:    "auth-basic",
			expVal:    "default/basic1",
			expLog:    "WARN annotation 'ing/auth-basic' from ingress 'default/ing1' overrides the same annotation with distinct value from [ingress 'default/ing2']",
		},
		// 1
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathURL, "auth-basic", "default/basic2", false},
				{srcing3, pathPath, "auth-basic", "default/basic3", false},
				{srcing4, pathApp, "auth-basic", "default/basic4", false},
			},
			annPrefix: "ing.k8s.io/",
			getKey:    "auth-basic",
			expVal:    "default/basic1",
			expLog:    "WARN annotation 'ing.k8s.io/auth-basic' from ingress 'default/ing1' overrides the same annotation with distinct value from [ingress 'default/ing2' ingress 'default/ing3' ingress 'default/ing4']",
		},
		// 2
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathURL, "auth-basic", "default/basic1", false},
				{srcing3, pathPath, "auth-basic", "default/basic1", false},
				{srcing4, pathApp, "auth-basic", "default/basic2", false},
			},
			annPrefix: "ing.k8s.io/",
			getKey:    "auth-basic",
			expVal:    "default/basic1",
			expLog:    "WARN annotation 'ing.k8s.io/auth-basic' from ingress 'default/ing1' overrides the same annotation with distinct value from [ingress 'default/ing4']",
		},
		// 3
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathRoot, "auth-basic", "default/basic2", true},
			},
			getKey: "auth-basic",
			expVal: "default/basic1",
		},
		// 4
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathURL, "auth-basic", "default/basic1", false},
			},
			getKey: "auth-basic",
			expVal: "default/basic1",
		},
		// 5
		{
			ann:     []ann{},
			getKey:  "auth-basic",
			expMiss: true,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		mapper := NewMapBuilder(c.logger, test.annPrefix, map[string]string{}).NewMapper()
		for j, ann := range test.ann {
			if conflict := mapper.addAnnotation(ann.src, ann.path, ann.key, ann.val); conflict != ann.expConflict {
				t.Errorf("expect conflict '%t' on '// %d (%d)', but was '%t'", ann.expConflict, i, j, conflict)
			}
		}
		if v := mapper.Get("error"); v.Source != nil {
			t.Errorf("expect to not find 'error' key on '%d', but was found", i)
		}
		v := mapper.Get(test.getKey)
		if v.Source == nil {
			if !test.expMiss {
				t.Errorf("expect to find '%s' key on '%d', but was not found", test.getKey, i)
			}
		} else if v.Value != test.expVal {
			t.Errorf("expect '%s' on '%d', but was '%s'", test.expVal, i, v)
		}
		c.logger.CompareLogging(test.expLog)
		c.teardown()
	}
}

func TestGetAnnotation(t *testing.T) {
	pathRoot := hatypes.CreatePathLink("domain.local", "/")
	pathURL := hatypes.CreatePathLink("domain.local", "/url")
	testCases := []struct {
		ann       []ann
		annPrefix string
		getKey    string
		expMiss   bool
		expConfig []*PathConfig
	}{
		// 0
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathURL, "auth-basic", "default/basic2", false},
			},
			getKey: "auth-basic",
			expConfig: []*PathConfig{
				{Source: srcing1, path: pathRoot, Value: "default/basic1"},
				{Source: srcing2, path: pathURL, Value: "default/basic2"},
			},
		},
		// 1
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-type", "basic", false},
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathRoot, "auth-basic", "default/basic2", true},
			},
			getKey: "auth-basic",
			expConfig: []*PathConfig{
				{Source: srcing1, path: pathRoot, Value: "default/basic1"},
			},
		},
		// 2
		{
			ann: []ann{
				{srcing1, pathRoot, "auth-type", "basic", false},
				{srcing1, pathRoot, "auth-basic", "default/basic1", false},
				{srcing2, pathRoot, "auth-basic", "default/basic2", true},
			},
			getKey: "auth-type",
			expConfig: []*PathConfig{
				{Source: srcing1, path: pathRoot, Value: "basic"},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		mapper := NewMapBuilder(c.logger, test.annPrefix, map[string]string{}).NewMapper()
		for j, ann := range test.ann {
			if conflict := mapper.addAnnotation(ann.src, ann.path, ann.key, ann.val); conflict != ann.expConflict {
				t.Errorf("expect conflict '%t' on '// %d (%d)', but was '%t'", ann.expConflict, i, j, conflict)
			}
		}
		pathConfig, found := mapper.GetStrMap(test.getKey)
		if !found {
			if !test.expMiss {
				t.Errorf("expect to find '%s' key on '%d', but was not found", test.getKey, i)
			}
		} else if !reflect.DeepEqual(pathConfig, test.expConfig) {
			t.Errorf("expected and actual differ on '%d' - expected: %+v - actual: %+v", i, test.expConfig, pathConfig)
		}
		c.teardown()
	}
}

func TestGetDefault(t *testing.T) {
	testCases := []struct {
		annDefaults map[string]string
		ann         map[string]string
		expAnn      map[string]string
	}{
		// 0
		{
			expAnn: map[string]string{
				"timeout-client": "",
			},
		},
		// 1
		{
			annDefaults: map[string]string{
				"timeout-client": "10s",
				"balance":        "roundrobin",
			},
			expAnn: map[string]string{
				"timeout-client": "10s",
				"balance":        "roundrobin",
			},
		},
		// 2
		{
			annDefaults: map[string]string{
				"timeout-client": "10s",
				"balance":        "roundrobin",
			},
			ann: map[string]string{
				"balance": "leastconn",
			},
			expAnn: map[string]string{
				"timeout-client": "10s",
				"balance":        "leastconn",
			},
		},
		// 3
		{
			annDefaults: map[string]string{
				"timeout-client": "10s",
				"balance":        "roundrobin",
			},
			ann: map[string]string{
				"timeout-client": "20s",
			},
			expAnn: map[string]string{
				"timeout-client": "20s",
				"balance":        "roundrobin",
			},
		},
		// 4
		{
			annDefaults: map[string]string{
				"timeout-client": "10s",
				"balance":        "roundrobin",
			},
			ann: map[string]string{
				"timeout-client": "30s",
				"balance":        "leastconn",
			},
			expAnn: map[string]string{
				"timeout-client": "30s",
				"balance":        "leastconn",
			},
		},
	}
	pathRoot := hatypes.CreatePathLink("domain.local", "/")
	for i, test := range testCases {
		c := setup(t)
		mapper := NewMapBuilder(c.logger, "ing.k8s.io", test.annDefaults).NewMapper()
		mapper.AddAnnotations(&Source{}, pathRoot, test.ann)
		for key, exp := range test.expAnn {
			value := mapper.Get(key).Value
			if exp != value {
				t.Errorf("expected key '%s'='%s' on '%d', but was '%s'", key, exp, i, value)
			}
		}
		c.teardown()
	}
}
