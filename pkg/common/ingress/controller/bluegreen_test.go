/*
Copyright 2018 The Kubernetes Authors.

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

package controller

import (
	"strconv"
	"strings"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/bluegreen"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/store"
)

func TestWeightBalance(t *testing.T) {
	s := cache.NewStore(cache.MetaNamespaceKeyFunc)
	s.Add(buildPod("pod0101-01", "app=d01,v=1"))
	s.Add(buildPod("pod0101-02", "app=d01,v=1"))
	s.Add(buildPod("pod0102-01", "app=d01,v=2"))
	s.Add(buildPod("pod0102-02", "app=d01,v=2"))
	s.Add(buildPod("pod0102-03", "app=d01,v=2"))
	s.Add(buildPod("pod0102-04", "app=d01,v=2"))
	s.Add(buildPod("pod0103-01", "app=d01,v=3"))
	podLister := store.PodLister{
		Store: s,
	}
	testUpstreams := map[string]*ingress.Backend{
		"b01-01": buildBackend("v=1=50,v=2=50", "pod0101-01,pod0102-01", "deploy"),
		"b01-02": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01", "deploy"),
		"b01-03": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01/d", "deploy"),
		"b02-01": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01,pod0102-02", "deploy"),
		"b02-02": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01,pod0102-02/d", "deploy"),
		"b02-03": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01,pod0102-02", "pod"),
		"b02-04": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01,pod0102-02/d", "pod"),
		"b02-05": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01,pod0102-02", ""),
		"b02-06": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-01,pod0102-02/d", ""),
		"b03-01": buildBackend("v=1=500,v=2=1", "pod0101-01,pod0102-01", "deploy"),
		"b04-01": buildBackend("v=1=60,v=2=3", "pod0101-01,pod0102-01,pod0102-02,pod0102-03,pod0102-04", "deploy"),
		"b04-02": buildBackend("v=1=70,v=2=3", "pod0101-01,pod0102-01,pod0102-02,pod0102-03,pod0102-04", "deploy"),
		"b05-01": buildBackend("", "pod0101-01,pod0102-01", "deploy"),
		"b06-01": buildBackend("v=1=50,v=2=25", ",pod0102-01", "deploy"),
		"b07-01": buildBackend("v=1=50,v=non=25", "pod0101-01,pod0102-01", "deploy"),
		"b07-02": buildBackend("v=1=50,v=non=25", "pod0101-01,pod0102-01", "pod"),
		"b07-03": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-non", "deploy"),
		"b07-04": buildBackend("v=1=50,v=2=25", "pod0101-01,pod0102-non", "pod"),
		"b08-01": buildBackend("v=1=50,v=2=25,v=3=25", "pod0101-01,pod0102-01,pod0102-02,pod0103-01", "deploy"),
		"b08-02": buildBackend("v=1=50,v=2=0,v=3=25", "pod0101-01,pod0102-01,pod0102-02,pod0103-01", "deploy"),
		"b09-01": buildBackend("v=1=50,v=2=0,v=3=25", "", "deploy"),
	}
	testExpectedWeight := map[string][]int{
		"b01-01": {1, 1},
		"b01-02": {2, 1},
		"b01-03": {1, 0},
		"b02-01": {4, 1, 1},
		"b02-02": {2, 1, 0},
		"b02-03": {50, 25, 25},
		"b02-04": {50, 25, 0},
		"b02-05": {4, 1, 1},
		"b02-06": {2, 1, 0},
		"b03-01": {256, 1},
		"b04-01": {80, 1, 1, 1, 1},
		"b04-02": {256, 2, 2, 2, 2},
		"b05-01": {1, 1},
		"b06-01": {1, 1},
		"b07-01": {1, 0},
		"b07-02": {50, 0},
		"b07-03": {1, 0},
		"b07-04": {50, 0},
		"b08-01": {4, 1, 1, 2},
		"b08-02": {2, 0, 0, 1},
		"b09-01": {},
	}
	weightBalance(&testUpstreams, podLister)
	for name, upstream := range testUpstreams {
		expected := testExpectedWeight[name]
		if len(upstream.Endpoints) != len(expected) {
			t.Errorf("len mismatch on %v, mock: %v, expected: %v", name, len(upstream.Endpoints), len(expected))
		}
		for id, ep := range upstream.Endpoints {
			if ep.Weight != expected[id] {
				t.Errorf("weight differs on %v[%v], real: %v, expected: %v", name, id, ep.Weight, expected[id])
			}
		}
	}
}

func buildBackend(deployWeight, endpoints, bgMode string) *ingress.Backend {
	w := []bluegreen.DeployWeight{}
	for _, weight := range strings.Split(deployWeight, ",") {
		if weight == "" {
			continue
		}
		dwSplit := strings.Split(weight, "=")
		pw, _ := strconv.ParseInt(dwSplit[2], 10, 0)
		w = append(w, bluegreen.DeployWeight{
			LabelName:  dwSplit[0],
			LabelValue: dwSplit[1],
			PodWeight:  int(pw),
		})
	}
	ep := []ingress.Endpoint{}
	if endpoints != "" {
		for _, e := range strings.Split(endpoints, ",") {
			epSplit := strings.Split(e, "/")
			name := epSplit[0]
			draining := len(epSplit) > 1 && epSplit[1] == "d"
			var target *v1.ObjectReference
			if name != "" {
				target = &v1.ObjectReference{
					Name: name,
				}
			}
			ep = append(ep, ingress.Endpoint{
				Draining: draining,
				Target:   target,
			})
		}
	}
	return &ingress.Backend{
		Service: &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc01",
				Namespace: "default",
			},
		},
		BlueGreen: bluegreen.Config{
			DeployWeight: w,
			Mode:         bgMode,
		},
		Endpoints: ep,
	}
}

func buildPod(name, labels string) *v1.Pod {
	l := make(map[string]string)
	for _, label := range strings.Split(labels, ",") {
		kv := strings.Split(label, "=")
		l[kv[0]] = kv[1]
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    l,
		},
	}
}
