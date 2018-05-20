/*
Copyright 2017 The Kubernetes Authors.

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

package net

import (
	"testing"
)

func TestNewIPSet(t *testing.T) {
	ipsets, ips, err := ParseIPNets("1.0.0.0", "2.0.0.0/8", "3.0.0.0/8")
	if err != nil {
		t.Errorf("error parsing IPNets: %v", err)
	}
	if len(ipsets) != 2 {
		t.Errorf("Expected len(ipsets)=2: %d", len(ipsets))
	}
	if len(ips) != 1 {
		t.Errorf("Expected len(ips)=1: %d", len(ips))
	}
}

func TestPartialIPParsing(t *testing.T) {
	ipsets, ips, err := ParseIPNets("1.355.0.0", "2.0.0.0/8", "3.0.0.0/33")
	if err == nil {
		t.Error("expected error parsing IPs")
	}
	if len(ipsets) != 1 {
		t.Errorf("expected len(ipsets)=1: %d -- %v", len(ipsets), ipsets)
	}
	if _, ok := ipsets["2.0.0.0/8"]; !ok {
		t.Errorf("expected ipsets['2.0.0.0/8'], was %v", ipsets)
	}
	if len(ips) != 0 {
		t.Errorf("expected len(ips)=0: %d -- %v", len(ips), ips)
	}
}
