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
	"testing"

	"github.com/kylelemons/godebug/diff"
	yaml "gopkg.in/yaml.v2"
)

func TestAppendHostname(t *testing.T) {
	testCases := []struct {
		hostname      string
		expectedMatch string
		expectedRegex string
	}{
		// 0
		{hostname: "Example.Local", expectedMatch: "example.local"},
		// 1
		{hostname: "example.local/", expectedMatch: "example.local/"},
		// 2
		{hostname: "*.Example.Local", expectedRegex: "^[^.]+\\.example\\.local$"},
		// 3
		{hostname: "*.example.local/", expectedRegex: "^[^.]+\\.example\\.local/"},
		// 4
		{hostname: "*.example.local/path", expectedRegex: "^[^.]+\\.example\\.local/path"},
	}
	for i, test := range testCases {
		hm := &HostsMap{}
		hm.AppendHostname(test.hostname, "backend")
		if test.expectedMatch != "" {
			if len(hm.Match) != 1 || len(hm.Regex) != 0 {
				t.Errorf("item %d, expected len(match)==1 and len(regex)==0, but was '%d' and '%d'", i, len(hm.Match), len(hm.Regex))
				continue
			}
			if hm.Match[0].Key != test.expectedMatch {
				t.Errorf("item %d, expected key '%s', but was '%s'", i, test.hostname, hm.Match[0].Key)
				continue
			}
		} else {
			//regex
			if len(hm.Match) != 0 || len(hm.Regex) != 1 {
				t.Errorf("item %d, expected len(match)==0 and len(regex)==1, but was '%d' and '%d'", i, len(hm.Match), len(hm.Regex))
				continue
			}
			if hm.Regex[0].Key != test.expectedRegex {
				t.Errorf("item %d, expected key '%s', but was '%s'", i, test.expectedRegex, hm.Regex[0].Key)
				continue
			}
		}
	}
}

func TestBuildFrontendEmpty(t *testing.T) {
	frontends, _ := BuildRawFrontends([]*Host{})
	if len(frontends) > 0 {
		t.Errorf("expected len(frontends) == 0, but was %d", len(frontends))
	}
}

func TestBuildFrontend(t *testing.T) {
	timeout10 := HostTimeoutConfig{Client: "10s"}
	timeout20 := HostTimeoutConfig{Client: "20s"}
	ca1 := HostTLSConfig{CAHash: "1"}
	ca2 := HostTLSConfig{CAHash: "2"}
	h10_1 := &Host{Hostname: "h1.local", Timeout: timeout10}
	h10_2 := &Host{Hostname: "h2.local", Timeout: timeout10}
	h20_1 := &Host{Hostname: "h3.local", Timeout: timeout20}
	h10CA1_1 := &Host{Hostname: "h4.local", Timeout: timeout10, TLS: ca1}
	h10CA2_1 := &Host{Hostname: "h5.local", Timeout: timeout10, TLS: ca2}
	h10CA2_2 := &Host{Hostname: "h6.local", Timeout: timeout10, TLS: ca2}
	testCases := []struct {
		hosts    []*Host
		expected []*Frontend
	}{
		// 0
		{
			hosts: []*Host{h10_1, h10_2},
			expected: []*Frontend{
				{
					Name:    "_front001",
					Timeout: timeout10,
					Hosts:   []*Host{h10_1, h10_2},
					Binds: []*BindConfig{
						&BindConfig{
							Hosts: []*Host{h10_1, h10_2},
						},
					},
				},
			},
		},
		// 1
		{
			hosts: []*Host{h10_1, h20_1, h10_2},
			expected: []*Frontend{
				{
					Name:    "_front001",
					Timeout: timeout10,
					Hosts:   []*Host{h10_1, h10_2},
					Binds: []*BindConfig{
						&BindConfig{
							Hosts: []*Host{h10_1, h10_2},
						},
					},
				},
				{
					Name:    "_front002",
					Timeout: timeout20,
					Hosts:   []*Host{h20_1},
					Binds: []*BindConfig{
						&BindConfig{
							Hosts: []*Host{h20_1},
						},
					},
				},
			},
		},
		// 2
		{
			hosts: []*Host{h10CA1_1, h10CA2_1, h10CA2_2},
			expected: []*Frontend{
				{
					Name:    "_front001",
					Timeout: timeout10,
					Hosts:   []*Host{h10CA1_1, h10CA2_1, h10CA2_2},
					Binds: []*BindConfig{
						&BindConfig{
							Hosts: []*Host{h10CA1_1},
							TLS:   BindTLSConfig{CAHash: "1"},
						},
						&BindConfig{
							Hosts: []*Host{h10CA2_1, h10CA2_2},
							TLS:   BindTLSConfig{CAHash: "2"},
						},
					},
				},
			},
		},
		// 3
		{
			hosts: []*Host{h10_1, h10_2, h10CA2_1, h10CA2_2},
			expected: []*Frontend{
				{
					Name:    "_front001",
					Timeout: timeout10,
					Hosts:   []*Host{h10_1, h10_2, h10CA2_1, h10CA2_2},
					Binds: []*BindConfig{
						&BindConfig{
							Hosts: []*Host{h10_1, h10_2},
						},
						&BindConfig{
							Hosts: []*Host{h10CA2_1, h10CA2_2},
							TLS:   BindTLSConfig{CAHash: "2"},
						},
					},
				},
			},
		},
	}
	for i, test := range testCases {
		frontends, _ := BuildRawFrontends(test.hosts)
		actualRaw, _ := yaml.Marshal(frontends)
		expectedRaw, _ := yaml.Marshal(test.expected)
		actual := string(actualRaw)
		expected := string(expectedRaw)
		if actual != expected {
			t.Errorf("frontend '%d' actual and expected differs:\n%v", i, diff.Diff(actual, expected))
		}
	}
}

func TestBuildSSLPassthrough(t *testing.T) {
	h1 := &Host{Hostname: "h1.local"}
	h2 := &Host{Hostname: "h2.local", SSLPassthrough: true}
	testCases := []struct {
		hosts    []*Host
		expected []*Host
	}{
		// 0
		{
			hosts:    []*Host{h1, h2},
			expected: []*Host{h2},
		},
	}
	for i, test := range testCases {
		_, sslpassthrough := BuildRawFrontends(test.hosts)
		actualRaw, _ := yaml.Marshal(sslpassthrough)
		expectedRaw, _ := yaml.Marshal(test.expected)
		actual := string(actualRaw)
		expected := string(expectedRaw)
		if actual != expected {
			t.Errorf("sslpassthrough '%d' actual and expected differs:\n%v", i, diff.Diff(actual, expected))
		}
	}
}
