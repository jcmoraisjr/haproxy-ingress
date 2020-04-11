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
