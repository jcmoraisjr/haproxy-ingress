/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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
	"testing"
)

func TestGetContentProtocol(t *testing.T) {
	testCases := []struct {
		input   string
		proto   string
		content string
	}{
		// 0
		{
			input:   "aname",
			proto:   "secret",
			content: "aname",
		},
		// 1
		{
			input:   "anamespace/aname",
			proto:   "secret",
			content: "anamespace/aname",
		},
		// 2
		{
			input:   "secret://aname",
			proto:   "secret",
			content: "aname",
		},
		// 3
		{
			input:   "secret://",
			proto:   "secret",
			content: "",
		},
		// 4
		{
			input:   "file:///tmp/data",
			proto:   "file",
			content: "/tmp/data",
		},
		// 5
		{
			input:   "file:///tmp/file1,/tmp/file2",
			proto:   "file",
			content: "/tmp/file1,/tmp/file2",
		},
		// 6
		{
			input:   "file://",
			proto:   "file",
			content: "",
		},
	}
	for i, test := range testCases {
		proto, content := getContentProtocol(test.input)
		if proto != test.proto {
			t.Errorf("proto differs on %d, expected %s but was %s", i, test.proto, proto)
		}
		if content != test.content {
			t.Errorf("content differs on %d, expected %s but was %s", i, test.content, content)
		}
	}
}
