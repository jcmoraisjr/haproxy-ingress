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

package utils

import (
	"fmt"
	"testing"
)

func TestParseURL(t *testing.T) {
	testCases := []struct {
		url string
		exp string
		err string
	}{
		// 0
		{
			url: "proto://",
			err: "invalid URL syntax: proto://",
		},
		// 1
		{
			url: "10.0.0.1",
			err: "invalid URL syntax: 10.0.0.1",
		},
		// 2
		{
			url: "proto://10.0.0.1",
			exp: "proto | 10.0.0.1 |  | ",
		},
		// 3
		{
			url: "proto://:8080",
			err: "invalid URL syntax: proto://:8080",
		},
		// 4
		{
			url: "proto://10.0.0.1:8080",
			exp: "proto | 10.0.0.1 | 8080 | ",
		},
		// 5
		{
			url: "proto://10.0.0.1/app",
			exp: "proto | 10.0.0.1 |  | /app",
		},
		// 6
		{
			url: "proto://10.0.0.1:named-port/App",
			exp: "proto | 10.0.0.1 | named-port | /App",
		},
		// 7
		{
			url: "proto://domain.local/app",
			exp: "proto | domain.local |  | /app",
		},
		// 8
		{
			url: "proto://name/app",
			exp: "proto | name |  | /app",
		},
		// 9
		{
			url: "proto://name/app:8080",
			exp: "proto | name/app | 8080 | ",
		},
		// 10
		{
			url: "proto://name:8080/app",
			exp: "proto | name | 8080 | /app",
		},
	}
	for i, test := range testCases {
		proto, host, port, path, err := ParseURL(test.url)
		actual := fmt.Sprintf("%s | %s | %s | %s", proto, host, port, path)
		if test.exp == "" {
			test.exp = " |  |  | "
		}
		if actual != test.exp {
			t.Errorf("expected '%s' on %d, but was '%s'", test.exp, i, actual)
		}
		if err != nil {
			if err.Error() != test.err {
				t.Errorf("expected error '%s' on %d, but was '%s'", test.err, i, err.Error())
			}
		} else if test.err != "" {
			t.Errorf("expected error '%s' on %d, but there was no error", test.err, i)
		}
	}
}
