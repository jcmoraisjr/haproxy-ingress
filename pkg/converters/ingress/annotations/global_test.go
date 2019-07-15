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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
)

func TestModSecurity(t *testing.T) {
	testCases := []struct {
		endpoints string
		expected  []string
	}{
		// 0
		{
			endpoints: "",
			expected:  []string{},
		},
		// 1
		{
			endpoints: "127.0.0.1:12345",
			expected:  []string{"127.0.0.1:12345"},
		},
		// 2
		{
			endpoints: "10.0.0.1:12345, 10.0.0.2:12345",
			expected:  []string{"10.0.0.1:12345", "10.0.0.2:12345"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		config := &types.ConfigGlobals{}
		config.ModsecurityEndpoints = test.endpoints
		d := c.createGlobalData(config)
		c.createUpdater().buildGlobalModSecurity(d)
		if !reflect.DeepEqual(test.expected, d.global.ModSecurity.Endpoints) {
			t.Errorf("endpoints differ on %d - expected: %v - actual: %v", i, test.expected, d.global.ModSecurity.Endpoints)
		}
		c.teardown()
	}
}

func TestForwardFor(t *testing.T) {
	testCases := []struct {
		conf     string
		expected string
		logging  string
	}{
		// 0
		{
			conf:     "",
			expected: "add",
			logging:  "",
		},
		// 1
		{
			conf:     "non",
			expected: "add",
			logging:  "WARN Invalid forwardfor value option on configmap: 'non'. Using 'add' instead",
		},
		// 2
		{
			conf:     "add",
			expected: "add",
			logging:  "",
		},
		// 3
		{
			conf:     "ignore",
			expected: "ignore",
			logging:  "",
		},
		// 4
		{
			conf:     "ifmissing",
			expected: "ifmissing",
			logging:  "",
		},
	}
	for i, test := range testCases {
		c := setup(t)
		u := c.createUpdater()
		d := c.createGlobalData(&types.ConfigGlobals{
			Forwardfor: test.conf,
		})
		u.buildGlobalForwardFor(d)
		if d.global.ForwardFor != test.expected {
			t.Errorf("ForwardFor differs on %d: expected '%s' but was '%s'", i, test.expected, d.global.ForwardFor)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
