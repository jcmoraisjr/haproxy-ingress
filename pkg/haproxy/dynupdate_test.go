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

package haproxy

import (
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func TestDynUpdate(t *testing.T) {
	testCases := []struct {
		oldConfig *config
		curConfig *config
		doconfig1 func(c *testConfig)
		doconfig2 func(c *testConfig)
		updated   bool
		cmd       string
		logging   string
	}{
		// 0
		{
			oldConfig: nil,
			curConfig: nil,
			updated:   false,
		},
		// 1
		{
			oldConfig: nil,
			curConfig: &config{},
			updated:   false,
		},
		// 2
		{
			oldConfig: &config{},
			curConfig: nil,
			updated:   false,
		},
		// 3
		{
			oldConfig: &config{},
			curConfig: &config{},
			updated:   true,
		},
		// 4
		{
			oldConfig: &config{},
			curConfig: &config{
				global: &hatypes.Global{},
			},
			updated: false,
		},
		// 5
		{
			doconfig1: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.2", 8080, "")
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			updated: false,
		},
		// 6
		{
			doconfig1: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.2", 8080, "")
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			updated: true,
			cmd: `
set server default_app_8080/srv001 state maint
set server default_app_8080/srv001 addr 127.0.0.1 port 1023
set server default_app_8080/srv001 weight 0
`,
			logging: `INFO-V(2) disabled endpoint 172.17.0.2:8080 on backend/server default_app_8080/srv001`,
		},
		// 7
		{
			doconfig1: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				ep := b.AddEndpoint("172.17.0.2", 8080, "")
				ep.Weight = 2
			},
			updated: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.2 port 8080
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 2
`,
			logging: `INFO-V(2) added endpoint 172.17.0.2:8080 on backend/server default_app_8080/srv001`,
		},
		// 8
		{
			doconfig1: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEmptyEndpoint()
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.2", 8080, "")
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			updated: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.2 port 8080
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 1
`,
			logging: `INFO-V(2) added endpoint 172.17.0.2:8080 on backend/server default_app_8080/srv001`,
		},
		// 9
		{
			doconfig1: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEmptyEndpoint()
				b.AddEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.AcquireBackend("default", "app", "8080")
				b.AddEndpoint("172.17.0.2", 8080, "")
				b.AddEndpoint("172.17.0.3", 8080, "")
			},
			updated: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.3 port 8080
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 1
`,
			logging: `INFO-V(2) added endpoint 172.17.0.3:8080 on backend/server default_app_8080/srv001`,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		instance := c.instance.(*instance)
		if test.doconfig1 != nil {
			test.doconfig1(c)
			test.oldConfig = c.config.(*config)
			instance.clearConfig()
			c.config = c.newConfig()
			instance.curConfig = c.config
		}
		if test.doconfig2 != nil {
			test.doconfig2(c)
			test.curConfig = c.config.(*config)
		}
		var cmd string
		dynUpdater := instance.newDynUpdater("/var/run/haproxy.sock")
		dynUpdater.cmd = func(socket string, command ...string) ([]string, error) {
			for _, c := range command {
				cmd = cmd + c + "\n"
			}
			return []string{}, nil
		}
		updated := dynUpdater.dynUpdate(test.oldConfig, test.curConfig)
		if updated != test.updated {
			t.Errorf("updated expected as '%t' on %d, but was '%t'", test.updated, i, updated)
		}
		cmd = strings.TrimSpace(cmd)
		test.cmd = strings.TrimSpace(test.cmd)
		if cmd != test.cmd {
			t.Errorf("cmd differs on %d:\n%s", i, diff.Diff(test.cmd, cmd))
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
