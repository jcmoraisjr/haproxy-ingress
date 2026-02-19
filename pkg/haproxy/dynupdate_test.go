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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func TestDynUpdate(t *testing.T) {
	testCases := map[string]struct {
		doconfig1 func(c *testConfig)
		doconfig2 func(c *testConfig)
		expected  []string
		dynamic   bool
		cmd       string
		cmdOutput []string
		logging   string
	}{
		"test01": {
			dynamic: true,
		},
		"test02": {
			doconfig2: func(c *testConfig) {
				c.config.Global().MaxConn = 1
			},
			dynamic: false,
			logging: `INFO-V(2) need to reload due to config changes: [global]`,
		},
		"test03": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		"test04": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
				"srv003:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		"test05": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			expected: []string{
				"srv002:172.17.0.3:8080:1",
				"srv001:172.17.0.4:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.4 port 8080
set server default_app_8080/srv001 weight 1
set server default_app_8080/srv001 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.2' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.2' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv001 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv001 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv001'
`,
		},
		"test06": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.Dynamic.BlockSize = 8
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
				"srv003:127.0.0.1:1023:1",
				"srv004:127.0.0.1:1023:1",
				"srv005:127.0.0.1:1023:1",
				"srv006:127.0.0.1:1023:1",
				"srv007:127.0.0.1:1023:1",
				"srv008:127.0.0.1:1023:1",
			},
			dynamic: false,
			logging: `
INFO-V(2) added endpoints on backend 'default_app_8080'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test07": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv002:172.17.0.3:8080:1",
				"srv001:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 state maint
`,
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.2:8080' weight '1' on backend/server 'default_app_8080/srv001'
`,
		},
		"test08": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				ep := b.AcquireEndpoint("172.17.0.2", 8080, "")
				ep.Weight = 2
			},
			expected: []string{
				"srv001:172.17.0.2:8080:2",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.2 port 8080
set server default_app_8080/srv001 weight 2
set server default_app_8080/srv001 state ready
`,
			cmdOutput: []string{
				"nothing changed",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 addr 172.17.0.2 port 8080
INFO-V(2) response from server: nothing changed
INFO-V(2) api call: set server default_app_8080/srv001 weight 2
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv001 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.2:8080' weight '2' on backend/server 'default_app_8080/srv001'
`,
		},
		"test09": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AddEmptyEndpoint()
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.2 port 8080
set server default_app_8080/srv001 weight 1
set server default_app_8080/srv001 state ready
`,
			cmdOutput: []string{
				"IP changed from '127.0.0.1' to '172.17.0.3', port changed from '1023' to '8080' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 addr 172.17.0.2 port 8080
INFO-V(2) response from server: IP changed from '127.0.0.1' to '172.17.0.3', port changed from '1023' to '8080' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv001 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv001 state ready
INFO-V(2) empty response from server
INFO-V(2) enabled endpoint '172.17.0.2:8080' weight '1' on backend/server 'default_app_8080/srv001'
`,
		},
		"test10": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AddEmptyEndpoint()
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv002:172.17.0.2:8080:1",
				"srv001:172.17.0.3:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.3 port 8080
set server default_app_8080/srv001 weight 1
set server default_app_8080/srv001 state ready
`,
			cmdOutput: []string{
				"IP changed from '127.0.0.1' to '172.17.0.3' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 addr 172.17.0.3 port 8080
INFO-V(2) response from server: IP changed from '127.0.0.1' to '172.17.0.3' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv001 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv001 state ready
INFO-V(2) empty response from server
INFO-V(2) enabled endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv001'
`,
		},
		"test11": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
				b.AcquireEndpoint("172.17.0.5", 8080, "")
				b.AcquireEndpoint("172.17.0.6", 8080, "")
				b.AcquireEndpoint("172.17.0.7", 8080, "")
				b.AcquireEndpoint("172.17.0.8", 8080, "")
				b.AcquireEndpoint("172.17.0.9", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.5", 8080, "")
				b.AcquireEndpoint("172.17.0.7", 8080, "")
			},
			expected: []string{
				"srv004:172.17.0.5:8080:1",
				"srv006:172.17.0.7:8080:1",
				"srv001:127.0.0.1:1023:1",
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
				"srv005:127.0.0.1:1023:1",
				"srv007:127.0.0.1:1023:1",
				"srv008:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 state maint
set server default_app_8080/srv002 state maint
set server default_app_8080/srv003 state maint
set server default_app_8080/srv005 state maint
set server default_app_8080/srv007 state maint
set server default_app_8080/srv008 state maint
`,
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.2:8080' weight '1' on backend/server 'default_app_8080/srv001'
INFO-V(2) api call: set server default_app_8080/srv002 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv002'
INFO-V(2) api call: set server default_app_8080/srv003 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv003'
INFO-V(2) api call: set server default_app_8080/srv005 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.6:8080' weight '1' on backend/server 'default_app_8080/srv005'
INFO-V(2) api call: set server default_app_8080/srv007 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.8:8080' weight '1' on backend/server 'default_app_8080/srv007'
INFO-V(2) api call: set server default_app_8080/srv008 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.9:8080' weight '1' on backend/server 'default_app_8080/srv008'
`,
		},
		"test12": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				c.config.Backends().AcquireBackend("default", "app", "8080").Dynamic.DynScaling = types.DynScalingSlots
			},
			expected: []string{
				"srv001:127.0.0.1:1023:1",
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 state maint
set server default_app_8080/srv002 state maint
set server default_app_8080/srv003 state maint
`,
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.2:8080' weight '1' on backend/server 'default_app_8080/srv001'
INFO-V(2) api call: set server default_app_8080/srv002 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv002'
INFO-V(2) api call: set server default_app_8080/srv003 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv003'
`,
		},
		"test13": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.Dynamic.MinFreeSlots = 4
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
				"srv003:172.17.0.4:8080:1",
				"srv004:127.0.0.1:1023:1",
				"srv005:127.0.0.1:1023:1",
				"srv006:127.0.0.1:1023:1",
				"srv007:127.0.0.1:1023:1",
			},
			dynamic: false,
			logging: `
INFO-V(2) added endpoints on backend 'default_app_8080'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test14": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AddEmptyEndpoint()
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.Dynamic.MinFreeSlots = 4
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
				"srv003:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.3 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '127.0.0.1' to '172.17.0.3' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.3 port 8080
INFO-V(2) response from server: IP changed from '127.0.0.1' to '172.17.0.3' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) enabled endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		"test15": {
			doconfig1: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				b1.Dynamic.DynScaling = types.DynScalingSlots
				b1.Dynamic.MinFreeSlots = 1
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynScaling = types.DynScalingSlots
				b2.AcquireEndpoint("172.17.0.2", 8080, "")
				b2.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
			},
			dynamic: false,
			cmd:     ``,
			logging: `
INFO-V(2) added endpoints on backend 'default_app_8080'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test16": {
			doconfig2: func(c *testConfig) {
				c.config.Backends().AcquireBackend("default", "app", "8080").Dynamic.DynScaling = types.DynScalingSlots
			},
			expected: []string{
				"srv001:127.0.0.1:1023:1",
			},
			dynamic: false,
			cmd:     ``,
			logging: `
INFO-V(2) added backend 'default_app_8080'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test17": {
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.Dynamic.BlockSize = 4
			},
			expected: []string{
				"srv001:127.0.0.1:1023:1",
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
				"srv004:127.0.0.1:1023:1",
			},
			dynamic: false,
			cmd:     ``,
			logging: `
INFO-V(2) added backend 'default_app_8080'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test18": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.3 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '127.0.0.1' to '172.17.0.3' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.3 port 8080
INFO-V(2) response from server: IP changed from '127.0.0.1' to '172.17.0.3' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) enabled endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		"test19": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.4", 8080, "").Label = "green"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '127.0.0.1' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '127.0.0.1' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) enabled endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
INFO-V(2) need to reload due to config changes: [backends]
`,
		},
		"test20": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Label = "green"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:127.0.0.1:1023:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 state maint`,
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 state maint
INFO-V(2) empty response from server
INFO-V(2) disabled endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv002'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test21": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Label = "green"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.4", 8080, "").Label = "green"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
INFO-V(2) need to reload due to config changes: [backends]
`,
		},
		"test22": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingNone
				b.Dynamic.MinFreeSlots = 4
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.3:8080:1",
			},
			dynamic: false,
			logging: `
INFO-V(2) backend 'default_app_8080' changed and its dynamic update is 'false'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		"test23": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.Dynamic.DynScaling = types.DynScalingNone
				b.Dynamic.MinFreeSlots = 4
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingNone
				b.Dynamic.MinFreeSlots = 4
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
			},
			dynamic: true,
		},
		// test that we're able to update when a cookie value of acquired
		// existing endpoint exactly matches and cookie affinity is enabled
		// even with "preserve" cookie mode
		"test24": {
			doconfig1: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				// some of these are unnecessary but the attempt is to have as
				// realistic config as possible for a more reliable test
				b2.Cookie.Name = "serverId"
				b2.Cookie.Strategy = "insert"
				b2.Cookie.Keywords = "nocache"
				b2.Cookie.Dynamic = false
				b2.Cookie.Preserve = true
				b2.ModeTCP = false
				b2.AcquireEndpoint("172.17.0.2", 8080, "").CookieValue = "5017b276-6886-4ae0-b75e-bd1fcb9b1e3b"
				b2.AcquireEndpoint("172.17.0.3", 8080, "").CookieValue = "3e4c9c86-0fc4-4aa9-9d96-bf0c49797006"
			},
			doconfig2: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				b1.Dynamic.DynScaling = types.DynScalingSlots
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynScaling = types.DynScalingSlots
				// some of these are unnecessary but the attempt is to have as
				// realistic config as possible for a more reliable test
				b2.Cookie.Name = "serverId"
				b2.Cookie.Strategy = "insert"
				b2.Cookie.Keywords = "nocache"
				b2.Cookie.Dynamic = false
				b2.Cookie.Preserve = true
				b2.ModeTCP = false
				b2.AcquireEndpoint("172.17.0.2", 8080, "").CookieValue = "5017b276-6886-4ae0-b75e-bd1fcb9b1e3b"
				// acquiring a different ip on srv002 should succeed dynamically
				// because the cookie didn't change
				b2.AcquireEndpoint("172.17.0.4", 8080, "").CookieValue = "3e4c9c86-0fc4-4aa9-9d96-bf0c49797006"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		// test that we're unable to update when a cookie value of acquired
		// existing endpoint doesn't match and "preserve" cookie mode is enabled
		"test25": {
			doconfig1: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				// some of these are unnecessary but the attempt is to have as
				// realistic config as possible for a more reliable test
				b2.Cookie.Name = "serverId"
				b2.Cookie.Strategy = "insert"
				b2.Cookie.Keywords = "nocache"
				b2.Cookie.Dynamic = false
				b2.Cookie.Preserve = true
				b2.ModeTCP = false
				b2.AcquireEndpoint("172.17.0.2", 8080, "").CookieValue = "5017b276-6886-4ae0-b75e-bd1fcb9b1e3b"
				b2.AcquireEndpoint("172.17.0.3", 8080, "").CookieValue = "3e4c9c86-0fc4-4aa9-9d96-bf0c49797006"
			},
			doconfig2: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				b1.Dynamic.DynScaling = types.DynScalingSlots
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynScaling = types.DynScalingSlots
				// some of these are unnecessary but the attempt is to have as
				// realistic config as possible for a more reliable test
				b2.Cookie.Name = "serverId"
				b2.Cookie.Strategy = "insert"
				b2.Cookie.Keywords = "nocache"
				b2.Cookie.Dynamic = false
				b2.Cookie.Preserve = true
				b2.ModeTCP = false
				b2.AcquireEndpoint("172.17.0.2", 8080, "").CookieValue = "5017b276-6886-4ae0-b75e-bd1fcb9b1e3b"
				// changing this cookie value should cause it to not be able to
				// dynupdate
				b2.AcquireEndpoint("172.17.0.4", 8080, "").CookieValue = "a7b4db22-8689-4b56-8f49-1c1638c30acd"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			dynamic: false,
			cmd:     ``,
			logging: `INFO-V(2) need to reload due to config changes: [backends]`,
		},
		// test that we're able to update when a cookie value of acquired
		// existing endpoint doesn't match and "preserve" cookie mode is not enabled
		// (eg. it doesn't care to preserve the cookie value, so still updates)
		"test26": {
			doconfig1: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				// some of these are unnecessary but the attempt is to have as
				// realistic config as possible for a more reliable test
				b2.Cookie.Name = "serverId"
				b2.Cookie.Strategy = "insert"
				b2.Cookie.Keywords = "nocache"
				b2.Cookie.Dynamic = false
				b2.Cookie.Preserve = false
				b2.ModeTCP = false
				b2.AcquireEndpoint("172.17.0.2", 8080, "").CookieValue = "5017b276-6886-4ae0-b75e-bd1fcb9b1e3b"
				b2.AcquireEndpoint("172.17.0.3", 8080, "").CookieValue = "3e4c9c86-0fc4-4aa9-9d96-bf0c49797006"
			},
			doconfig2: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				b1.Dynamic.DynScaling = types.DynScalingSlots
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynScaling = types.DynScalingSlots
				// some of these are unnecessary but the attempt is to have as
				// realistic config as possible for a more reliable test
				b2.Cookie.Name = "serverId"
				b2.Cookie.Strategy = "insert"
				b2.Cookie.Keywords = "nocache"
				b2.Cookie.Dynamic = false
				b2.Cookie.Preserve = false
				b2.ModeTCP = false
				b2.AcquireEndpoint("172.17.0.2", 8080, "").CookieValue = "5017b276-6886-4ae0-b75e-bd1fcb9b1e3b"
				// we can still update even though the cookie changes below because
				// "preserve" cookie strategy is disabled
				b2.AcquireEndpoint("172.17.0.4", 8080, "").CookieValue = "a7b4db22-8689-4b56-8f49-1c1638c30acd"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		"test27": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				c.config.backends.DefaultBackend = b
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				c.config.backends.DefaultBackend = b
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.3:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.3 port 8080
set server default_app_8080/srv001 weight 1
set server default_app_8080/srv001 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.2' to '172.17.0.3' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv001 addr 172.17.0.3 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.2' to '172.17.0.3' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv001 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv001 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv001'
`,
		},
		"test28": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Resolver = "k8s"
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Resolver = "k8s"
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.3:8080:1",
				"srv002:127.0.0.1:1023:1",
			},
			dynamic: true,
		},
		"test29": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Name = "srv002"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Name = "srv003"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
				b.AcquireEndpoint("172.17.0.4", 8080, "").Name = "srv004"
				b.AcquireEndpoint("172.17.0.5", 8080, "").Name = "srv005"
			},
			expected: []string{
				"srv002:172.17.0.4:8080:1",
				"srv003:172.17.0.5:8080:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv003 addr 172.17.0.5 port 8080
`,
			cmdOutput: []string{
				"No such server.",
				"No such server.",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
WARN unrecognized response updating (address) backend server default_app_8080/srv002: No such server.
INFO-V(2) api call: set server default_app_8080/srv003 addr 172.17.0.5 port 8080
WARN unrecognized response updating (address) backend server default_app_8080/srv003: No such server.
INFO-V(2) need to reload due to config changes: [backends]
`,
		},
		"test30": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Name = "srv002"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Name = "srv003"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingSlots
			},
			expected: []string{
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 state maint
set server default_app_8080/srv003 state maint
`,
			cmdOutput: []string{
				"No such server.",
				"No such server.",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 state maint
WARN unrecognized response updating (state) backend server default_app_8080/srv002: No such server.
INFO-V(2) api call: set server default_app_8080/srv003 state maint
WARN unrecognized response updating (state) backend server default_app_8080/srv003: No such server.
INFO-V(2) need to reload due to config changes: [backends]
`,
		},
		"test31": {
			doconfig1: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h2 := f.AcquireHost("domain2.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h2.TLS.TLSFilename = "/tmp/domain2.pem"
				h1.TLS.TLSHash = "1"
				h2.TLS.TLSHash = "2"
			},
			doconfig2: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h2 := f.AcquireHost("domain2.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h2.TLS.TLSFilename = "/tmp/domain2.pem"
				h1.TLS.TLSHash = "1"
				h2.TLS.TLSHash = "3"
			},
			dynamic: true,
			cmd: `
set ssl cert /tmp/domain2.pem <<
<content>

commit ssl cert /tmp/domain2.pem
`,
			cmdOutput: []string{
				"Transaction created for certificate /tmp/domain2.pem!\n\n",
				"Committing /tmp/domain2.pem.\nSuccess!\n\n",
			},
			logging: `
INFO-V(2) response from server: Transaction created for certificate /tmp/domain2.pem!
INFO-V(2) response from server: Committing /tmp/domain2.pem. \\ Success!
INFO certificate updated for domain2.local
`,
		},
		"test32": {
			doconfig1: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
			},
			doconfig2: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain2.pem"
				h1.TLS.TLSHash = "2"
			},
			dynamic: false,
			logging: `
INFO-V(2) diff outside server certificate of host 'domain1.local'
INFO-V(2) need to reload due to config changes: [hosts (_front_http)]
`,
		},
		"test33": {
			doconfig1: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h2 := f.AcquireHost("domain2.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h2.TLS.TLSFilename = ""
				h1.TLS.TLSHash = "1"
				h2.TLS.TLSHash = "2"
			},
			doconfig2: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h2 := f.AcquireHost("domain2.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h2.TLS.TLSFilename = ""
				h1.TLS.TLSHash = "3"
				h2.TLS.TLSHash = "2"
			},
			dynamic: true,
			cmd: `
set ssl cert /tmp/domain1.pem <<
<content>

commit ssl cert /tmp/domain1.pem
`,
			cmdOutput: []string{
				"Transaction created for certificate /tmp/domain1.pem!\n\n",
				"Committing /tmp/domain1.pem.\nSuccess!\n\n",
			},
			logging: `
INFO-V(2) response from server: Transaction created for certificate /tmp/domain1.pem!
INFO-V(2) response from server: Committing /tmp/domain1.pem. \\ Success!
INFO certificate updated for domain1.local
`,
		},
		"test34": {
			doconfig1: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
			},
			doconfig2: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "2"
			},
			dynamic: false,
			cmd: `
set ssl cert /tmp/domain1.pem <<
<content>

commit ssl cert /tmp/domain1.pem
`,
			cmdOutput: []string{
				"Can't replace a certificate which is not referenced by the configuration!\nCan't update /tmp/domain1.pem!\n\n",
				"No ongoing transaction! !\nCan't commit /tmp/domain1.pem!\n\n",
			},
			logging: `
INFO-V(2) response from server: Can't replace a certificate which is not referenced by the configuration! \\ Can't update /tmp/domain1.pem!
INFO-V(2) response from server: No ongoing transaction! ! \\ Can't commit /tmp/domain1.pem!
WARN cannot update certificate for domain1.local
INFO-V(2) need to reload due to config changes: [hosts (_front_http)]
`,
		},
		"test35": {
			doconfig1: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
				f.AcquireHost("domain2.local")
			},
			doconfig2: func(c *testConfig) {
				f := c.httpFrontend(80)
				h1 := f.AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
			},
			dynamic: false,
			logging: `
INFO-V(2) removed host 'domain2.local'
INFO-V(2) need to reload due to config changes: [hosts (_front_http)]
`,
		},
		"test36": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.HealthCheck.Interval = "5s"
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.HealthCheck.Interval = "5s"
				b.Dynamic.DynScaling = types.DynScalingAdd
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			dynamic: true,
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.3:8080:1",
			},
			cmd: `
add server default_app_8080/srv002 172.17.0.3:8080 weight 1 check inter 5s
set server default_app_8080/srv002 state ready
enable health default_app_8080/srv002
`,
			cmdOutput: []string{
				"New server registered.",
			},
			logging: `
INFO-V(2) api call: add server default_app_8080/srv002 172.17.0.3:8080 weight 1 check inter 5s
INFO-V(2) response from server: New server registered.
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) api call: enable health default_app_8080/srv002
INFO-V(2) empty response from server
INFO-V(2) registered new endpoint '172.17.0.3:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		// deleting server without pending connections
		"test37": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingAdd
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			dynamic: true,
			expected: []string{
				"srv001:172.17.0.2:8080:1",
			},
			cmd: `
set server default_app_8080/srv002 state maint
del server default_app_8080/srv002
`,
			cmdOutput: []string{
				"",
				"Server deleted.",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 state maint
INFO-V(2) empty response from server
INFO-V(2) api call: del server default_app_8080/srv002
INFO-V(2) response from server: Server deleted.
INFO-V(2) deleted endpoint '172.17.0.3:8080' weight '1' backend/server 'default_app_8080/srv002'
`,
		},
		// deleting server with pending connections
		"test38": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingAdd
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			dynamic: true,
			expected: []string{
				"srv001:172.17.0.2:8080:1",
			},
			cmd: `
set server default_app_8080/srv002 state maint
del server default_app_8080/srv002
`,
			cmdOutput: []string{
				"",
				"Server still has connections attached to it, cannot remove it.",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 state maint
INFO-V(2) empty response from server
INFO-V(2) api call: del server default_app_8080/srv002
WARN unrecognized response deleting backend server default_app_8080/srv002: Server still has connections attached to it, cannot remove it.
INFO-V(2) disabled endpoint '172.17.0.3:8080' weight '1' backend/server 'default_app_8080/srv002'
`,
		},
		// changing IP address of the same server
		"test39": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynScaling = types.DynScalingAdd
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			dynamic: true,
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:172.17.0.4:8080:1",
			},
			cmd: `
set server default_app_8080/srv002 addr 172.17.0.4 port 8080
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv002 state ready
`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/srv002 addr 172.17.0.4 port 8080
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4' by 'stats socket command'
INFO-V(2) api call: set server default_app_8080/srv002 weight 1
INFO-V(2) empty response from server
INFO-V(2) api call: set server default_app_8080/srv002 state ready
INFO-V(2) empty response from server
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/srv002'
`,
		},
		// changing IP address and also changing the backend server name, removing before adding by naming from pod2 to pod3
		"test40": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.EpNaming = types.EpTargetRef
				b.AcquireEndpoint("172.17.0.2", 8080, "pod1")
				b.AcquireEndpoint("172.17.0.3", 8080, "pod2")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.EpNaming = types.EpTargetRef
				b.Dynamic.DynScaling = types.DynScalingAdd
				b.AcquireEndpoint("172.17.0.2", 8080, "pod1")
				b.AcquireEndpoint("172.17.0.4", 8080, "pod3")
			},
			dynamic: true,
			expected: []string{
				"pod1:172.17.0.2:8080:1",
				"pod3:172.17.0.4:8080:1",
			},
			cmd: `
set server default_app_8080/pod2 state maint
del server default_app_8080/pod2
add server default_app_8080/pod3 172.17.0.4:8080 weight 1
set server default_app_8080/pod3 state ready
`,
			cmdOutput: []string{
				"",
				"Server still has connections attached to it, cannot remove it.",
				"New server registered.",
			},
			logging: `
INFO-V(2) api call: set server default_app_8080/pod2 state maint
INFO-V(2) empty response from server
INFO-V(2) api call: del server default_app_8080/pod2
WARN unrecognized response deleting backend server default_app_8080/pod2: Server still has connections attached to it, cannot remove it.
INFO-V(2) disabled endpoint '172.17.0.3:8080' weight '1' backend/server 'default_app_8080/pod2'
INFO-V(2) api call: add server default_app_8080/pod3 172.17.0.4:8080 weight 1
INFO-V(2) response from server: New server registered.
INFO-V(2) api call: set server default_app_8080/pod3 state ready
INFO-V(2) empty response from server
INFO-V(2) registered new endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/pod3'
`,
		},
		// changing IP address and also changing the backend server name, adding before removing by naming from pod3 to pod2
		"test41": {
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.EpNaming = types.EpTargetRef
				b.AcquireEndpoint("172.17.0.2", 8080, "pod1")
				b.AcquireEndpoint("172.17.0.3", 8080, "pod3")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.EpNaming = types.EpTargetRef
				b.Dynamic.DynScaling = types.DynScalingAdd
				b.AcquireEndpoint("172.17.0.2", 8080, "pod1")
				b.AcquireEndpoint("172.17.0.4", 8080, "pod2")
			},
			dynamic: true,
			expected: []string{
				"pod1:172.17.0.2:8080:1",
				"pod2:172.17.0.4:8080:1",
			},
			cmd: `
add server default_app_8080/pod2 172.17.0.4:8080 weight 1
set server default_app_8080/pod2 state ready
set server default_app_8080/pod3 state maint
del server default_app_8080/pod3
`,
			cmdOutput: []string{
				"New server registered.",
				"",
				"",
				"Server still has connections attached to it, cannot remove it.",
			},
			logging: `
INFO-V(2) api call: add server default_app_8080/pod2 172.17.0.4:8080 weight 1
INFO-V(2) response from server: New server registered.
INFO-V(2) api call: set server default_app_8080/pod2 state ready
INFO-V(2) empty response from server
INFO-V(2) registered new endpoint '172.17.0.4:8080' weight '1' on backend/server 'default_app_8080/pod2'
INFO-V(2) api call: set server default_app_8080/pod3 state maint
INFO-V(2) empty response from server
INFO-V(2) api call: del server default_app_8080/pod3
WARN unrecognized response deleting backend server default_app_8080/pod3: Server still has connections attached to it, cannot remove it.
INFO-V(2) disabled endpoint '172.17.0.3:8080' weight '1' backend/server 'default_app_8080/pod3'
`,
		},
	}
	readFile = func(_ string) ([]byte, error) {
		return []byte("<content>"), nil
	}
	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			c := setup(t)
			f := c.httpFrontend(80)
			if test.doconfig1 != nil {
				test.doconfig1(c)
			}
			c.instance.config.Commit()
			hostnames := []string{}
			for hostname := range f.Hosts() {
				hostnames = append(hostnames, hostname)
			}
			f.RemoveAllHosts(hostnames)
			backendIDs := []string{}
			for _, backend := range c.config.Backends().Items() {
				backendIDs = append(backendIDs, backend.ID)
			}
			c.config.Backends().RemoveAll(backendIDs)
			if test.doconfig2 != nil {
				test.doconfig2(c)
			}
			clientMock := &clientMock{
				cmdOutput: test.cmdOutput,
			}
			dynUpdater := c.instance.newDynUpdater()
			dynUpdater.socket = clientMock
			dynamic := dynUpdater.update()
			var actual []string
			for _, ep := range c.config.Backends().AcquireBackend("default", "app", "8080").Endpoints {
				actual = append(actual, fmt.Sprintf("%s:%s:%d:%d", ep.Name, ep.IP, ep.Port, ep.Weight))
			}
			assert.Equal(t, test.expected, actual, "endpoints differ")
			assert.Equal(t, test.dynamic, dynamic, "dynamic differ")
			cmd := strings.TrimSpace(clientMock.cmd)
			test.cmd = strings.TrimSpace(test.cmd)
			assert.Equal(t, test.cmd, cmd, "cmd differ")
			c.logger.CompareLogging(test.logging)
			c.teardown()
		})
	}
}

type clientMock struct {
	cmd       string
	cmdOutput []string
}

func (cli *clientMock) Address() string {
	return ""
}

func (cli *clientMock) HasConn() bool {
	return true
}

func (cli *clientMock) Send(observer func(duration time.Duration), command ...string) ([]string, error) {
	for _, c := range command {
		cli.cmd = cli.cmd + c + "\n"
	}
	for range len(command) - len(cli.cmdOutput) {
		cli.cmdOutput = append(cli.cmdOutput, "")
	}
	output := cli.cmdOutput[:len(command)]
	cli.cmdOutput = cli.cmdOutput[len(command):]
	return output, nil
}

func (cli *clientMock) Unlistening() error {
	return nil
}

func (cli *clientMock) Close() error {
	return nil
}
