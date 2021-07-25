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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kylelemons/godebug/diff"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func TestDynUpdate(t *testing.T) {
	testCases := []struct {
		doconfig1 func(c *testConfig)
		doconfig2 func(c *testConfig)
		expected  []string
		dynamic   bool
		cmd       string
		cmdOutput []string
		logging   string
	}{
		// 0
		{
			dynamic: true,
		},
		// 1
		{
			doconfig2: func(c *testConfig) {
				c.config.Global().MaxConn = 1
			},
			dynamic: false,
			logging: `INFO-V(2) need to reload due to config changes: [global]`,
		},
		// 2
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1`,
			logging: `INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
		},
		// 3
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1`,
			logging: `INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
		},
		// 4
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 1`,
			logging: `INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv001'`,
		},
		// 5
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
		// 6
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv002:172.17.0.3:8080:1",
				"srv001:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 state maint
set server default_app_8080/srv001 addr 127.0.0.1 port 1023
set server default_app_8080/srv001 weight 0
`,
			logging: `INFO-V(2) disabled endpoint '172.17.0.2:8080' on backend/server 'default_app_8080/srv001'`,
		},
		// 7
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
				ep := b.AcquireEndpoint("172.17.0.2", 8080, "")
				ep.Weight = 2
			},
			expected: []string{
				"srv001:172.17.0.2:8080:2",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.2 port 8080
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 2
`,
			logging: `INFO-V(2) updated endpoint '172.17.0.2:8080' weight '2' state 'ready' on backend/server 'default_app_8080/srv001'`,
		},
		// 8
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AddEmptyEndpoint()
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 1
`,
			logging: `INFO-V(2) added endpoint '172.17.0.2:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv001'`,
		},
		// 9
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AddEmptyEndpoint()
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 1
`,
			logging: `INFO-V(2) added endpoint '172.17.0.3:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv001'`,
		},
		// 10
		{
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
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv001 addr 127.0.0.1 port 1023
set server default_app_8080/srv001 weight 0
set server default_app_8080/srv002 state maint
set server default_app_8080/srv002 addr 127.0.0.1 port 1023
set server default_app_8080/srv002 weight 0
set server default_app_8080/srv003 state maint
set server default_app_8080/srv003 addr 127.0.0.1 port 1023
set server default_app_8080/srv003 weight 0
set server default_app_8080/srv005 state maint
set server default_app_8080/srv005 addr 127.0.0.1 port 1023
set server default_app_8080/srv005 weight 0
set server default_app_8080/srv007 state maint
set server default_app_8080/srv007 addr 127.0.0.1 port 1023
set server default_app_8080/srv007 weight 0
set server default_app_8080/srv008 state maint
set server default_app_8080/srv008 addr 127.0.0.1 port 1023
set server default_app_8080/srv008 weight 0
`,
			logging: `
INFO-V(2) disabled endpoint '172.17.0.2:8080' on backend/server 'default_app_8080/srv001'
INFO-V(2) disabled endpoint '172.17.0.3:8080' on backend/server 'default_app_8080/srv002'
INFO-V(2) disabled endpoint '172.17.0.4:8080' on backend/server 'default_app_8080/srv003'
INFO-V(2) disabled endpoint '172.17.0.6:8080' on backend/server 'default_app_8080/srv005'
INFO-V(2) disabled endpoint '172.17.0.8:8080' on backend/server 'default_app_8080/srv007'
INFO-V(2) disabled endpoint '172.17.0.9:8080' on backend/server 'default_app_8080/srv008'
`,
		},
		// 11
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
				b.AcquireEndpoint("172.17.0.4", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				c.config.Backends().AcquireBackend("default", "app", "8080").Dynamic.DynUpdate = true
			},
			expected: []string{
				"srv001:127.0.0.1:1023:1",
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 state maint
set server default_app_8080/srv001 addr 127.0.0.1 port 1023
set server default_app_8080/srv001 weight 0
set server default_app_8080/srv002 state maint
set server default_app_8080/srv002 addr 127.0.0.1 port 1023
set server default_app_8080/srv002 weight 0
set server default_app_8080/srv003 state maint
set server default_app_8080/srv003 addr 127.0.0.1 port 1023
set server default_app_8080/srv003 weight 0
`,
			logging: `
INFO-V(2) disabled endpoint '172.17.0.2:8080' on backend/server 'default_app_8080/srv001'
INFO-V(2) disabled endpoint '172.17.0.3:8080' on backend/server 'default_app_8080/srv002'
INFO-V(2) disabled endpoint '172.17.0.4:8080' on backend/server 'default_app_8080/srv003'
`,
		},
		// 12
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
		// 13
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AddEmptyEndpoint()
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1
`,
			logging: `INFO-V(2) added endpoint '172.17.0.3:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
		},
		// 14
		{
			doconfig1: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				b1.Dynamic.DynUpdate = true
				b1.Dynamic.MinFreeSlots = 1
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynUpdate = true
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
		// 15
		{
			doconfig2: func(c *testConfig) {
				c.config.Backends().AcquireBackend("default", "app", "8080").Dynamic.DynUpdate = true
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
		// 16
		{
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
		// 17
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1`,
			logging: `INFO-V(2) added endpoint '172.17.0.3:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
		},
		// 18
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1`,
			logging: `
INFO-V(2) added endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		// 19
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Label = "green"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
				"srv002:127.0.0.1:1023:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 state maint
set server default_app_8080/srv002 addr 127.0.0.1 port 1023
set server default_app_8080/srv002 weight 0`,
			logging: `
INFO-V(2) disabled endpoint '172.17.0.3:8080' on backend/server 'default_app_8080/srv002'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		// 20
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Label = "green"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Label = "green"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1`,
			cmdOutput: []string{
				"IP changed from '172.17.0.3' to '172.17.0.4', no need to change the port by 'stats socket command'",
				"",
				"",
			},
			logging: `
INFO-V(2) response from server: IP changed from '172.17.0.3' to '172.17.0.4', no need to change the port by 'stats socket command'
INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		// 21
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = false
				b.Dynamic.MinFreeSlots = 4
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.3:8080:1",
			},
			dynamic: false,
			logging: `
INFO-V(2) backend 'default_app_8080' changed and its dynamic-scaling is 'false'
INFO-V(2) need to reload due to config changes: [backends]`,
		},
		// 22
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.Dynamic.DynUpdate = false
				b.Dynamic.MinFreeSlots = 4
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = false
				b.Dynamic.MinFreeSlots = 4
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.2:8080:1",
			},
			dynamic: true,
		},
		// 23 - test that we're able to update when a cookie value of acquired
		// existing endpoint exactly matches and cookie affinity is enabled
		// even with "preserve" cookie mode
		{
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
				b1.Dynamic.DynUpdate = true
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1
`,
			logging: `INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
		},
		// 24 - test that we're unable to update when a cookie value of acquired
		// existing endpoint doesn't match and "preserve" cookie mode is enabled
		{
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
				b1.Dynamic.DynUpdate = true
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynUpdate = true
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
		// 25 - test that we're able to update when a cookie value of acquired
		// existing endpoint doesn't match and "preserve" cookie mode is not enabled
		// (eg. it doesn't care to preserve the cookie value, so still updates)
		{
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
				b1.Dynamic.DynUpdate = true
				c.config.Backends().DefaultBackend = b1
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1`,
			logging: `INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
		},
		// 26
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				c.config.backends.DefaultBackend = b
				b.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				c.config.backends.DefaultBackend = b
				b.Dynamic.DynUpdate = true
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.3:8080:1",
			},
			dynamic: true,
			cmd: `
set server default_app_8080/srv001 addr 172.17.0.3 port 8080
set server default_app_8080/srv001 state ready
set server default_app_8080/srv001 weight 1`,
			logging: `INFO-V(2) updated endpoint '172.17.0.3:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv001'`,
		},
		// 27
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Resolver = "k8s"
				b.AcquireEndpoint("172.17.0.2", 8080, "")
				b.AddEmptyEndpoint()
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Resolver = "k8s"
				b.Dynamic.DynUpdate = true
				b.AcquireEndpoint("172.17.0.3", 8080, "")
			},
			expected: []string{
				"srv001:172.17.0.3:8080:1",
				"srv002:127.0.0.1:1023:1",
			},
			dynamic: true,
		},
		// 28
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Name = "srv002"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Name = "srv003"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
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
set server default_app_8080/srv002 state ready
set server default_app_8080/srv002 weight 1
set server default_app_8080/srv003 addr 172.17.0.5 port 8080
set server default_app_8080/srv003 state ready
set server default_app_8080/srv003 weight 1
`,
			cmdOutput: []string{
				"No such server.",
				"No such server.",
			},
			logging: `
WARN unrecognized response adding/updating endpoint default_app_8080/srv002: No such server.
WARN unrecognized response adding/updating endpoint default_app_8080/srv003: No such server.
INFO-V(2) need to reload due to config changes: [backends]
`,
		},
		// 29
		{
			doconfig1: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.AcquireEndpoint("172.17.0.2", 8080, "").Name = "srv002"
				b.AcquireEndpoint("172.17.0.3", 8080, "").Name = "srv003"
			},
			doconfig2: func(c *testConfig) {
				b := c.config.Backends().AcquireBackend("default", "app", "8080")
				b.Dynamic.DynUpdate = true
			},
			expected: []string{
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
			},
			dynamic: false,
			cmd: `
set server default_app_8080/srv002 state maint
set server default_app_8080/srv002 addr 127.0.0.1 port 1023
set server default_app_8080/srv002 weight 0
set server default_app_8080/srv003 state maint
set server default_app_8080/srv003 addr 127.0.0.1 port 1023
set server default_app_8080/srv003 weight 0
`,
			cmdOutput: []string{
				"No such server.",
				"No such server.",
			},
			logging: `
WARN unrecognized response disabling endpoint default_app_8080/srv002: No such server.
WARN unrecognized response disabling endpoint default_app_8080/srv003: No such server.
INFO-V(2) need to reload due to config changes: [backends]
`,
		},
		// 28
		{
			doconfig1: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h2 := c.config.Hosts().AcquireHost("domain2.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h2.TLS.TLSFilename = "/tmp/domain2.pem"
				h1.TLS.TLSHash = "1"
				h2.TLS.TLSHash = "2"
			},
			doconfig2: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h2 := c.config.Hosts().AcquireHost("domain2.local")
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
		// 29
		{
			doconfig1: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
			},
			doconfig2: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain2.pem"
				h1.TLS.TLSHash = "2"
			},
			dynamic: false,
			logging: `
INFO-V(2) diff outside server certificate of host 'domain1.local'
INFO-V(2) need to reload due to config changes: [hosts]
`,
		},
		// 30
		{
			doconfig1: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h2 := c.config.Hosts().AcquireHost("domain2.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h2.TLS.TLSFilename = ""
				h1.TLS.TLSHash = "1"
				h2.TLS.TLSHash = "2"
			},
			doconfig2: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h2 := c.config.Hosts().AcquireHost("domain2.local")
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
		// 31
		{
			doconfig1: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
			},
			doconfig2: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
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
INFO-V(2) need to reload due to config changes: [hosts]
`,
		},
		// 32
		{
			doconfig1: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
				c.config.Hosts().AcquireHost("domain2.local")
			},
			doconfig2: func(c *testConfig) {
				h1 := c.config.Hosts().AcquireHost("domain1.local")
				h1.TLS.TLSFilename = "/tmp/domain1.pem"
				h1.TLS.TLSHash = "1"
			},
			dynamic: false,
			logging: `
INFO-V(2) removed host 'domain2.local'
INFO-V(2) need to reload due to config changes: [hosts]
`,
		},
	}
	readFile = func(filename string) ([]byte, error) {
		return []byte("<content>"), nil
	}
	for i, test := range testCases {
		c := setup(t)
		if test.doconfig1 != nil {
			test.doconfig1(c)
		}
		c.instance.config.Commit()
		hostnames := []string{}
		for hostname := range c.config.hosts.Items() {
			hostnames = append(hostnames, hostname)
		}
		c.config.Hosts().RemoveAll(hostnames)
		backendIDs := []types.BackendID{}
		for _, backend := range c.config.Backends().Items() {
			backendIDs = append(backendIDs, backend.BackendID())
		}
		c.config.Backends().RemoveAll(backendIDs)
		if test.doconfig2 != nil {
			test.doconfig2(c)
		}
		clientMock := &clientMock{
			cmdOutput: test.cmdOutput,
		}
		dynUpdater := c.instance.newDynUpdater(clientMock)
		dynamic := dynUpdater.update()
		var actual []string
		for _, ep := range c.config.Backends().AcquireBackend("default", "app", "8080").Endpoints {
			actual = append(actual, fmt.Sprintf("%s:%s:%d:%d", ep.Name, ep.IP, ep.Port, ep.Weight))
		}
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("endpoints expected and actual differs on %d -- expected: %v -- actual: %v",
				i, test.expected, actual)
		}
		if dynamic != test.dynamic {
			t.Errorf("dynamic expected as '%t' on %d, but was '%t'", test.dynamic, i, dynamic)
		}
		cmd := strings.TrimSpace(clientMock.cmd)
		test.cmd = strings.TrimSpace(test.cmd)
		if cmd != test.cmd {
			t.Errorf("cmd differs on %d:\n%s", i, diff.Diff(test.cmd, cmd))
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
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
	return cli.cmdOutput, nil
}

func (cli *clientMock) Unlistening() error {
	return nil
}

func (cli *clientMock) Close() error {
	return nil
}
