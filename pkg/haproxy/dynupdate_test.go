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
			logging: `INFO-V(2) diff outside backends: [global]`,
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
				"srv001:172.17.0.4:8080:1",
				"srv002:172.17.0.3:8080:1",
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
			logging: `INFO-V(2) added endpoints on backend 'default_app_8080'`,
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
				"srv001:127.0.0.1:1023:1",
				"srv002:172.17.0.3:8080:1",
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
				"srv001:172.17.0.3:8080:1",
				"srv002:172.17.0.2:8080:1",
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
				"srv001:127.0.0.1:1023:1",
				"srv002:127.0.0.1:1023:1",
				"srv003:127.0.0.1:1023:1",
				"srv004:172.17.0.5:8080:1",
				"srv005:127.0.0.1:1023:1",
				"srv006:172.17.0.7:8080:1",
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
			logging: `INFO-V(2) added endpoints on backend 'default_app_8080'`,
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
				c.config.Backends().SetDefaultBackend(b1)
				b2 := c.config.Backends().AcquireBackend("default", "app", "8080")
				b2.AcquireEndpoint("172.17.0.2", 8080, "")
			},
			doconfig2: func(c *testConfig) {
				b1 := c.config.Backends().AcquireBackend("default", "default_backend", "8080")
				b1.Dynamic.DynUpdate = true
				b1.Dynamic.MinFreeSlots = 1
				c.config.Backends().SetDefaultBackend(b1)
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
			logging: `INFO-V(2) added endpoints on backend 'default_app_8080'`,
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
			logging: `INFO-V(2) added backend 'default_app_8080'`,
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
			logging: `INFO-V(2) added backend 'default_app_8080'`,
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
			logging: `INFO-V(2) added endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
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
			logging: `INFO-V(2) disabled endpoint '172.17.0.3:8080' on backend/server 'default_app_8080/srv002'`,
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
			logging: `INFO-V(2) updated endpoint '172.17.0.4:8080' weight '1' state 'ready' on backend/server 'default_app_8080/srv002'`,
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
			logging: `INFO-V(2) backend 'default_app_8080' changed and its dynamic-scaling is 'false'`,
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
	}
	for i, test := range testCases {
		c := setup(t)
		instance := c.instance.(*instance)
		if test.doconfig1 != nil {
			test.doconfig1(c)
		}
		instance.config.Commit()
		backendIDs := []types.BackendID{}
		for _, backend := range c.config.Backends().Items() {
			if backend != c.config.Backends().DefaultBackend() {
				backendIDs = append(backendIDs, backend.BackendID())
			}
		}
		c.config.Backends().RemoveAll(backendIDs)
		if test.doconfig2 != nil {
			test.doconfig2(c)
		}
		var cmd string
		dynUpdater := instance.newDynUpdater()
		dynUpdater.cmd = func(socket string, observer func(duration time.Duration), command ...string) ([]string, error) {
			for _, c := range command {
				cmd = cmd + c + "\n"
			}
			return []string{}, nil
		}
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
		cmd = strings.TrimSpace(cmd)
		test.cmd = strings.TrimSpace(test.cmd)
		if cmd != test.cmd {
			t.Errorf("cmd differs on %d:\n%s", i, diff.Diff(test.cmd, cmd))
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
