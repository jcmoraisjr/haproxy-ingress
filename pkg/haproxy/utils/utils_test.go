/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestHAProxyProcs(t *testing.T) {
	testCases := []struct {
		cmdOutput []string
		cmdError  error
		expOutput *ProcTable
		expError  bool
	}{
		// 0
		{
			expOutput: &ProcTable{},
		},
		// 1
		{
			cmdError: fmt.Errorf("fail"),
			expError: true,
		},
		// 2
		{
			cmdOutput: []string{`#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
1               master          0               0               0d00h00m08s     2.2.3-0e58a34
# workers
# old workers
# programs

`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 1, RPID: 0, Reloads: 0},
			},
		},
		// 3
		{
			cmdOutput: []string{`#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
1               master          0               1               0d00h00m28s     2.2.3-0e58a34
# workers
2               worker          1               0               0d00h00m00s     2.2.3-0e58a34
# old workers
# programs

`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 1, RPID: 0, Reloads: 1},
				Workers: []Proc{
					{Type: "worker", PID: 2, RPID: 1, Reloads: 0},
				},
			},
		},
		// 4
		{
			cmdOutput: []string{`#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
1               master          0               2               0d00h01m28s     2.2.3-0e58a34
# workers
3               worker          1               0               0d00h00m00s     2.2.3-0e58a34
# old workers
2               worker          [was: 1]        1               0d00h00m28s     2.2.3-0e58a34
# programs

`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 1, RPID: 0, Reloads: 2},
				Workers: []Proc{
					{Type: "worker", PID: 3, RPID: 1, Reloads: 0},
				},
				OldWorkers: []Proc{
					{Type: "worker", PID: 2, RPID: 1, Reloads: 1},
				},
			},
		},
		// 5
		{
			cmdOutput: []string{`#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
1               master          0               3               0d00h02m28s     2.2.3-0e58a34
# workers
# old workers
3               worker          [was: 1]        2               0d00h01m28s     2.2.3-0e58a34
# programs

`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 1, RPID: 0, Reloads: 3},
				OldWorkers: []Proc{
					{Type: "worker", PID: 3, RPID: 1, Reloads: 2},
				},
			},
		},
		// 6
		{
			cmdOutput: []string{`#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
1001            master          0               1128            0d00h02m28s     2.2.3-0e58a34
# workers
3115            worker          1001            11              0d00h00m00s     2.2.3-0e58a34
3116            worker          1002            11              0d00h00m00s     2.2.3-0e58a34
# old workers
2112            worker          [was: 1001]     128             0d00h01m28s     2.2.3-0e58a34
2113            worker          [was: 1002]     128             0d00h01m28s     2.2.3-0e58a34
2114            worker          [was: 1003]     128             0d00h01m28s     2.2.3-0e58a34
# programs

`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 1001, RPID: 0, Reloads: 1128},
				Workers: []Proc{
					{Type: "worker", PID: 3115, RPID: 1001, Reloads: 11},
					{Type: "worker", PID: 3116, RPID: 1002, Reloads: 11},
				},
				OldWorkers: []Proc{
					{Type: "worker", PID: 2112, RPID: 1001, Reloads: 128},
					{Type: "worker", PID: 2113, RPID: 1002, Reloads: 128},
					{Type: "worker", PID: 2114, RPID: 1003, Reloads: 128},
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		c.cmdOutput = test.cmdOutput
		c.cmdError = test.cmdError
		out, err := HAProxyProcs("socket")
		if !reflect.DeepEqual(out, test.expOutput) {
			t.Errorf("output differs on %d - expected: %+v, actual: %+v", i, test.expOutput, out)
		}
		if (err != nil) != test.expError {
			t.Errorf("error differs on %d - expected: %v, actual: %v", i, test.expError, err)
		}
		c.tearDown()
	}
}

func TestHAProxyProcsLoop(t *testing.T) {
	testCases := []struct {
		reload   time.Duration
		minDelay time.Duration
		maxCnt   int
	}{
		// 0
		{
			reload:   0,
			minDelay: 1 * time.Millisecond,
			maxCnt:   1,
		},
		// 1
		{
			reload:   20 * time.Millisecond,
			minDelay: (1 + 2 + 4 + 8 + 16) * time.Millisecond,
			maxCnt:   5,
		},
		// 2
		{
			reload:   450 * time.Millisecond,
			minDelay: (1 + 2 + 4 + 8 + 16 + 32 + 64 + 96 + 128 + 160) * time.Millisecond,
			maxCnt:   10,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		c.cmdError = syscall.ECONNREFUSED
		time.AfterFunc(test.reload, func() { c.cmdError = nil })
		start := time.Now()
		_, err := HAProxyProcs("")
		if err != nil {
			t.Errorf("%d should not return an error: %w", i, err)
		}
		elapsed := time.Now().Sub(start)
		if elapsed < test.minDelay {
			t.Errorf("elapsed in %d is '%s' and should not be lower than min '%s'", i, elapsed.String(), test.minDelay.String())
		}
		if c.callCnt > test.maxCnt {
			t.Errorf("callCnt in %d is '%d' and should not be greater than max '%d'", i, c.callCnt, test.maxCnt)
		}
	}
}

type testConfig struct {
	t         *testing.T
	cmdOutput []string
	cmdError  error
	callCnt   int
}

func setup(t *testing.T) *testConfig {
	c := &testConfig{
		t: t,
	}
	haproxyCmd = c.haproxyCommand
	return c
}

func (c *testConfig) tearDown() {}

func (c *testConfig) haproxyCommand(string, func(duration time.Duration), ...string) ([]string, error) {
	c.callCnt++
	return c.cmdOutput, c.cmdError
}
