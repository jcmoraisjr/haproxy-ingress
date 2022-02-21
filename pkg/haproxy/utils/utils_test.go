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

func TestHAProxyCommand(t *testing.T) {
	// needs a running HAProxy and admin socket at /tmp/h.sock
	// also, it will output the response in the error pipe, so will always fail
	// TODO create a test and temp server where HAProxyCommand can connect to
	/*
		out, err := HAProxyCommand("/tmp/h.sock", nil, "show info")
		if err != nil {
			t.Errorf("%v", err)
		} else {
			t.Errorf("%d %v", len(out[0]), out[0])
		}
	*/
}

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
		// 7
		{
			cmdOutput: []string{`#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
1001            master          0               1128            0d00h02m28s     2.2.3-0e58a34
# workers
3115            worker          1001            11              0d00h00m00s     2.2.3-0e58a34
3116            worker          1002  `},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 1001, RPID: 0, Reloads: 1128},
				Workers: []Proc{
					{Type: "worker", PID: 3115, RPID: 1001, Reloads: 11},
					{Type: "worker", PID: 3116, RPID: 1002, Reloads: 0},
				},
			},
		},
		// 8
		{
			cmdOutput: []string{`#<PID>          <type>          <reloads>       <uptime>        <version>
94292           master          0 [failed: 0]   0d00h00m04s     2.5.3-abf078b
# workers
94293           worker       	   0               0d00h00m04s     2.5.3-abf078b
# programs
`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 94292, Reloads: 0, Failed: 0, Uptime: "0d00h00m04s", Version: "2.5.3-abf078b"},
				Workers: []Proc{
					{Type: "worker", PID: 94293, Reloads: 0, Uptime: "0d00h00m04s", Version: "2.5.3-abf078b"},
				},
			},
		},
		// 9
		{
			cmdOutput: []string{`#<PID>          <type>          <reloads>       <uptime>        <version>
94292           master          1035 [failed: 57] 0d00h09m40s     2.5.3-abf078b
# workers
913             worker          57              0d00h04m45s     2.5.3-abf078b
# programs
`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 94292, Reloads: 1035, Failed: 57, Uptime: "0d00h09m40s", Version: "2.5.3-abf078b"},
				Workers: []Proc{
					{Type: "worker", PID: 913, Reloads: 57, Uptime: "0d00h04m45s", Version: "2.5.3-abf078b"},
				},
			},
		},
		// 10
		{
			cmdOutput: []string{`#<PID>          <type>          <reloads>       <uptime>        <version>
2965            master          1420 [failed: 0] 0d00h11m09s     2.5.3-abf078b
# workers
10668           worker          0               0d00h00m59s     2.5.3-abf078b
# old workers
9529            worker          240             0d00h01m50s     2.5.3-abf078b
9463            worker          254             0d00h01m53s     2.5.3-abf078b
9401            worker          268             0d00h01m56s     2.5.3-abf078b
9335            worker          282             0d00h01m59s     2.5.3-abf078b
9273            worker          296             0d00h02m02s     2.5.3-abf078b
9209            worker          310             0d00h02m05s     2.5.3-abf078b
# programs
`},
			expOutput: &ProcTable{
				Master: Proc{Type: "master", PID: 2965, Reloads: 1420, Failed: 0, Uptime: "0d00h11m09s", Version: "2.5.3-abf078b"},
				Workers: []Proc{
					{Type: "worker", PID: 10668, Reloads: 0, Uptime: "0d00h00m59s", Version: "2.5.3-abf078b"},
				},
				OldWorkers: []Proc{
					{Type: "worker", PID: 9529, Reloads: 240, Uptime: "0d00h01m50s", Version: "2.5.3-abf078b"},
					{Type: "worker", PID: 9463, Reloads: 254, Uptime: "0d00h01m53s", Version: "2.5.3-abf078b"},
					{Type: "worker", PID: 9401, Reloads: 268, Uptime: "0d00h01m56s", Version: "2.5.3-abf078b"},
					{Type: "worker", PID: 9335, Reloads: 282, Uptime: "0d00h01m59s", Version: "2.5.3-abf078b"},
					{Type: "worker", PID: 9273, Reloads: 296, Uptime: "0d00h02m02s", Version: "2.5.3-abf078b"},
					{Type: "worker", PID: 9209, Reloads: 310, Uptime: "0d00h02m05s", Version: "2.5.3-abf078b"},
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
