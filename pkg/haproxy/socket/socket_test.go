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

package socket

import (
	"fmt"
	"reflect"
	"regexp"
	"syscall"
	"testing"
	"time"
)

func TestSocket(t *testing.T) {
	// needs a running HAProxy and admin socket at /tmp/h.sock with stats timeout 1s
	// start with haproxy -f h.cfg -W -S /tmp/m.sock
	// TODO create a test and temp server where HAProxyCommand can connect to
	//
	// testSocket(t, false)
	// testSocket(t, true)
}

func testSocket(t *testing.T, keepalive bool) {
	clisock := "/tmp/h.sock"
	mastersock := "/tmp/m.sock"
	socketTimeout := time.Second
	regexpOneSession := regexp.MustCompile("^0x[0-9a-f]+: proto=[^\n]+$")
	regexpTwoSessions := regexp.MustCompile("^(0x[0-9a-f]+: proto=[^\n]+\n?){2}$")
	regexpThreeSessions := regexp.MustCompile("^(0x[0-9a-f]+: proto=[^\n]+\n?){3}$")
	regexpShowInfo := regexp.MustCompile("\nNbthread: [0-9]+\n")
	regexpShowProc := regexp.MustCompile("^#<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>      \n")
	regexpShowCliSockets := regexp.MustCompile("^# socket lvl processes\n")
	var regexpPos1ShowSess, regexpPos2ShowSess *regexp.Regexp
	if keepalive {
		regexpPos1ShowSess = regexpTwoSessions
		regexpPos2ShowSess = regexpThreeSessions
	} else {
		regexpPos1ShowSess = regexpOneSession
		regexpPos2ShowSess = regexpOneSession
	}
	testCases := []struct {
		cmd        []string
		cmdChk     []*regexp.Regexp
		cmdPos     string
		cmdPosChk  *regexp.Regexp
		master     bool
		waitBefore time.Duration
	}{
		// 0
		{
			cmd:       []string{"show sess"},
			cmdChk:    []*regexp.Regexp{regexpOneSession},
			cmdPos:    "show sess",
			cmdPosChk: regexpPos1ShowSess,
		},
		// 1
		{
			waitBefore: socketTimeout / 4,
			cmd:        []string{"show info"},
			cmdChk:     []*regexp.Regexp{regexpShowInfo},
			cmdPos:     "show sess",
			cmdPosChk:  regexpPos2ShowSess,
		},
		// 2
		{
			waitBefore: 3 * socketTimeout / 2,
			cmd:        []string{"show sess"},
			cmdChk:     []*regexp.Regexp{regexpOneSession},
			cmdPos:     "show sess",
			cmdPosChk:  regexpPos1ShowSess,
		},
		// 3
		{
			cmd:    []string{"show sess", "show info"},
			cmdChk: []*regexp.Regexp{regexpPos1ShowSess, regexpShowInfo},
		},
		// 4
		{
			cmd:    []string{"show proc"},
			cmdChk: []*regexp.Regexp{regexpShowProc},
			master: true,
		},
		// 5
		{
			cmd:    []string{"show cli sockets"},
			cmdChk: []*regexp.Regexp{regexpShowCliSockets},
			master: true,
		},
	}
	clientSocket := make([]HAProxySocket, len(testCases))
	clientSocketPos := make([]HAProxySocket, len(testCases))
	masterSocket := make([]HAProxySocket, len(testCases))
	for i, test := range testCases {
		clientSocket[i] = NewSocket(clisock, keepalive)
		clientSocketPos[i] = NewSocket(clisock, false)
		masterSocket[i] = NewSocket(mastersock, keepalive)
		time.Sleep(test.waitBefore)
		var sock, sockPos HAProxySocket
		if test.master {
			sock = masterSocket[i]
		} else {
			if test.waitBefore > socketTimeout && i > 0 {
				// reuse a connection, use newConn()
				clientSocket[i] = clientSocket[i-1]
			}
			sock = clientSocket[i]
			sockPos = clientSocketPos[i]
		}
		if out, err := sock.Send(nil, test.cmd...); err == nil {
			for j, o := range out {
				if test.cmdChk[j] == nil || !test.cmdChk[j].MatchString(o) {
					t.Errorf("cmd '%s' on %d keepalive %t output\nlen: %d\nbytes: %v\n%v", test.cmd, i, keepalive, len(o), []byte(o), o)
				}
			}
			if test.cmdPos != "" {
				if out, err = sockPos.Send(nil, test.cmdPos); err == nil {
					if test.cmdPosChk == nil || !test.cmdPosChk.MatchString(out[0]) {
						t.Errorf("cmdPos '%s' on %d keepalive %t output\nlen: %d\nbytes: %v\n%v", test.cmdPos, i, keepalive, len(out[0]), []byte(out[0]), out[0])
					}
				} else {
					t.Errorf("cmdPos error on %d keepalive %t: %v", i, keepalive, err)
				}
			}
		} else {
			t.Errorf("cmd error on %d keepalive %t: %v", i, keepalive, err)
		}
	}
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
	}
	for i, test := range testCases {
		c := setup(t)
		cli := &clientMock{
			cmdOutput: test.cmdOutput,
			cmdError:  test.cmdError,
		}
		out, err := HAProxyProcs(cli)
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
		cli := &clientMock{
			cmdError: syscall.ECONNREFUSED,
		}
		time.AfterFunc(test.reload, func() { cli.cmdError = nil })
		start := time.Now()
		_, err := HAProxyProcs(cli)
		if err != nil {
			t.Errorf("%d should not return an error: %w", i, err)
		}
		elapsed := time.Now().Sub(start)
		if elapsed < test.minDelay {
			t.Errorf("elapsed in %d is '%s' and should not be lower than min '%s'", i, elapsed.String(), test.minDelay.String())
		}
		if cli.callCnt > test.maxCnt {
			t.Errorf("callCnt in %d is '%d' and should not be greater than max '%d'", i, cli.callCnt, test.maxCnt)
		}
		c.tearDown()
	}
}

type testConfig struct {
	t *testing.T
}

func setup(t *testing.T) *testConfig {
	c := &testConfig{
		t: t,
	}
	return c
}

func (c *testConfig) tearDown() {}

type clientMock struct {
	cmdOutput []string
	cmdError  error
	callCnt   int
}

func (c *clientMock) Address() string {
	return ""
}

func (c *clientMock) HasConn() bool {
	return true
}

func (c *clientMock) Send(observer func(duration time.Duration), command ...string) ([]string, error) {
	c.callCnt++
	return c.cmdOutput, c.cmdError
}

func (c *clientMock) Unlistening() error {
	return nil
}

func (c *clientMock) Close() error {
	return nil
}
