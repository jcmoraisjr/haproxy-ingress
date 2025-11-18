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
	"context"
	"fmt"
	"reflect"
	"regexp"
	"syscall"
	"testing"
	"time"
)

func TestSocket(t *testing.T) {
	// needs a running HAProxy with the conf below:
	//     global
	//         stats socket unix@/tmp/h.sock level admin
	//         stats timeout 1s
	//     defaults
	//         timeout client 1m
	//         timeout server 1m
	//         timeout connect 5s
	//     listen l1
	//         bind :8000
	//         bind :8443 ssl crt /tmp/crt.pem
	// create a self-signed certificate:
	//     openssl req -x509 -newkey rsa:2048 -subj /CN=localhost -nodes -out crt -keyout key
	//     cat crt key >/tmp/crt.pem
	//     rm crt key
	// start with:
	//     haproxy -f h.cfg -W -S /tmp/m.sock
	//
	// TODO create a test and temp server where socket commands can connect to
	// - although integration tests do a really good job already
	t.SkipNow()
	testSocket(t, false)
	testSocket(t, true)
}

func testSocket(t *testing.T, keepalive bool) {
	clisock := "/tmp/h.sock"
	mastersock := "/tmp/m.sock"
	crtFile := "/tmp/crt.pem"
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
		// 6
		{
			cmd: []string{
				fmt.Sprintf("set ssl cert %s <<\n%s\n", crtFile, crtPayload),
				fmt.Sprintf("commit ssl cert %s", crtFile),
			},
			cmdChk: []*regexp.Regexp{
				regexp.MustCompile(`Transaction created for.*/tmp/crt.pem!$`),
				regexp.MustCompile(`Success!`),
			},
		},
	}
	ctx := context.Background()
	clientSocket := make([]HAProxySocket, len(testCases))
	clientSocketPos := make([]HAProxySocket, len(testCases))
	masterSocket := make([]HAProxySocket, len(testCases))
	for i, test := range testCases {
		clientSocket[i] = NewSocket(ctx, clisock, keepalive)
		clientSocketPos[i] = NewSocket(ctx, clisock, false)
		masterSocket[i] = NewSocket(ctx, mastersock, keepalive)
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
					t.Errorf("cmd '%s' on %d keepalive %t output\nlen: %d\nbytes: %v\n%v", test.cmd[j], i, keepalive, len(o), []byte(o), o)
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

const crtPayload = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDIBIkh7vGNLTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjEwNzMxMjE1MTE4WhcNMjEwODMwMjE1MTE4WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3
dZe4HdLAvu444orR2aOSVyHwTqxNaq36GiSu8Xv3QWzUBhOgsZ8qF5kYXQnFyJNr
xcI0/JKZsy8F4buiibjL8+SyDdHrFMN+3kPv5xd5IC55pb+jFKgtuJPNeHJ+Rjaa
k/gGlwnLm6RRIZ9387SFfJhoWQiUT9+sBK3wJoxlLVKyqhmbqvRRi3yWm3kkQyDL
Psi7fofn6pkxuKaxUEx6+i8RA5sfYXQxy5xwGSdfRiNsUbnZDde1B49dRKik9VWM
NeJ9mmx0oaBg6KGmkv+5ymMs0dqDYNB4W36rjZt/I7XLC0GcEvOZFGt/f6KoRcvG
fYXOfaixFaqWCrvuwKS3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBACriKYnsAUKL
UH31jvkJpx6dTO2ZxRVj7N6EqLCPYg8ICMSaykL4fhhl0glolkpTeBSvWf+wTbAI
6n5yBY7HYLYHgZiR+LxsJJhxvgaVTp9HQJ5DWKffiLs8pTI7dnzOFt02xcSQFKMQ
0V29XRyx0tOt2SmksFDTe4sGn7nRnK+QH6zjwqpFvoPS34Ydr31EDrD/dUTTXAQ4
kQ0vp7q2cIlLveuOctt0ErQzRjmY2l61XRALngJR2s4IwxHTlvFd+La0/TOW07gz
2Iy6IRd4biaotF2sMlb8KeEC09qBhc7uqf2SE0gAUGgai0bzjmZWTAGOt47vKz4k
5GOIEZDcZlg=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3dZe4HdLAvu44
4orR2aOSVyHwTqxNaq36GiSu8Xv3QWzUBhOgsZ8qF5kYXQnFyJNrxcI0/JKZsy8F
4buiibjL8+SyDdHrFMN+3kPv5xd5IC55pb+jFKgtuJPNeHJ+Rjaak/gGlwnLm6RR
IZ9387SFfJhoWQiUT9+sBK3wJoxlLVKyqhmbqvRRi3yWm3kkQyDLPsi7fofn6pkx
uKaxUEx6+i8RA5sfYXQxy5xwGSdfRiNsUbnZDde1B49dRKik9VWMNeJ9mmx0oaBg
6KGmkv+5ymMs0dqDYNB4W36rjZt/I7XLC0GcEvOZFGt/f6KoRcvGfYXOfaixFaqW
CrvuwKS3AgMBAAECggEAEY9m60+neZ2M7dL5WKbNWleOvxK4uVxJtNPFyR0CMaOI
iC7guBPoWT4TAFr/cXgGbF1sfmfinGWjTZvSuvcVwifhLw3VlvvQzpb1x8PF4mkr
Kaes1S5H/sBZHWS3CNEtrtQU/IR+goeuTbm7Kt8f21sWt342LQQMM8nq4D7AV3q6
ZGRjvNytDMdJVEJTIaGWZdBu/TgOgaYTJ3qirRUREkN8UHWey0QfEbCLuvlCxVyg
Bc4tQRF63vgILsAwGQdicbe/RLjlOjsMKFwQyMpT7mSXUREbrTeYiCDQAXZxzdK1
PNSaLwyYwNUer6ahlrXgOVRwoAUNK+uSWobhz63E4QKBgQDw6X+JjeMQliVSWX+n
NMKtskcYuOOEa4uNMlB40uVkU7QeZqbMe6a4uS7PDW/D6vhAg1yiJ83/ixdm3YBo
IMM4RLj3HUPaL5fomR55ukde8Zgl5W2jqONbBNi9ugv4TISRxiZ4ZAvIAaCoFRf3
tA2xshIL0hNlBwpj53MPaPew0QKBgQDC8vbkZb/534r4l3nKBS7pD/SYEamYC6vw
y7WhP+w6Fgd65Utpb5PzBWGcZHUpj4IbdG/tfCqqpH50syv/K8gxjrvuLEyIwX8n
F88BpjhrAY20vkDNQ+QGLJG5tXTvTBDqfwDSX94Kw1Pzii7PV6daJI2tTlVnFpvQ
NQKp2NmfBwKBgBCPbHXvK/Gi8JPVlSHQTaWVALAhXXpnziL5l3CGxr/7xQDl+4dI
5LAEAsS23rzv9PqyTPbUl6N+UzB9/2qo/eJrTu+lsllYNjAF/oNNm8RaBSRtvfin
DmHeVmvMUzBRSjefEFvsPKcV/Y4wTQJ4/Qv++qCXYz/pmPw/F7iydXxRAoGAZMfm
CrzvOeXumgT02RNE5QdykwrOeePOx3UIOIwrOvwYcdgH3EHqYj/t7kOgrhOaV0ci
dcsy43SWSw41OH0RyUzYqpAMIManTTZptZiQogDzmPSh23u1bdusmizMfsj8Fb4C
Vr9osne39rcA6/+MbHVpKKbOT7TIaCJ/df68whECgYEAotmmXBsVxlrGev8Idnut
P7eOp7uHMV8pq7r+FX+VTUELmYpZBvDKi0pPHRDMsUKJlOCiDQaC+7u4hJh27fjM
+ZiWZWtSEvhEUgehlxollglhh/vL+Cv/o7PucVqtSyv/v5cs3hSJCmTR2Z1G1DHs
30newKUAPkQo6uSiKXwXRIg=
-----END PRIVATE KEY-----
`

func TestHAProxyProcs(t *testing.T) {
	testCases := []struct {
		cmdOutput []string
		cmdError  error
		hasSock   bool
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
			hasSock:  true,
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
	ctx := context.Background()
	for i, test := range testCases {
		c := setup(t)
		cli := &clientMock{
			cmdOutput: test.cmdOutput,
			cmdError:  test.cmdError,
			hasSock:   test.hasSock,
		}
		out, err := HAProxyProcs(ctx, cli)
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
			minDelay: 0 * time.Millisecond,
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
			reload:   650 * time.Millisecond,
			minDelay: (1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 + 192 + 256) * time.Millisecond,
			maxCnt:   10,
		},
	}
	ctx := context.Background()
	for i, test := range testCases {
		c := setup(t)
		cli := &clientMock{
			cmdError: syscall.ECONNREFUSED,
		}
		time.AfterFunc(test.reload, func() { cli.cmdError = nil })
		start := time.Now()
		_, err := HAProxyProcs(ctx, cli)
		if err != nil {
			t.Errorf("%d should not return an error: %v", i, err)
		}
		elapsed := time.Since(start)
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
	hasSock   bool
}

func (c *clientMock) Address() string {
	if c.hasSock {
		return "/dev/null"
	}
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
