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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	k8snet "k8s.io/apimachinery/pkg/util/net"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// HAProxyCommand ...
func HAProxyCommand(socket string, observer func(duration time.Duration), command ...string) ([]string, error) {
	var msg []string
	for _, cmd := range command {
		start := time.Now()
		c, err := net.Dial("unix", socket)
		if err != nil {
			return msg, fmt.Errorf("error connecting to unix socket %s: %w", socket, err)
		}
		defer c.Close()
		if !strings.HasSuffix(cmd, "\n") {
			// haproxy starts the command after receiving a line break
			cmd += "\n"
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(cmd)); err != nil {
			return msg, fmt.Errorf("error sending to unix socket %s: %w", socket, err)
		}
		readBuffer := make([]byte, 1536) // fits all the `show info` response in a single chunck
		var response string
		for {
			r, err := c.Read(readBuffer)
			if err != nil && err != io.EOF {
				// ignore any successfully read data in the case of an error
				return msg, fmt.Errorf("error reading response from unix socket %s: %w", socket, err)
			}
			response += string(readBuffer[:r])
			if r == 0 || strings.HasSuffix(response, "\n\n") {
				// end of the stream if empty (r==0) or response ended with two consecutive line breaks
				// the line breaks are the way haproxy says we reach the end of the stream, since
				// master socket seems to always work on interactive/prompt mode and doesn't close the
				// connection
				break
			}
		}
		msg = append(msg, strings.TrimRight(response, "\n"))
		if observer != nil {
			observer(time.Since(start))
		}
	}
	return msg, nil
}

// ProcTable ...
type ProcTable struct {
	Master     Proc
	Workers    []Proc
	OldWorkers []Proc
}

// Proc ...
type Proc struct {
	Type    string
	PID     int
	RPID    int
	Reloads int
	Failed  int
	Uptime  string
	Version string
}

var haproxyCmd func(string, func(duration time.Duration), ...string) ([]string, error) = HAProxyCommand

// HAProxyProcs reads and converts `show proc` from the master CLI to a ProcTable
// instance. Waits for the reload to complete while master CLI is down and the
// attempt to connect leads to a connection refused. Some context:
// https://www.mail-archive.com/haproxy@formilux.org/msg38415.html
// The amount of time between attempts increases exponentially between 1ms and 64ms,
// and aritmetically betweem 128ms and 1s in order to save CPU on long reload events
// and quit fast on the fastest ones. The whole processing time can be calculated by
// the caller as the haproxy reload time.
func HAProxyProcs(masterSocket string) (*ProcTable, error) {
	maxLogWait := 64 * time.Millisecond
	logFactor := 2
	maxArithWait := 1024 * time.Millisecond
	arithFactor := 32 * time.Millisecond
	wait := time.Millisecond
	for {
		time.Sleep(wait)
		out, err := haproxyCmd(masterSocket, nil, "show proc")
		if !waitHAProxy(masterSocket, err) {
			if len(out) > 0 {
				return buildProcTable(out[0]), err
			}
			if err == nil {
				return &ProcTable{}, nil
			}
			return nil, err
		}
		if wait < maxLogWait {
			wait = time.Duration(logFactor) * wait
		} else if wait < maxArithWait {
			wait = wait + arithFactor
		}
	}
}

func waitHAProxy(sock string, err error) bool {
	if err == nil {
		// connection succeeded, no need to wait (wait = FALSE)
		return false
	}
	if k8snet.IsConnectionRefused(err) || k8snet.IsConnectionReset(err) {
		// connection refused or connection reset, give more time to haproxy (wait = TRUE)
		return true
	}
	// now check if err (which is not nil) means unix socket not found
	// should continue if socket not found, giving more time to haproxy create it
	_, e := os.Stat(sock)
	notFound := e != nil && errors.Is(err, os.ErrNotExist)
	// should wait (wait = TRUE) if file was not found
	return notFound
}

// buildProcTable parses `show proc` output and creates a corresponding ProcTable
//
//
// layout 2.2 up to 2.4
//                   1               3               4               6               8               9
//   0.......|.......6.......|.......2.......|.......8.......|.......4.......|.......0.......|.......6
//   #<PID>          <type>          <relative PID>  <reloads>       <uptime>        <version>
//   1               master          0               2               0d00h01m28s     2.2.3-0e58a34
//   # workers
//   3               worker          1               0               0d00h00m00s     2.2.3-0e58a34
//   # old workers
//   2               worker          [was: 1]        1               0d00h00m28s     2.2.3-0e58a34
//   # programs
//
//
// layout 2.5+
//                   1               3               4               6               8
//   0.......|.......6.......|.......2.......|.......8.......|.......4.......|.......0
//   #<PID>          <type>          <reloads>       <uptime>        <version>
//   1               master          4200 [failed: 42] 0d00h01m28s     2.5.3-abf078b
//   # workers
//   3               worker          0               0d00h00m00s     2.5.3-abf078b
//   # old workers
//   2               worker          1               0d00h00m28s     2.5.3-abf078b
//   # programs
//
func buildProcTable(procOutput string) *ProcTable {
	if strings.Index(procOutput, "relative PID") > 0 {
		// TODO remove after v0.14
		return buildProcTable24(procOutput)
	}
	procTable := ProcTable{}
	old := false
	l := linereader()
	for _, line := range utils.LineToSlice(procOutput) {
		if strings.HasPrefix(line, "#<PID>") {
			l.parseHeader(line)
		} else if len(line) > 0 && line[0] != '#' {
			l.feed(line)
			rpid := l.asInt("<relative_PID>")
			if rpid == 0 {
				rpid = l.asInt("<relative_PID>.was")
			}
			proc := Proc{
				PID:     l.asInt("<PID>"),
				Type:    l.asString("<type>"),
				RPID:    rpid,
				Reloads: l.asInt("<reloads>"),
				Failed:  l.asInt("<reloads>.failed"),
				Uptime:  l.asString("<uptime>"),
				Version: l.asString("<version>"),
			}
			if proc.Type == "master" {
				procTable.Master = proc
			} else if old {
				procTable.OldWorkers = append(procTable.OldWorkers, proc)
			} else {
				procTable.Workers = append(procTable.Workers, proc)
			}
		} else if line == "# old workers" {
			old = true
		}
	}
	return &procTable
}

type line struct {
	t       *tokenizer
	headers []string
	hwidth  int
	fields  map[string]string
}

func linereader() *line {
	return &line{t: &tokenizer{}, hwidth: 16}
}

func (l *line) parseHeader(h string) {
	s := strings.TrimPrefix(h, "#")
	var inside bool
	var pos []int
	for i := range s {
		switch s[i] {
		case '<':
			inside = true
		case '>':
			inside = false
		case ' ':
			if inside {
				pos = append(pos, i)
			}
		}
	}
	for _, i := range pos {
		s = s[:i] + "_" + s[i+1:]
	}
	l.headers = strings.Fields(s)
	l.fields = nil
}

func (l *line) feed(line string) {
	t := l.t
	t.reset(line)
	fields := map[string]string{}
	pos := 0
	for _, h := range l.headers {
		t.skipSpaces()
		for !t.eof() && t.pos-pos < l.hwidth {
			name, value := t.readField()
			if name == "" {
				fields[h] = value
			} else {
				fields[h+"."+name] = value
			}
			t.skipSpaces()
		}
		pos = t.pos
	}
	l.fields = fields
}

func (l *line) asString(h string) string {
	return l.fields[h]
}

func (l *line) asInt(h string) int {
	i, _ := strconv.Atoi(l.asString(h))
	return i
}

type tokenizer struct {
	buf string
	len int
	pos int
}

func (t *tokenizer) reset(buf string) {
	t.buf = buf
	t.len = len(buf)
	t.pos = 0
}

func (t *tokenizer) eof() bool {
	return t.pos >= t.len
}

var isSpace = [256]bool{'\t': true, '\r': true, '\n': true, ' ': true}
var isSpecial = [256]bool{'[': true, ':': true, ']': true}

func (t *tokenizer) skipSpaces() {
	for !t.eof() && isSpace[t.buf[t.pos]] {
		t.pos++
	}
}

func (t *tokenizer) readNextToken() string {
	t.skipSpaces()
	pos := t.pos
	if isSpecial[t.buf[pos]] {
		return string(t.buf[pos])
	}
	for pos < t.len && !isSpace[t.buf[pos]] && !isSpecial[t.buf[pos]] {
		pos++
	}
	return t.buf[t.pos:pos]
}

func (t *tokenizer) readToken() string {
	token := t.readNextToken()
	t.pos += len(token)
	return token
}

func (t *tokenizer) readField() (string, string) {
	token := t.readToken()
	if token != "[" {
		// e.g. `1` or `worker`
		return "", token
	}
	// e.g. `[failed: 2]` or `[was: 1]`
	name := t.readToken()
	_ = t.readToken() // `:`
	value := t.readToken()
	for !t.eof() && t.readToken() != "]" {
		//
	}
	return name, value
}

func buildProcTable24(procOutput string) *ProcTable {
	atoi := func(s string) int {
		i, _ := strconv.Atoi(s)
		return i
	}
	cut := func(s string, i, j int) string {
		l := len(s)
		if i >= l {
			return ""
		}
		if j >= l {
			j = l - 1
		}
		v := strings.TrimSpace(s[i:j])
		if strings.HasPrefix(v, "[") {
			return v[6 : len(v)-1] // `[was: 1]`
		}
		return v
	}
	procTable := ProcTable{}
	old := false
	for _, line := range utils.LineToSlice(procOutput) {
		if len(line) > 0 && line[0] != '#' {
			proc := Proc{
				PID:     atoi(cut(line, 0, 16)),
				Type:    cut(line, 16, 32),
				RPID:    atoi(cut(line, 32, 48)),
				Reloads: atoi(cut(line, 48, 64)),
			}
			if proc.Type == "master" {
				procTable.Master = proc
			} else if old {
				procTable.OldWorkers = append(procTable.OldWorkers, proc)
			} else {
				procTable.Workers = append(procTable.Workers, proc)
			}
		} else if line == "# old workers" {
			old = true
		}
	}
	return &procTable
}
