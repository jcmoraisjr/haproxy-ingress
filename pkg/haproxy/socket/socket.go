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

package socket

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	k8snet "k8s.io/apimachinery/pkg/util/net"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// HAProxySocket ...
type HAProxySocket interface {
	Address() string
	Send(observer func(duration time.Duration), command ...string) ([]string, error)
	Down()
	Close() error
}

type sock struct {
	address   string
	listening bool
	keepalive bool
	conn      net.Conn
	buffer    []byte
	mutex     sync.Mutex
}

// NewSocket ...
func NewSocket(address string) HAProxySocket {
	return &sock{
		address:   address,
		listening: true,
		keepalive: true,
		mutex:     sync.Mutex{},
	}
}

// Address ...
func (s *sock) Address() string {
	return s.address
}

// Send ...
func (s *sock) Send(observer func(duration time.Duration), command ...string) ([]string, error) {
	// we've distinct threads using and cleaning up socket instances
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var msg []string
	for _, cmd := range command {
		start := time.Now()
		response, err := s.send(cmd)
		if err != nil {
			return msg, err
		}
		if observer != nil {
			observer(time.Since(start))
		}
		msg = append(msg, response)
	}
	return msg, nil
}

func (s *sock) Down() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.listening = false
}

// Close ...
func (s *sock) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.close()
}

func (s *sock) close() error {
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *sock) send(cmd string) (string, error) {
	c, err := s.acquireConn()
	if err != nil {
		return "", fmt.Errorf("error connecting to %s: %w", s.address, err)
	}
	if !strings.HasSuffix(cmd, "\n") {
		// haproxy starts the command after receiving a line break
		cmd += "\n"
	}
	if n, err := c.Write([]byte(cmd)); err != nil {
		if n == 0 && s.listening && !k8snet.IsConnectionRefused(err) {
			// nothing was sent, server socket is still alive
			// but current connection is broken, try a new connection
			c, err = s.newConn()
			if err == nil {
				_, err = c.Write([]byte(cmd))
			}
		}
		if err != nil {
			return "", fmt.Errorf("error writing to %s: %w", s.address, err)
		}
	}
	var response string
	for {
		r, err := c.Read(s.buffer)
		if err != nil && err != io.EOF {
			// ignore any successfully read data in the case of an error
			return "", fmt.Errorf("error reading response from %s: %w", s.address, err)
		}
		response += string(s.buffer[:r])
		if r == 0 ||
			strings.HasSuffix(response, "\n> ") ||
			strings.HasSuffix(response, "master> ") ||
			strings.HasSuffix(response, "\n\n") {
			// end of the stream if empty (r==0), ended with an interactive prompt ("> "),
			// master prompt ("master> ") or it's a non interactive response ("\n\n").
			// ps: currently master doesn't close the connection even in non interactive mode.
			break
		}
	}
	// remove the last line breaks and all trailing chars, that might be
	// the cli prompt ("> ") or the master prompt ("master> ")
	i := strings.LastIndex(response, "\n")
	return strings.TrimRight(response[:i+1], "\n"), nil
}

func (s *sock) acquireConn() (net.Conn, error) {
	if s.buffer == nil {
		s.buffer = make([]byte, 1536)
	}
	if s.conn == nil {
		c, err := net.Dial("unix", s.address)
		if err != nil {
			return nil, err
		}
		s.conn = c
		if s.keepalive {
			// Master socket is always in keep alive mode, even without calling prompt.
			// Currently keep alive is always true, so we are good. Need to be revisited
			// if a false state is desired.
			s.send("prompt")
		}
	}
	return s.conn, nil
}

func (s *sock) newConn() (net.Conn, error) {
	s.close()
	return s.acquireConn()
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
}

// HAProxyProcs reads and converts `show proc` from the master CLI to a ProcTable
// instance. Waits for the reload to complete while master CLI is down and the
// attempt to connect leads to a connection refused. Some context:
// https://www.mail-archive.com/haproxy@formilux.org/msg38415.html
// The amount of time between attempts increases exponentially between 1ms and 64ms,
// and aritmetically betweem 128ms and 1s in order to save CPU on long reload events
// and quit fast on the fastest ones. The whole processing time can be calculated by
// the caller as the haproxy reload time.
func HAProxyProcs(masterSocket HAProxySocket) (*ProcTable, error) {
	maxLogWait := 64 * time.Millisecond
	logFactor := 2
	maxArithWait := 1024 * time.Millisecond
	arithFactor := 32 * time.Millisecond
	wait := time.Millisecond
	for {
		time.Sleep(wait)
		out, err := masterSocket.Send(nil, "show proc")
		if err == nil || !k8snet.IsConnectionRefused(err) {
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

// buildProcTable parses `show proc` output and creates a corresponding ProcTable
//
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
func buildProcTable(procOutput string) *ProcTable {
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
