/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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
	"sync"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/socket"
)

func newConnections(masterSock, adminSock string) *connections {
	return &connections{
		mutex:      sync.Mutex{},
		masterSock: masterSock,
		adminSock:  adminSock,
	}
}

type connections struct {
	mutex        sync.Mutex
	masterSock   string
	adminSock    string
	oldInstances []socket.HAProxySocket
	master       socket.HAProxySocket
	dynUpdate    socket.HAProxySocket
	idleChk      socket.HAProxySocket
}

func (c *connections) TrackCurrentInstance(timeoutStopDur, closeSessDur time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.shrinkConns()
	sock := socket.NewSocketConcurrent(c.adminSock, true)
	sock.Unlistening()
	c.oldInstances = append(c.oldInstances, sock)

	if closeSessDur > 0 && closeSessDur < timeoutStopDur {
		// schedule shutdown sessions
		time.AfterFunc(timeoutStopDur-closeSessDur, func() {
			// All the shutdowns run synchronously and exits after all the
			// remaining sessions have been shutdown, or in the case of an error.
			// When it finishes we can safely close the connection
			shutdownSessionsSync(sock, closeSessDur)
			sock.Close()
		})
	} else {
		// This connection can be used by other jobs, and this schedule is
		// responsible for closing it if closeSessDur wasn't configured.
		time.AfterFunc(timeoutStopDur, func() { sock.Close() })
	}
}

func (c *connections) ReleaseLastInstance() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	l := len(c.oldInstances)
	if l > 0 {
		c.oldInstances[l-1].Close()
		c.oldInstances = c.oldInstances[:l-1]
	}
}

func (c *connections) OldInstancesCount() int {
	return len(c.oldInstances)
}

func (c *connections) shrinkConns() {
	i := 0
	for j, old := range c.oldInstances {
		if i < j {
			c.oldInstances[i] = old
		}
		if old.HasConn() {
			i++
		}
	}
	c.oldInstances = c.oldInstances[:i]
}

func shutdownSessionsSync(sock socket.HAProxySocket, duration time.Duration) {
	sess, err := sock.Send(nil, "show sess")
	if err != nil {
		return
	}
	// sess output:
	//
	// 0x7f9440810000: proto=unix_stream src=...
	// 0x7f943f87f200: proto=unix_stream src=...
	// 0x7f9442808200: proto=unix_stream src=...
	// ...
	var sessionList []string
	for _, s := range strings.Split(sess[0], "\n") {
		i := strings.Index(s, ":")
		if i > 0 {
			sessionList = append(sessionList, s[:i])
		}
	}
	interval := duration / time.Duration((len(sessionList) + 1))
	for _, s := range sessionList {
		_, err := sock.Send(nil, "shutdown session "+s)
		if err != nil {
			// maybe the connection or the instance is gone,
			// haproxy takes care of the remaining sessions if any
			return
		}
		// we can enqueue shutdowns and sleeps, this is a dedicated go routine
		// TODO interval should be the duration between two shutdown starts,
		// but it's currently between the end of the former and the start of the next.
		time.Sleep(interval)
	}
}

func (c *connections) Master() socket.HAProxySocket {
	if c.master == nil {
		c.master = socket.NewSocket(c.masterSock, false)
	}
	return c.master
}

func (c *connections) DynUpdate() socket.HAProxySocket {
	if c.dynUpdate == nil {
		// using a non persistent connection (keep alive false)
		// to ensure that the current instance will be used
		c.dynUpdate = socket.NewSocket(c.adminSock, false)
	}
	return c.dynUpdate
}

func (c *connections) IdleChk() socket.HAProxySocket {
	if c.idleChk == nil {
		c.idleChk = socket.NewSocket(c.adminSock, false)
	}
	return c.idleChk
}
