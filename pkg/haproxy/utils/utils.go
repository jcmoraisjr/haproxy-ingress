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
	"fmt"
	"net"
	"time"
)

// HAProxyCommand ...
func HAProxyCommand(socket string, observer func(duration time.Duration), command ...string) ([]string, error) {
	var msg []string
	for _, cmd := range command {
		start := time.Now()
		c, err := net.Dial("unix", socket)
		if err != nil {
			return msg, fmt.Errorf("error connecting to unix socket %s: %v", socket, err)
		}
		defer c.Close()
		cmd = cmd + "\n"
		if sent, err := c.Write([]byte(cmd)); err != nil {
			return msg, fmt.Errorf("error sending to unix socket %s: %v", socket, err)
		} else if sent != len(cmd) {
			return msg, fmt.Errorf("incomplete data sent to unix socket %s", socket)
		}
		readBuffer := make([]byte, 1024)
		if r, err := c.Read(readBuffer); err != nil {
			return msg, fmt.Errorf("error reading response buffer: %v", err)
		} else if r > 2 {
			msg = append(msg, fmt.Sprintf("response from server: %s", string(readBuffer[:r-2])))
		}
		observer(time.Since(start))
	}
	return msg, nil
}
