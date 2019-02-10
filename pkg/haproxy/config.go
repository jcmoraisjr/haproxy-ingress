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
	"sort"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Config ...
type Config interface {
	AcquireHost(hostname string) *hatypes.Host
	FindHost(hostname string) *hatypes.Host
	AcquireBackend(namespace, name string, port int) *hatypes.Backend
	FindBackend(namespace, name string, port int) *hatypes.Backend
	ConfigDefaultBackend(defaultBackend *hatypes.Backend)
	AddUserlist(name string, users []hatypes.User) *hatypes.Userlist
	FindUserlist(name string) *hatypes.Userlist
	DefaultHost() *hatypes.Host
	DefaultBackend() *hatypes.Backend
	Global() *hatypes.Global
	Hosts() []*hatypes.Host
	Backends() []*hatypes.Backend
	Userlists() []*hatypes.Userlist
	Equals(other Config) bool
}

type config struct {
	global         *hatypes.Global
	hosts          []*hatypes.Host
	backends       []*hatypes.Backend
	userlists      []*hatypes.Userlist
	defaultHost    *hatypes.Host
	defaultBackend *hatypes.Backend
}

func createConfig() Config {
	return &config{
		global: &hatypes.Global{},
	}
}

func (c *config) AcquireHost(hostname string) *hatypes.Host {
	if host := c.FindHost(hostname); host != nil {
		return host
	}
	host := createHost(hostname)
	if host.Hostname != "*" {
		c.hosts = append(c.hosts, host)
		sort.Slice(c.hosts, func(i, j int) bool {
			return c.hosts[i].Hostname < c.hosts[j].Hostname
		})
	} else {
		c.defaultHost = host
	}
	return host
}

func (c *config) FindHost(hostname string) *hatypes.Host {
	if hostname == "*" && c.defaultHost != nil {
		return c.defaultHost
	}
	for _, f := range c.hosts {
		if f.Hostname == hostname {
			return f
		}
	}
	return nil
}

func createHost(hostname string) *hatypes.Host {
	return &hatypes.Host{
		Hostname: hostname,
	}
}

func (c *config) AcquireBackend(namespace, name string, port int) *hatypes.Backend {
	if backend := c.FindBackend(namespace, name, port); backend != nil {
		return backend
	}
	backend := createBackend(namespace, name, port)
	c.backends = append(c.backends, backend)
	sort.Slice(c.backends, func(i, j int) bool {
		return c.backends[i].ID < c.backends[j].ID
	})
	return backend
}

func (c *config) FindBackend(namespace, name string, port int) *hatypes.Backend {
	// TODO test missing `== port`
	if c.defaultBackend != nil && c.defaultBackend.Namespace == namespace && c.defaultBackend.Name == name {
		return c.defaultBackend
	}
	for _, b := range c.backends {
		if b.Namespace == namespace && b.Name == name && b.Port == port {
			return b
		}
	}
	return nil
}

func createBackend(namespace, name string, port int) *hatypes.Backend {
	return &hatypes.Backend{
		ID:        buildID(namespace, name, port),
		Namespace: namespace,
		Name:      name,
		Port:      port,
		Endpoints: []*hatypes.Endpoint{},
	}
}

func buildID(namespace, name string, port int) string {
	return fmt.Sprintf("%s_%s_%d", namespace, name, port)
}

func (c *config) ConfigDefaultBackend(defaultBackend *hatypes.Backend) {
	c.defaultBackend = defaultBackend
	// remove the default backend from the list
	for i, backend := range c.backends {
		if backend.ID == defaultBackend.ID {
			c.backends = append(c.backends[:i], c.backends[i+1:]...)
			break
		}
	}
}

func (c *config) AddUserlist(name string, users []hatypes.User) *hatypes.Userlist {
	userlist := &hatypes.Userlist{
		Name:  name,
		Users: users,
	}
	c.userlists = append(c.userlists, userlist)
	sort.Slice(c.userlists, func(i, j int) bool {
		return c.userlists[i].Name < c.userlists[j].Name
	})
	return userlist
}

func (c *config) FindUserlist(name string) *hatypes.Userlist {
	return nil
}

func (c *config) DefaultHost() *hatypes.Host {
	return c.defaultHost
}

func (c *config) DefaultBackend() *hatypes.Backend {
	return c.defaultBackend
}

func (c *config) Global() *hatypes.Global {
	return c.global
}

func (c *config) Hosts() []*hatypes.Host {
	return c.hosts
}

func (c *config) Backends() []*hatypes.Backend {
	return c.backends
}

func (c *config) Userlists() []*hatypes.Userlist {
	return c.userlists
}

func (c *config) Equals(other Config) bool {
	c2, ok := other.(*config)
	if !ok {
		return false
	}
	return reflect.DeepEqual(c, c2)
}
