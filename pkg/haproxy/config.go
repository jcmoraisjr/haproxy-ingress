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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Config ...
type Config interface {
	AcquireHost(hostname string) *hatypes.Host
	FindHost(hostname string) *hatypes.Host
	AcquireBackend(namespace, name string, port int) *hatypes.Backend
	FindBackend(namespace, name string, port int) *hatypes.Backend
	ConfigDefaultBackend(defaultBackend *hatypes.Backend)
	ConfigDefaultX509Cert(filename string)
	AddUserlist(name string, users []hatypes.User) *hatypes.Userlist
	FindUserlist(name string) *hatypes.Userlist
	BuildFrontendGroup() (*hatypes.FrontendGroup, error)
	DefaultHost() *hatypes.Host
	DefaultBackend() *hatypes.Backend
	Global() *hatypes.Global
	Hosts() []*hatypes.Host
	Backends() []*hatypes.Backend
	Userlists() []*hatypes.Userlist
	Equals(other Config) bool
}

type config struct {
	bindUtils       hatypes.BindUtils
	mapsTemplate    *template.Config
	mapsDir         string
	global          *hatypes.Global
	hosts           []*hatypes.Host
	backends        []*hatypes.Backend
	userlists       []*hatypes.Userlist
	defaultHost     *hatypes.Host
	defaultBackend  *hatypes.Backend
	defaultX509Cert string
}

type options struct {
	mapsTemplate *template.Config
	mapsDir      string
}

func createConfig(bindUtils hatypes.BindUtils, options options) *config {
	mapsTemplate := options.mapsTemplate
	if mapsTemplate == nil {
		mapsTemplate = template.CreateConfig()
	}
	return &config{
		bindUtils:    bindUtils,
		global:       &hatypes.Global{},
		mapsTemplate: mapsTemplate,
		mapsDir:      options.mapsDir,
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

func (c *config) sortBackends() {
	sort.Slice(c.backends, func(i, j int) bool {
		if c.backends[i] == c.defaultBackend {
			return false
		}
		if c.backends[j] == c.defaultBackend {
			return true
		}
		return c.backends[i].ID < c.backends[j].ID
	})
}

func (c *config) AcquireBackend(namespace, name string, port int) *hatypes.Backend {
	if backend := c.FindBackend(namespace, name, port); backend != nil {
		return backend
	}
	backend := createBackend(namespace, name, port)
	c.backends = append(c.backends, backend)
	c.sortBackends()
	return backend
}

func (c *config) FindBackend(namespace, name string, port int) *hatypes.Backend {
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
	if c.defaultBackend != nil {
		def := c.defaultBackend
		def.ID = buildID(def.Namespace, def.Name, def.Port)
	}
	c.defaultBackend = defaultBackend
	if c.defaultBackend != nil {
		c.defaultBackend.ID = "_default_backend"
	}
	c.sortBackends()
}

func (c *config) ConfigDefaultX509Cert(filename string) {
	c.defaultX509Cert = filename
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

func (c *config) BuildFrontendGroup() (*hatypes.FrontendGroup, error) {
	if len(c.hosts) == 0 {
		return nil, fmt.Errorf("cannot create frontends without hosts")
	}
	frontends, sslpassthrough := hatypes.BuildRawFrontends(c.hosts)
	for _, frontend := range frontends {
		mapPrefix := c.mapsDir + "/" + frontend.Name
		frontend.HostBackendsMap = mapPrefix + "_host.map"
		frontend.SNIBackendsMap = mapPrefix + "_sni.map"
		frontend.TLSInvalidCrtErrorPagesMap = mapPrefix + "_inv_crt.map"
		frontend.TLSNoCrtErrorPagesMap = mapPrefix + "_no_crt.map"
		frontend.VarNamespaceMap = mapPrefix + "_k8s_ns.map"
	}
	fgroup := &hatypes.FrontendGroup{
		Frontends:         frontends,
		HasSSLPassthrough: len(sslpassthrough) > 0,
		HTTPFrontsMap:     c.mapsDir + "/http-front.map",
		SSLPassthroughMap: c.mapsDir + "/sslpassthrough.map",
	}
	if fgroup.HasTCPProxy() {
		// More than one HAProxy's frontend or bind, or using ssl-passthrough config,
		// so need a `mode tcp` frontend with `inspect-delay` and `req.ssl_sni`
		var i int
		for _, frontend := range frontends {
			for _, bind := range frontend.Binds {
				var bindName string
				if len(bind.Hosts) == 1 {
					bindName = bind.Hosts[0].Hostname
					bind.TLS.TLSCert = c.defaultX509Cert
					bind.TLS.TLSCertDir = bind.Hosts[0].TLS.TLSFilename
				} else {
					i++
					bindName = fmt.Sprintf("_socket%03d", i)
					x509dir, err := c.createCertsDir(bindName, bind.Hosts)
					if err != nil {
						return nil, err
					}
					bind.TLS.TLSCert = c.defaultX509Cert
					bind.TLS.TLSCertDir = x509dir
				}
				bind.Name = bindName
				bind.Socket = fmt.Sprintf("unix@/var/run/front_%s.sock", bindName)
				bind.AcceptProxy = true
			}
		}
	} else {
		// One single HAProxy's frontend and bind
		bind := frontends[0].Binds[0]
		bind.Name = "_public"
		bind.Socket = ":443"
		if len(bind.Hosts) == 1 {
			bind.TLS.TLSCert = c.defaultX509Cert
			bind.TLS.TLSCertDir = bind.Hosts[0].TLS.TLSFilename
		} else {
			x509dir, err := c.createCertsDir(bind.Name, bind.Hosts)
			if err != nil {
				return nil, err
			}
			frontends[0].Binds[0].TLS.TLSCert = c.defaultX509Cert
			frontends[0].Binds[0].TLS.TLSCertDir = x509dir
		}
	}
	type mapEntry struct {
		Key   string
		Value string
	}
	var sslpassthroughMap []mapEntry
	var httpFront []mapEntry
	for _, sslpassHost := range sslpassthrough {
		rootPath := sslpassHost.FindPath("/")
		if rootPath == nil {
			return nil, fmt.Errorf("missing root path on host %s", sslpassHost.Hostname)
		}
		sslpassthroughMap = append(sslpassthroughMap, mapEntry{
			Key:   sslpassHost.Hostname,
			Value: rootPath.BackendID,
		})
		if sslpassHost.HTTPPassthroughBackend != nil {
			httpFront = append(httpFront, mapEntry{
				Key:   sslpassHost.Hostname + "/",
				Value: sslpassHost.HTTPPassthroughBackend.ID,
			})
		} else {
			fgroup.HasRedirectHTTPS = true
		}
	}
	for _, f := range frontends {
		var hostBackendsMap []mapEntry
		var sniBackendsMap []mapEntry
		var invalidCrtMap []mapEntry
		var noCrtMap []mapEntry
		var varNamespaceMap []mapEntry
		for _, host := range f.Hosts {
			for _, path := range host.Paths {
				entry := mapEntry{
					Key:   host.Hostname + path.Path,
					Value: path.BackendID,
				}
				if host.HasTLSAuth() {
					sniBackendsMap = append(sniBackendsMap, entry)
				} else {
					hostBackendsMap = append(hostBackendsMap, entry)
				}
				if path.Backend.SSLRedirect {
					fgroup.HasRedirectHTTPS = true
				} else {
					httpFront = append(httpFront, entry)
				}
				if host.VarNamespace {
					entry.Value = path.Backend.Namespace
				} else {
					entry.Value = "-"
				}
				varNamespaceMap = append(varNamespaceMap, entry)
			}
			if host.HasTLSAuth() && host.TLS.CAErrorPage != "" {
				entry := mapEntry{
					Key:   host.Hostname,
					Value: host.TLS.CAErrorPage,
				}
				invalidCrtMap = append(invalidCrtMap, entry)
				if !host.TLS.CAVerifyOptional {
					noCrtMap = append(noCrtMap, entry)
				}
			}
		}
		if err := c.mapsTemplate.WriteOutput(hostBackendsMap, f.HostBackendsMap); err != nil {
			return nil, err
		}
		if err := c.mapsTemplate.WriteOutput(sniBackendsMap, f.SNIBackendsMap); err != nil {
			return nil, err
		}
		if err := c.mapsTemplate.WriteOutput(invalidCrtMap, f.TLSInvalidCrtErrorPagesMap); err != nil {
			return nil, err
		}
		if err := c.mapsTemplate.WriteOutput(noCrtMap, f.TLSNoCrtErrorPagesMap); err != nil {
			return nil, err
		}
		if err := c.mapsTemplate.WriteOutput(varNamespaceMap, f.VarNamespaceMap); err != nil {
			return nil, err
		}
	}
	if err := c.mapsTemplate.WriteOutput(sslpassthroughMap, fgroup.SSLPassthroughMap); err != nil {
		return nil, err
	}
	if err := c.mapsTemplate.WriteOutput(httpFront, fgroup.HTTPFrontsMap); err != nil {
		return nil, err
	}
	fgroup.HasHTTPHost = len(httpFront) > 0
	return fgroup, nil
}

func (c *config) createCertsDir(bindName string, hosts []*hatypes.Host) (string, error) {
	certs := make([]string, 0, len(hosts))
	added := map[string]bool{}
	for _, host := range hosts {
		filename := host.TLS.TLSFilename
		if filename != "" && !added[filename] && filename != c.defaultX509Cert {
			certs = append(certs, host.TLS.TLSFilename)
			added[filename] = true
		}
	}
	if len(certs) == 0 {
		return "", nil
	}
	return c.bindUtils.CreateX509CertsDir(bindName, certs)
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
