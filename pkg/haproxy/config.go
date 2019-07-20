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
	AcquireBackend(namespace, name, port string) *hatypes.Backend
	FindBackend(namespace, name, port string) *hatypes.Backend
	ConfigDefaultBackend(defaultBackend *hatypes.Backend)
	ConfigDefaultX509Cert(filename string)
	AddUserlist(name string, users []hatypes.User) *hatypes.Userlist
	FindUserlist(name string) *hatypes.Userlist
	FrontendGroup() *hatypes.FrontendGroup
	BuildFrontendGroup() error
	BuildBackendMaps() error
	DefaultHost() *hatypes.Host
	DefaultBackend() *hatypes.Backend
	Global() *hatypes.Global
	Hosts() []*hatypes.Host
	Backends() []*hatypes.Backend
	Userlists() []*hatypes.Userlist
	Equals(other Config) bool
}

type config struct {
	fgroup          *hatypes.FrontendGroup
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

func (c *config) AcquireBackend(namespace, name, port string) *hatypes.Backend {
	if backend := c.FindBackend(namespace, name, port); backend != nil {
		return backend
	}
	backend := createBackend(namespace, name, port)
	c.backends = append(c.backends, backend)
	c.sortBackends()
	return backend
}

func (c *config) FindBackend(namespace, name, port string) *hatypes.Backend {
	for _, b := range c.backends {
		if b.Namespace == namespace && b.Name == name && b.Port == port {
			return b
		}
	}
	return nil
}

func createBackend(namespace, name, port string) *hatypes.Backend {
	return &hatypes.Backend{
		ID:        buildID(namespace, name, port),
		Namespace: namespace,
		Name:      name,
		Port:      port,
		Endpoints: []*hatypes.Endpoint{},
	}
}

func buildID(namespace, name, port string) string {
	return fmt.Sprintf("%s_%s_%s", namespace, name, port)
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

func (c *config) FrontendGroup() *hatypes.FrontendGroup {
	return c.fgroup
}

func (c *config) BuildFrontendGroup() error {
	// tested thanks to instance_test templating tests
	// ideas to make a nice test or a nice refactor are welcome
	if len(c.hosts) == 0 {
		return fmt.Errorf("cannot create frontends without hosts")
	}
	frontends, sslpassthrough := hatypes.BuildRawFrontends(c.hosts)
	fgroupMaps := hatypes.CreateMaps()
	fgroup := &hatypes.FrontendGroup{
		Frontends:         frontends,
		HasSSLPassthrough: len(sslpassthrough) > 0,
		Maps:              fgroupMaps,
		HTTPFrontsMap:     fgroupMaps.AddMap(c.mapsDir + "/_global_http_front.map"),
		HTTPRootRedirMap:  fgroupMaps.AddMap(c.mapsDir + "/_global_http_root_redir.map"),
		HTTPSRedirMap:     fgroupMaps.AddMap(c.mapsDir + "/_global_https_redir.map"),
		SSLPassthroughMap: fgroupMaps.AddMap(c.mapsDir + "/_global_sslpassthrough.map"),
	}
	if fgroup.HasTCPProxy() {
		// More than one HAProxy's frontend or bind, or using ssl-passthrough config,
		// so need a `mode tcp` frontend with `inspect-delay` and `req.ssl_sni`
		var i int
		for _, frontend := range frontends {
			for _, bind := range frontend.Binds {
				i++
				bindName := fmt.Sprintf("_socket%03d", i)
				if len(bind.Hosts) == 1 {
					bind.TLS.TLSCert = c.defaultX509Cert
					bind.TLS.TLSCertDir = bind.Hosts[0].TLS.TLSFilename
				} else {
					x509dir, err := c.createCertsDir(bindName, bind.Hosts)
					if err != nil {
						return err
					}
					bind.TLS.TLSCert = c.defaultX509Cert
					bind.TLS.TLSCertDir = x509dir
				}
				bind.Name = bindName
				bind.Socket = fmt.Sprintf("unix@/var/run/%s.sock", bindName)
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
				return err
			}
			frontends[0].Binds[0].TLS.TLSCert = c.defaultX509Cert
			frontends[0].Binds[0].TLS.TLSCertDir = x509dir
		}
	}
	for _, frontend := range frontends {
		mapsPrefix := c.mapsDir + "/" + frontend.Name
		frontend.Maps = hatypes.CreateMaps()
		frontend.HostBackendsMap = frontend.Maps.AddMap(mapsPrefix + "_host.map")
		frontend.RootRedirMap = frontend.Maps.AddMap(mapsPrefix + "_root_redir.map")
		frontend.SNIBackendsMap = frontend.Maps.AddMap(mapsPrefix + "_sni.map")
		frontend.TLSInvalidCrtErrorList = frontend.Maps.AddMap(mapsPrefix + "_inv_crt.list")
		frontend.TLSInvalidCrtErrorPagesMap = frontend.Maps.AddMap(mapsPrefix + "_inv_crt_redir.map")
		frontend.TLSNoCrtErrorList = frontend.Maps.AddMap(mapsPrefix + "_no_crt.list")
		frontend.TLSNoCrtErrorPagesMap = frontend.Maps.AddMap(mapsPrefix + "_no_crt_redir.map")
		frontend.VarNamespaceMap = frontend.Maps.AddMap(mapsPrefix + "_k8s_ns.map")
		for _, bind := range frontend.Binds {
			bind.Maps = hatypes.CreateMaps()
			bind.UseServerList = bind.Maps.AddMap(c.mapsDir + "/" + bind.Name + ".list")
		}
	}
	// Some maps use yes/no answers instead of a list with found/missing keys
	// This approach avoid overlap:
	//  1. match with path_beg/map_beg, /path has a feature and a declared /path/sub doesn't have
	//  2. *.host.domain wildcard/alias/alias-regex has a feature and a declared sub.host.domain doesn't have
	yesno := map[bool]string{true: "yes", false: "no"}
	for _, sslpassHost := range sslpassthrough {
		rootPath := sslpassHost.FindPath("/")
		if rootPath == nil {
			return fmt.Errorf("missing root path on host %s", sslpassHost.Hostname)
		}
		fgroup.SSLPassthroughMap.AppendHostname(sslpassHost.Hostname, rootPath.BackendID)
		fgroup.HTTPSRedirMap.AppendHostname(sslpassHost.Hostname+"/", yesno[sslpassHost.HTTPPassthroughBackend == nil])
		if sslpassHost.HTTPPassthroughBackend != nil {
			fgroup.HTTPFrontsMap.AppendHostname(sslpassHost.Hostname+"/", sslpassHost.HTTPPassthroughBackend.ID)
		}
	}
	for _, f := range frontends {
		for _, host := range f.Hosts {
			for _, path := range host.Paths {
				// TODO use only root path if all uri has the same conf
				fgroup.HTTPSRedirMap.AppendHostname(host.Hostname+path.Path, yesno[path.Backend.SSLRedirect])
				base := host.Hostname + path.Path
				var aliasName, aliasRegex string
				// TODO warn in logs about ignoring alias name due to hostname colision
				if host.Alias.AliasName != "" && c.FindHost(host.Alias.AliasName) == nil {
					aliasName = host.Alias.AliasName + path.Path
				}
				if host.Alias.AliasRegex != "" {
					aliasRegex = host.Alias.AliasRegex + path.Path
				}
				back := path.BackendID
				if host.HasTLSAuth() {
					f.SNIBackendsMap.AppendHostname(base, back)
					f.SNIBackendsMap.AppendAliasName(aliasName, back)
					f.SNIBackendsMap.AppendAliasRegex(aliasRegex, back)
					path.Backend.SSL.HasTLSAuth = true
				} else {
					f.HostBackendsMap.AppendHostname(base, back)
					f.HostBackendsMap.AppendAliasName(aliasName, back)
					f.HostBackendsMap.AppendAliasRegex(aliasRegex, back)
				}
				if !path.Backend.SSLRedirect {
					fgroup.HTTPFrontsMap.AppendHostname(base, back)
				}
				var ns string
				if host.VarNamespace {
					ns = path.Backend.Namespace
				} else {
					ns = "-"
				}
				f.VarNamespaceMap.AppendHostname(base, ns)
			}
			if host.HasTLSAuth() {
				f.TLSInvalidCrtErrorList.AppendHostname(host.Hostname, "")
				if !host.TLS.CAVerifyOptional {
					f.TLSNoCrtErrorList.AppendHostname(host.Hostname, "")
				}
				page := host.TLS.CAErrorPage
				if page != "" {
					f.TLSInvalidCrtErrorPagesMap.AppendHostname(host.Hostname, page)
					if !host.TLS.CAVerifyOptional {
						f.TLSNoCrtErrorPagesMap.AppendHostname(host.Hostname, page)
					}
				}
			}
			// TODO wildcard/alias/alias-regex hostname can overlap
			// a configured domain which doesn't have rootRedirect
			if host.RootRedirect != "" {
				fgroup.HTTPRootRedirMap.AppendHostname(host.Hostname, host.RootRedirect)
				f.RootRedirMap.AppendHostname(host.Hostname, host.RootRedirect)
			}
		}
		for _, bind := range f.Binds {
			for _, host := range bind.Hosts {
				bind.UseServerList.AppendHostname(host.Hostname, "")
			}
		}
	}
	if err := writeMaps(fgroup.Maps, c.mapsTemplate); err != nil {
		return err
	}
	for _, f := range frontends {
		if err := writeMaps(f.Maps, c.mapsTemplate); err != nil {
			return err
		}
		for _, bind := range f.Binds {
			if err := writeMaps(bind.Maps, c.mapsTemplate); err != nil {
				return err
			}
		}
	}
	c.fgroup = fgroup
	return nil
}

func (c *config) BuildBackendMaps() error {
	// TODO rename HostMap types to HAProxyMap
	maps := hatypes.CreateMaps()
	for _, backend := range c.backends {
		mapsPrefix := c.mapsDir + "/_back_" + backend.ID
		if backend.NeedACL() {
			pathsMap := maps.AddMap(mapsPrefix + "_idpath.map")
			for _, path := range backend.Paths {
				pathsMap.AppendPath(path.Path, path.ID)
			}
			backend.PathsMap = pathsMap
		}
	}
	return writeMaps(maps, c.mapsTemplate)
}

func writeMaps(maps *hatypes.HostsMaps, template *template.Config) error {
	for _, hmap := range maps.Items {
		if err := template.WriteOutput(hmap.Match, hmap.MatchFile); err != nil {
			return err
		}
		if len(hmap.Regex) > 0 {
			if err := template.WriteOutput(hmap.Regex, hmap.RegexFile); err != nil {
				return err
			}
		}
	}
	return nil
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
