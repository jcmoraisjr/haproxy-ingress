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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Config ...
type Config interface {
	AcquireTCPBackend(servicename string, port int) *hatypes.TCPBackend
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
	AcmeData() *hatypes.AcmeData
	Acme() *hatypes.Acme
	Global() *hatypes.Global
	TCPBackends() []*hatypes.TCPBackend
	Hosts() []*hatypes.Host
	Backends() []*hatypes.Backend
	Userlists() []*hatypes.Userlist
	Equals(other Config) bool
}

type config struct {
	// external state, non haproxy data, cannot reflect in Config.Equals()
	acmeData *hatypes.AcmeData
	// haproxy internal state
	acme            *hatypes.Acme
	fgroup          *hatypes.FrontendGroup
	mapsTemplate    *template.Config
	mapsDir         string
	global          *hatypes.Global
	tcpbackends     []*hatypes.TCPBackend
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

func createConfig(options options) *config {
	mapsTemplate := options.mapsTemplate
	if mapsTemplate == nil {
		mapsTemplate = template.CreateConfig()
	}
	return &config{
		acmeData:     &hatypes.AcmeData{},
		acme:         &hatypes.Acme{},
		global:       &hatypes.Global{},
		mapsTemplate: mapsTemplate,
		mapsDir:      options.mapsDir,
	}
}

func (c *config) AcquireTCPBackend(servicename string, port int) *hatypes.TCPBackend {
	for _, backend := range c.tcpbackends {
		if backend.Name == servicename && backend.Port == port {
			return backend
		}
	}
	backend := &hatypes.TCPBackend{
		Name: servicename,
		Port: port,
	}
	c.tcpbackends = append(c.tcpbackends, backend)
	sort.Slice(c.tcpbackends, func(i, j int) bool {
		back1 := c.tcpbackends[i]
		back2 := c.tcpbackends[j]
		if back1.Name == back2.Name {
			return back1.Port < back2.Port
		}
		return back1.Name < back2.Name
	})
	return backend
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
		Server:    hatypes.ServerConfig{InitialWeight: 1},
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
	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})
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
	frontends, sslpassthrough, defaultBind := hatypes.BuildRawFrontends(c.hosts)
	fgroupMaps := hatypes.CreateMaps()
	fgroup := &hatypes.FrontendGroup{
		Frontends:         frontends,
		HasSSLPassthrough: len(sslpassthrough) > 0,
		DefaultBind:       defaultBind,
		Maps:              fgroupMaps,
		HTTPFrontsMap:     fgroupMaps.AddMap(c.mapsDir + "/_global_http_front.map"),
		HTTPRootRedirMap:  fgroupMaps.AddMap(c.mapsDir + "/_global_http_root_redir.map"),
		HTTPSRedirMap:     fgroupMaps.AddMap(c.mapsDir + "/_global_https_redir.map"),
		SSLPassthroughMap: fgroupMaps.AddMap(c.mapsDir + "/_global_sslpassthrough.map"),
		VarNamespaceMap:   fgroupMaps.AddMap(c.mapsDir + "/_global_k8s_ns.map"),
	}
	if c.global.Bind.HasFrontingProxy() {
		bind := hatypes.NewFrontendBind(nil)
		bind.Socket = c.global.Bind.FrontingBind
		bind.ID = c.global.Bind.FrontingSockID
		bind.AcceptProxy = c.global.Bind.AcceptProxy
		fgroup.ToHTTPBind = bind
	}
	if fgroup.HasTCPProxy() {
		// More than one HAProxy's frontend or bind, or using ssl-passthrough config,
		// so need a `mode tcp` frontend with `inspect-delay` and `req.ssl_sni`
		var i int
		for _, frontend := range frontends {
			i++
			bindName := fmt.Sprintf("%s_socket", frontend.Name)
			bind := &frontend.Bind
			bind.Name = bindName
			bind.Socket = fmt.Sprintf("unix@/var/run/%s.sock", bindName)
			bind.AcceptProxy = true
			bind.ALPN = c.global.SSL.ALPN
		}
	} else {
		// One single HAProxy's frontend and bind
		bind := &frontends[0].Bind
		bind.Name = "_public"
		bind.Socket = c.global.Bind.HTTPSBind
		bind.AcceptProxy = c.global.Bind.AcceptProxy
		bind.ALPN = c.global.SSL.ALPN
	}
	for _, frontend := range frontends {
		mapsPrefix := c.mapsDir + "/" + frontend.Name
		frontend.Maps = hatypes.CreateMaps()
		frontend.HostBackendsMap = frontend.Maps.AddMap(mapsPrefix + "_host.map")
		frontend.RootRedirMap = frontend.Maps.AddMap(mapsPrefix + "_root_redir.map")
		frontend.MaxBodySizeMap = frontend.Maps.AddMap(mapsPrefix + "_max_body_size.map")
		frontend.SNIBackendsMap = frontend.Maps.AddMap(mapsPrefix + "_sni.map")
		frontend.TLSInvalidCrtErrorList = frontend.Maps.AddMap(mapsPrefix + "_inv_crt.list")
		frontend.TLSInvalidCrtErrorPagesMap = frontend.Maps.AddMap(mapsPrefix + "_inv_crt_redir.map")
		frontend.TLSNoCrtErrorList = frontend.Maps.AddMap(mapsPrefix + "_no_crt.list")
		frontend.TLSNoCrtErrorPagesMap = frontend.Maps.AddMap(mapsPrefix + "_no_crt_redir.map")
		frontend.Bind.CrtList = frontend.Maps.AddMap(mapsPrefix + "_bind_crt.list")
		frontend.Bind.UseServerList = frontend.Maps.AddMap(mapsPrefix + "_use_server.list")
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
		fgroup.SSLPassthroughMap.AppendHostname(sslpassHost.Hostname, rootPath.Backend.ID)
		fgroup.HTTPSRedirMap.AppendHostname(sslpassHost.Hostname+"/", yesno[sslpassHost.HTTPPassthroughBackend == ""])
		if sslpassHost.HTTPPassthroughBackend != "" {
			fgroup.HTTPFrontsMap.AppendHostname(sslpassHost.Hostname+"/", sslpassHost.HTTPPassthroughBackend)
		}
	}
	for _, f := range frontends {
		for _, host := range f.Hosts {
			if c.global.StrictHost && host.FindPath("/") == nil {
				var back *hatypes.Backend
				if c.defaultHost != nil {
					if path := c.defaultHost.FindPath("/"); path != nil {
						hback := path.Backend
						back = c.FindBackend(hback.Namespace, hback.Name, hback.Port)
					}
				}
				if back == nil {
					// TODO c.defaultBackend can be nil; create a valid
					// _error404 backend, remove `if nil` from host.AddPath()
					// and from `for range host.Paths` below
					back = c.defaultBackend
				}
				host.AddPath(back, "/")
			}
			// TODO implement deny 413 and move all MaxBodySize stuff to backend
			maxBodySizes := map[string]int64{}
			for _, path := range host.Paths {
				backend := c.FindBackend(path.Backend.Namespace, path.Backend.Name, path.Backend.Port)
				base := host.Hostname + path.Path
				isRegex := path.IsRegex
				hasSSLRedirect := false
				if host.TLS.HasTLS() && backend != nil {
					hasSSLRedirect = backend.HasSSLRedirectHostpath(base)
				}
				// TODO use only root path if all uri has the same conf
				fgroup.HTTPSRedirMap.AppendHostname(host.Hostname+path.Path, yesno[hasSSLRedirect])
				var aliasName, aliasRegex string
				// TODO warn in logs about ignoring alias name due to hostname colision
				if host.Alias.AliasName != "" && c.FindHost(host.Alias.AliasName) == nil {
					aliasName = host.Alias.AliasName + path.Path
				}
				if host.Alias.AliasRegex != "" {
					aliasRegex = host.Alias.AliasRegex + path.Path
				}
				back := path.Backend.ID
				if host.HasTLSAuth() {
					f.SNIBackendsMap.AppendHostname(base, back)
					f.SNIBackendsMap.AppendAliasName(aliasName, back)
					f.SNIBackendsMap.AppendAliasRegex(aliasRegex, back)
					if backend != nil {
						backend.TLS.HasTLSAuth = true
					}
				} else {
					f.HostBackendsMap.AppendHostname(base, back)
					f.HostBackendsMap.AppendAliasName(aliasName, back)
					f.HostBackendsMap.AppendAliasRegex(aliasRegex, back)
				}
				if backend != nil {
					if maxBodySize := backend.MaxBodySizeHostpath(base); maxBodySize > 0 {
						maxBodySizes[base] = maxBodySize
					}
				}
				if !hasSSLRedirect || c.global.Bind.HasFrontingProxy() {
					if isRegex {
						baseRegex := regexp.QuoteMeta(host.Hostname) + path.Path
						fgroup.HTTPFrontsMap.AppendHostnameRegex(baseRegex, back)
					} else {
						fgroup.HTTPFrontsMap.AppendHostname(base, back)
					}
				}
				var ns string
				if host.VarNamespace {
					ns = path.Backend.Namespace
				} else {
					ns = "-"
				}
				fgroup.VarNamespaceMap.AppendHostname(base, ns)
			}
			// TODO implement deny 413 and move all MaxBodySize stuff to backend
			if len(maxBodySizes) > 0 {
				// add all paths of the same host to avoid overlap
				// 0 (zero) means unlimited
				for _, path := range host.Paths {
					base := host.Hostname + path.Path
					f.MaxBodySizeMap.AppendHostname(base, strconv.FormatInt(maxBodySizes[base], 10))
				}
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
		f.Bind.CrtList.AppendItem(c.defaultX509Cert)
		for _, tls := range f.Bind.TLS {
			crtFile := tls.CrtFilename
			if (crtFile == "" || crtFile == c.defaultX509Cert) && tls.CAFilename == "" {
				// default cert without client cert auth, ignore
				continue
			}
			if crtFile == "" {
				crtFile = c.defaultX509Cert
			}
			var crtListConfig string
			hostnames := strings.Join(tls.Hostnames, " ")
			if tls.CAFilename == "" {
				crtListConfig = fmt.Sprintf("%s %s", crtFile, hostnames)
			} else {
				// TODO this NEED its own template file
				var crl string
				if tls.CRLFilename != "" {
					crl = " crl-file " + tls.CRLFilename
				}
				crtListConfig = fmt.Sprintf("%s [ca-file %s%s verify optional] %s", crtFile, tls.CAFilename, crl, hostnames)
			}
			f.Bind.CrtList.AppendItem(crtListConfig)
		}
		for _, host := range f.Hosts {
			f.Bind.UseServerList.AppendHostname(host.Hostname, "")
		}
	}
	if err := writeMaps(fgroup.Maps, c.mapsTemplate); err != nil {
		return err
	}
	for _, f := range frontends {
		if err := writeMaps(f.Maps, c.mapsTemplate); err != nil {
			return err
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
				pathsMap.AppendPath(path.Hostpath, path.ID)
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

func (c *config) DefaultHost() *hatypes.Host {
	return c.defaultHost
}

func (c *config) DefaultBackend() *hatypes.Backend {
	return c.defaultBackend
}

func (c *config) AcmeData() *hatypes.AcmeData {
	return c.acmeData
}

func (c *config) Acme() *hatypes.Acme {
	return c.acme
}

func (c *config) Global() *hatypes.Global {
	return c.global
}

func (c *config) TCPBackends() []*hatypes.TCPBackend {
	return c.tcpbackends
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
	// (config struct): external state, cannot reflect in Config.Equals()
	copy := *c2
	copy.acmeData = c.acmeData
	return reflect.DeepEqual(c, &copy)
}
