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
	"strconv"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Config ...
type Config interface {
	AcquireTCPBackend(servicename string, port int) *hatypes.TCPBackend
	ConfigDefaultX509Cert(filename string)
	AddUserlist(name string, users []hatypes.User) *hatypes.Userlist
	FindUserlist(name string) *hatypes.Userlist
	Frontend() *hatypes.Frontend
	SyncConfig()
	WriteFrontendMaps() error
	WriteBackendMaps() error
	AcmeData() *hatypes.AcmeData
	Acme() *hatypes.Acme
	Global() *hatypes.Global
	TCPBackends() []*hatypes.TCPBackend
	Hosts() *hatypes.Hosts
	Backends() *hatypes.Backends
	Userlists() []*hatypes.Userlist
	Equals(other Config) bool
}

type config struct {
	// external state, non haproxy data, cannot reflect in Config.Equals()
	acmeData *hatypes.AcmeData
	// haproxy internal state
	acme            *hatypes.Acme
	mapsTemplate    *template.Config
	mapsDir         string
	global          *hatypes.Global
	frontend        *hatypes.Frontend
	hosts           *hatypes.Hosts
	backends        *hatypes.Backends
	tcpbackends     []*hatypes.TCPBackend
	userlists       []*hatypes.Userlist
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
		frontend:     &hatypes.Frontend{Name: "_front001"},
		hosts:        &hatypes.Hosts{},
		backends:     hatypes.CreateBackends(),
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

func (c *config) Frontend() *hatypes.Frontend {
	return c.frontend
}

// SyncConfig does final synchronization, just before write
// maps and config files to disk. These tasks should be done
// during ingress, services and endpoint parsing, but most of
// them need to start after all objects are parsed.
func (c *config) SyncConfig() {
	if c.hosts.HasSSLPassthrough() {
		// using ssl-passthrough config, so need a `mode tcp`
		// frontend with `inspect-delay` and `req.ssl_sni`
		bindName := fmt.Sprintf("%s_socket", c.frontend.Name)
		c.frontend.BindName = bindName
		c.frontend.BindSocket = fmt.Sprintf("unix@/var/run/%s.sock", bindName)
		c.frontend.AcceptProxy = true
	} else {
		// One single HAProxy's frontend and bind
		c.frontend.BindName = "_public"
		c.frontend.BindSocket = c.global.Bind.HTTPSBind
		c.frontend.AcceptProxy = c.global.Bind.AcceptProxy
	}
	for _, host := range c.hosts.Items {
		if host.SSLPassthrough {
			// no action if ssl-passthrough
			continue
		}
		if host.HasTLSAuth() {
			for _, path := range host.Paths {
				backend := c.backends.FindBackend(path.Backend.Namespace, path.Backend.Name, path.Backend.Port)
				if backend != nil {
					backend.TLS.HasTLSAuth = true
				}
			}
		}
		if c.global.StrictHost && host.FindPath("/") == nil {
			var back *hatypes.Backend
			defaultHost := c.hosts.DefaultHost()
			if defaultHost != nil {
				if path := defaultHost.FindPath("/"); path != nil {
					hback := path.Backend
					back = c.backends.FindBackend(hback.Namespace, hback.Name, hback.Port)
				}
			}
			if back == nil {
				// TODO c.defaultBackend can be nil; create a valid
				// _error404 backend, remove `if nil` from host.AddPath()
				// and from `for range host.Paths` on map building.
				back = c.backends.DefaultBackend()
			}
			host.AddPath(back, "/")
		}
	}
}

// WriteFrontendMaps reads the model and writes haproxy's maps
// used in the frontend. Should be called before write the main
// config file. This func doesn't change model state, except the
// link to the frontend maps.
func (c *config) WriteFrontendMaps() error {
	mapBuilder := hatypes.CreateMaps()
	fmaps := &hatypes.FrontendMaps{
		HTTPFrontsMap:     mapBuilder.AddMap(c.mapsDir + "/_global_http_front.map"),
		HTTPRootRedirMap:  mapBuilder.AddMap(c.mapsDir + "/_global_http_root_redir.map"),
		HTTPSRedirMap:     mapBuilder.AddMap(c.mapsDir + "/_global_https_redir.map"),
		SSLPassthroughMap: mapBuilder.AddMap(c.mapsDir + "/_global_sslpassthrough.map"),
		VarNamespaceMap:   mapBuilder.AddMap(c.mapsDir + "/_global_k8s_ns.map"),
		//
		HostBackendsMap:            mapBuilder.AddMap(c.mapsDir + "/_front001_host.map"),
		RootRedirMap:               mapBuilder.AddMap(c.mapsDir + "/_front001_root_redir.map"),
		MaxBodySizeMap:             mapBuilder.AddMap(c.mapsDir + "/_front001_max_body_size.map"),
		SNIBackendsMap:             mapBuilder.AddMap(c.mapsDir + "/_front001_sni.map"),
		TLSInvalidCrtErrorList:     mapBuilder.AddMap(c.mapsDir + "/_front001_inv_crt.list"),
		TLSInvalidCrtErrorPagesMap: mapBuilder.AddMap(c.mapsDir + "/_front001_inv_crt_redir.map"),
		TLSNoCrtErrorList:          mapBuilder.AddMap(c.mapsDir + "/_front001_no_crt.list"),
		TLSNoCrtErrorPagesMap:      mapBuilder.AddMap(c.mapsDir + "/_front001_no_crt_redir.map"),
		//
		CrtList:       mapBuilder.AddMap(c.mapsDir + "/_front001_bind_crt.list"),
		UseServerList: mapBuilder.AddMap(c.mapsDir + "/_front001_use_server.list"),
	}
	fmaps.CrtList.AppendItem(c.defaultX509Cert)
	// Some maps use yes/no answers instead of a list with found/missing keys
	// This approach avoid overlap:
	//  1. match with path_beg/map_beg, /path has a feature and a declared /path/sub doesn't have
	//  2. *.host.domain wildcard/alias/alias-regex has a feature and a declared sub.host.domain doesn't have
	yesno := map[bool]string{true: "yes", false: "no"}
	for _, host := range c.hosts.Items {
		if host.SSLPassthrough {
			rootPath := host.FindPath("/")
			if rootPath == nil {
				// Cannot use this hostname if the root path wasn't declared.
				// Silently skipping beucase we have not a logger here.
				// However this skip should never happen because root path
				// validation already happens in the annotation parsing phase.
				continue
			}
			fmaps.SSLPassthroughMap.AppendHostname(host.Hostname, rootPath.Backend.ID)
			fmaps.HTTPSRedirMap.AppendHostname(host.Hostname+"/", yesno[host.HTTPPassthroughBackend == ""])
			if host.HTTPPassthroughBackend != "" {
				fmaps.HTTPFrontsMap.AppendHostname(host.Hostname+"/", host.HTTPPassthroughBackend)
			}
			// ssl-passthrough is as simple as that, jump to the next host
			continue
		}
		//
		// Starting here to the end of this for loop has only HTTP/L7 map configuration
		//
		// TODO implement deny 413 and move all MaxBodySize stuff to backend
		maxBodySizes := map[string]int64{}
		for _, path := range host.Paths {
			backend := c.backends.FindBackend(path.Backend.Namespace, path.Backend.Name, path.Backend.Port)
			base := host.Hostname + path.Path
			hasSSLRedirect := false
			if host.TLS.HasTLS() && backend != nil {
				hasSSLRedirect = backend.HasSSLRedirectHostpath(base)
			}
			// TODO use only root path if all uri has the same conf
			fmaps.HTTPSRedirMap.AppendHostname(host.Hostname+path.Path, yesno[hasSSLRedirect])
			var aliasName, aliasRegex string
			// TODO warn in logs about ignoring alias name due to hostname colision
			if host.Alias.AliasName != "" && c.hosts.FindHost(host.Alias.AliasName) == nil {
				aliasName = host.Alias.AliasName + path.Path
			}
			if host.Alias.AliasRegex != "" {
				aliasRegex = host.Alias.AliasRegex + path.Path
			}
			backendID := path.Backend.ID
			if host.HasTLSAuth() {
				fmaps.SNIBackendsMap.AppendHostname(base, backendID)
				fmaps.SNIBackendsMap.AppendAliasName(aliasName, backendID)
				fmaps.SNIBackendsMap.AppendAliasRegex(aliasRegex, backendID)
			} else {
				fmaps.HostBackendsMap.AppendHostname(base, backendID)
				fmaps.HostBackendsMap.AppendAliasName(aliasName, backendID)
				fmaps.HostBackendsMap.AppendAliasRegex(aliasRegex, backendID)
			}
			if backend != nil {
				if maxBodySize := backend.MaxBodySizeHostpath(base); maxBodySize > 0 {
					maxBodySizes[base] = maxBodySize
				}
			}
			if !hasSSLRedirect || c.global.Bind.HasFrontingProxy() {
				fmaps.HTTPFrontsMap.AppendHostname(base, backendID)
			}
			var ns string
			if host.VarNamespace {
				ns = path.Backend.Namespace
			} else {
				ns = "-"
			}
			fmaps.VarNamespaceMap.AppendHostname(base, ns)
		}
		// TODO implement deny 413 and move all MaxBodySize stuff to backend
		if len(maxBodySizes) > 0 {
			// add all paths of the same host to avoid overlap
			// 0 (zero) means unlimited
			for _, path := range host.Paths {
				base := host.Hostname + path.Path
				fmaps.MaxBodySizeMap.AppendHostname(base, strconv.FormatInt(maxBodySizes[base], 10))
			}
		}
		if host.HasTLSAuth() {
			fmaps.TLSInvalidCrtErrorList.AppendHostname(host.Hostname, "")
			if !host.TLS.CAVerifyOptional {
				fmaps.TLSNoCrtErrorList.AppendHostname(host.Hostname, "")
			}
			page := host.TLS.CAErrorPage
			if page != "" {
				fmaps.TLSInvalidCrtErrorPagesMap.AppendHostname(host.Hostname, page)
				if !host.TLS.CAVerifyOptional {
					fmaps.TLSNoCrtErrorPagesMap.AppendHostname(host.Hostname, page)
				}
			}
		}
		// TODO wildcard/alias/alias-regex hostname can overlap
		// a configured domain which doesn't have rootRedirect
		if host.RootRedirect != "" {
			fmaps.HTTPRootRedirMap.AppendHostname(host.Hostname, host.RootRedirect)
			fmaps.RootRedirMap.AppendHostname(host.Hostname, host.RootRedirect)
		}
		fmaps.UseServerList.AppendHostname(host.Hostname, "")
		//
		tls := host.TLS
		crtFile := tls.TLSFilename
		if crtFile == "" {
			crtFile = c.defaultX509Cert
		}
		if crtFile != c.defaultX509Cert || tls.CAFilename != "" {
			// has custom cert or tls auth
			//
			// TODO optimization: distinct hostnames that shares crt, ca and crl
			// can be combined into a single line. Note that this is usually the exception.
			// TODO this NEED its own template file.
			var crtListConfig string
			if tls.CAFilename == "" {
				crtListConfig = fmt.Sprintf("%s %s", crtFile, host.Hostname)
			} else {
				var crl string
				if tls.CRLFilename != "" {
					crl = " crl-file " + tls.CRLFilename
				}
				crtListConfig = fmt.Sprintf("%s [ca-file %s%s verify optional] %s", crtFile, tls.CAFilename, crl, host.Hostname)
			}
			fmaps.CrtList.AppendItem(crtListConfig)
		}
	}
	if err := writeMaps(mapBuilder, c.mapsTemplate); err != nil {
		return err
	}
	c.frontend.Maps = fmaps
	return nil
}

// WriteBackendMaps reads the model and writes haproxy's maps
// used in the backends. Should be called before write the main
// config file. This func doesn't change model state, except the
// link to the backend maps.
func (c *config) WriteBackendMaps() error {
	// TODO rename HostMap types to HAProxyMap
	mapBuilder := hatypes.CreateMaps()
	for _, backend := range c.backends.Items() {
		mapsPrefix := c.mapsDir + "/_back_" + backend.ID
		if backend.NeedACL() {
			pathsMap := mapBuilder.AddMap(mapsPrefix + "_idpath.map")
			for _, path := range backend.Paths {
				pathsMap.AppendPath(path.Hostpath, path.ID)
			}
			backend.PathsMap = pathsMap
		}
	}
	return writeMaps(mapBuilder, c.mapsTemplate)
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

func (c *config) Hosts() *hatypes.Hosts {
	return c.hosts
}

func (c *config) Backends() *hatypes.Backends {
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
