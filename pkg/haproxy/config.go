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
	"strings"

	"github.com/jinzhu/copier"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Config ...
type Config interface {
	Frontend() *hatypes.Frontend
	SyncConfig()
	WriteFrontendMaps() error
	WriteBackendMaps() error
	AcmeData() *hatypes.AcmeData
	Global() *hatypes.Global
	TCPBackends() *hatypes.TCPBackends
	Hosts() *hatypes.Hosts
	Backends() *hatypes.Backends
	Userlists() *hatypes.Userlists
	Clear()
	Shrink()
	Commit()
}

type config struct {
	// external state, non haproxy data
	options  options
	acmeData *hatypes.AcmeData
	// haproxy internal state
	globalOld   *hatypes.Global
	global      *hatypes.Global
	frontend    *hatypes.Frontend
	hosts       *hatypes.Hosts
	backends    *hatypes.Backends
	tcpbackends *hatypes.TCPBackends
	userlists   *hatypes.Userlists
}

type options struct {
	mapsTemplate *template.Config
	mapsDir      string
	shardCount   int
}

func createConfig(options options) *config {
	if options.mapsTemplate == nil {
		options.mapsTemplate = template.CreateConfig()
	}
	return &config{
		options:     options,
		acmeData:    &hatypes.AcmeData{},
		global:      &hatypes.Global{},
		frontend:    &hatypes.Frontend{},
		hosts:       hatypes.CreateHosts(),
		backends:    hatypes.CreateBackends(options.shardCount),
		tcpbackends: hatypes.CreateTCPBackends(),
		userlists:   hatypes.CreateUserlists(),
	}
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
		bindName := "_https_socket"
		c.frontend.BindName = bindName
		c.frontend.BindSocket = fmt.Sprintf("unix@/var/run/haproxy/%s.sock", bindName)
		c.frontend.AcceptProxy = true
	} else {
		// One single HAProxy's frontend and bind
		c.frontend.BindName = "_public"
		c.frontend.BindSocket = c.global.Bind.HTTPSBind
		c.frontend.AcceptProxy = c.global.Bind.AcceptProxy
	}
	for _, host := range c.hosts.ItemsAdd() {
		if host.SSLPassthrough() {
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
			host.AddPath(back, "/", hatypes.MatchBegin)
		}
	}
}

// WriteFrontendMaps reads the model and writes haproxy's maps
// used in the frontend. Should be called before write the main
// config file. This func doesn't change model state, except the
// link to the frontend maps.
func (c *config) WriteFrontendMaps() error {
	if c.frontend.Maps != nil && !c.hosts.Changed() {
		// TODO Maps!=nil just to preserve the current behavior. Check if this can be removed.
		// hosts are clean, maps are updated
		return nil
	}
	mapBuilder := hatypes.CreateMaps(c.global.MatchOrder)
	mapsDir := c.options.mapsDir
	fmaps := &hatypes.FrontendMaps{
		HTTPHostMap:  mapBuilder.AddMap(mapsDir + "/_front_http_host.map"),
		HTTPSHostMap: mapBuilder.AddMap(mapsDir + "/_front_https_host.map"),
		HTTPSSNIMap:  mapBuilder.AddMap(mapsDir + "/_front_https_sni.map"),
		//
		RedirToHTTPSMap:   mapBuilder.AddMap(mapsDir + "/_front_redir_tohttps.map"),
		RedirFromRootMap:  mapBuilder.AddMap(mapsDir + "/_front_redir_fromroot.map"),
		SSLPassthroughMap: mapBuilder.AddMap(mapsDir + "/_front_sslpassthrough.map"),
		VarNamespaceMap:   mapBuilder.AddMap(mapsDir + "/_front_namespace.map"),
		//
		TLSAuthList:           mapBuilder.AddMap(mapsDir + "/_front_tls_auth.list"),
		TLSNeedCrtList:        mapBuilder.AddMap(mapsDir + "/_front_tls_needcrt.list"),
		TLSInvalidCrtPagesMap: mapBuilder.AddMap(mapsDir + "/_front_tls_invalidcrt_pages.map"),
		TLSMissingCrtPagesMap: mapBuilder.AddMap(mapsDir + "/_front_tls_missingcrt_pages.map"),
		//
		CrtList: mapBuilder.AddMap(mapsDir + "/_front_bind_crt.list"),
	}
	fmaps.CrtList.AppendItem(c.frontend.DefaultCrtFile)
	// Some maps use yes/no answers instead of a list with found/missing keys
	// This approach avoid overlap:
	//  1. match with path_beg/map_beg, /path has a feature and a declared /path/sub doesn't have
	//  2. *.host.domain wildcard/alias/alias-regex has a feature and a declared sub.host.domain doesn't have
	yesno := map[bool]string{true: "yes", false: "no"}
	hasVarNamespace := c.hosts.HasVarNamespace()
	for _, host := range c.hosts.BuildSortedItems() {
		if host.SSLPassthrough() {
			rootPath := host.FindPath("/")
			if rootPath == nil {
				// Cannot use this hostname if the root path wasn't declared.
				// Silently skipping beucase we have not a logger here.
				// However this skip should never happen because root path
				// validation already happens in the annotation parsing phase.
				continue
			}
			fmaps.SSLPassthroughMap.AddHostnameMapping(host.Hostname, rootPath.Backend.ID)
			hasHTTPBackend := host.HTTPPassthroughBackend != ""
			fmaps.RedirToHTTPSMap.AddHostnamePathMapping(host.Hostname, rootPath, yesno[!hasHTTPBackend])
			if hasHTTPBackend {
				fmaps.HTTPHostMap.AddHostnamePathMapping(host.Hostname, rootPath, host.HTTPPassthroughBackend)
			}
			// ssl-passthrough is as simple as that, jump to the next host
			continue
		}
		//
		// Starting here to the end of the outer for-loop has only HTTP/L7 map configuration
		//
		for _, path := range host.Paths {
			backend := c.backends.FindBackend(path.Backend.Namespace, path.Backend.Name, path.Backend.Port)
			hasSSLRedirect := false
			if host.TLS.HasTLS() && backend != nil {
				hasSSLRedirect = backend.LinkHasSSLRedirect(path.Link)
			}
			// TODO use only root path if all uri has the same conf
			fmaps.RedirToHTTPSMap.AddHostnamePathMapping(host.Hostname, path, yesno[hasSSLRedirect])
			backendID := path.Backend.ID
			// IMPLEMENT check if host.Alias.AliasName was already used as a hostname
			if host.HasTLSAuth() {
				fmaps.HTTPSSNIMap.AddHostnamePathMapping(host.Hostname, path, backendID)
				fmaps.HTTPSSNIMap.AddAliasPathMapping(host.Alias, path, backendID)
			} else {
				fmaps.HTTPSHostMap.AddHostnamePathMapping(host.Hostname, path, backendID)
				fmaps.HTTPSHostMap.AddAliasPathMapping(host.Alias, path, backendID)
			}
			if !hasSSLRedirect || c.global.Bind.HasFrontingProxy() {
				fmaps.HTTPHostMap.AddHostnamePathMapping(host.Hostname, path, backendID)
				fmaps.HTTPHostMap.AddAliasPathMapping(host.Alias, path, backendID)
			}
			if hasVarNamespace {
				// add "-" on missing paths to avoid overlap
				var ns string
				if host.VarNamespace {
					ns = path.Backend.Namespace
				} else {
					ns = "-"
				}
				fmaps.VarNamespaceMap.AddHostnamePathMapping(host.Hostname, path, ns)
			}
		}
		if host.HasTLSAuth() {
			fmaps.TLSAuthList.AddHostnameMapping(host.Hostname, "")
			if !host.TLS.CAVerifyOptional {
				fmaps.TLSNeedCrtList.AddHostnameMapping(host.Hostname, "")
			}
			page := host.TLS.CAErrorPage
			if page != "" {
				fmaps.TLSInvalidCrtPagesMap.AddHostnameMapping(host.Hostname, page)
				if !host.TLS.CAVerifyOptional {
					fmaps.TLSMissingCrtPagesMap.AddHostnameMapping(host.Hostname, page)
				}
			}
		}
		// TODO wildcard/alias/alias-regex hostname can overlap
		// a configured domain which doesn't have rootRedirect
		if host.RootRedirect != "" {
			fmaps.RedirFromRootMap.AddHostnameMapping(host.Hostname, host.RootRedirect)
		}
		//
		tls := host.TLS
		crtFile := tls.TLSFilename
		if crtFile == "" {
			crtFile = c.frontend.DefaultCrtFile
		}
		if crtFile != c.frontend.DefaultCrtFile ||
			tls.ALPN != "" ||
			tls.CAFilename != "" ||
			tls.Ciphers != "" ||
			tls.CipherSuites != "" ||
			tls.Options != "" {
			// has custom tls config
			//
			// TODO optimization: distinct hostnames that shares crt, ca and crl
			// can be combined into a single line. Note that this is usually the exception.
			// TODO this NEED its own template file.
			var bindConf = make([]string, 0, 20)
			if tls.ALPN != "" {
				bindConf = append(bindConf, "alpn", tls.ALPN)
			}
			if tls.CAFilename != "" {
				bindConf = append(bindConf, "ca-file", tls.CAFilename, "verify", "optional")
				if tls.CRLFilename != "" {
					bindConf = append(bindConf, "crl-file", tls.CRLFilename)
				}
			}
			if tls.Ciphers != "" {
				bindConf = append(bindConf, "ciphers", tls.Ciphers)
			}
			if tls.CipherSuites != "" {
				bindConf = append(bindConf, "ciphersuites", tls.CipherSuites)
			}
			if tls.Options != "" {
				bindConf = append(bindConf, tls.Options)
			}

			var crtListEntry string
			if len(bindConf) == 0 {
				crtListEntry = fmt.Sprintf("%s %s", crtFile, host.Hostname)
			} else {
				crtListEntry = fmt.Sprintf("%s [%s] %s", crtFile, strings.Join(bindConf, " "), host.Hostname)
			}
			fmaps.CrtList.AppendItem(crtListEntry)
		}
	}
	if err := writeMaps(mapBuilder, c.options.mapsTemplate); err != nil {
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
	if !c.backends.Changed() {
		// backends are clean, maps are updated
		return nil
	}
	mapBuilder := hatypes.CreateMaps(c.global.MatchOrder)
	for _, backend := range c.backends.ItemsAdd() {
		if backend.NeedACL() {
			mapsPrefix := c.options.mapsDir + "/_back_" + backend.ID
			pathsMap := mapBuilder.AddMap(mapsPrefix + "_idpath.map")
			for _, path := range backend.Paths {
				// IMPLEMENT add HostPath link into the backend path
				h := c.hosts.FindHost(path.Hostname())
				if h == nil {
					continue
				}
				p := h.FindPath(path.Path())
				if p == nil {
					continue
				}
				pathsMap.AddHostnamePathMapping(path.Hostname(), p, path.ID)
			}
			backend.PathsMap = pathsMap
		}
	}
	return writeMaps(mapBuilder, c.options.mapsTemplate)
}

func writeMaps(maps *hatypes.HostsMaps, template *template.Config) error {
	for _, hmap := range maps.Items {
		if f, err := hmap.Filename(hatypes.MatchEmpty); err == nil {
			if err := template.WriteOutput(hmap.BuildSortedValues(hatypes.MatchEmpty), f); err != nil {
				return err
			}
		}
		for _, match := range hmap.UsedMatchTypes() {
			filename, err := hmap.Filename(match)
			if err != nil {
				return err
			}
			if err := template.WriteOutput(hmap.BuildSortedValues(match), filename); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *config) AcmeData() *hatypes.AcmeData {
	return c.acmeData
}

func (c *config) Global() *hatypes.Global {
	return c.global
}

func (c *config) TCPBackends() *hatypes.TCPBackends {
	return c.tcpbackends
}

func (c *config) Hosts() *hatypes.Hosts {
	return c.hosts
}

func (c *config) Backends() *hatypes.Backends {
	return c.backends
}

func (c *config) Userlists() *hatypes.Userlists {
	return c.userlists
}

func (c *config) Clear() {
	config := createConfig(c.options)
	*c = *config
}

func (c *config) Shrink() {
	c.hosts.Shrink()
	c.backends.Shrink()
}

func (c *config) Commit() {
	if !reflect.DeepEqual(c.globalOld, c.global) {
		// globals still uses the old deepCopy+fullParsing+deepEqual strategy
		var globalOld hatypes.Global
		if err := copier.Copy(&globalOld, c.global); err != nil {
			panic(err)
		}
		c.globalOld = &globalOld
	}
	c.hosts.Commit()
	c.backends.Commit()
	c.tcpbackends.Commit()
	c.userlists.Commit()
	c.acmeData.Storages().Commit()
}

func (c *config) hasCommittedData() bool {
	// Committed data is data which was already added and synchronized
	// to a haproxy instance. A `Clear()` clears the committed state.
	// Whenever a commit is performed the global instance is cloned to
	// its old state, and whenever a clear is performed such clone is
	// cleaned as well. So a globalOld != nil is a fast and safe way to
	// know if there is committed data.
	return c.globalOld != nil
}
