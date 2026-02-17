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
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/jinzhu/copier"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// Config ...
type Config interface {
	Frontends() *hatypes.Frontends
	SyncConfig()
	WriteTCPServicesMaps() error
	WriteFrontendsMaps() error
	WriteBackendMaps() error
	AcmeData() *hatypes.AcmeData
	Global() *hatypes.Global
	TCPBackends() *hatypes.TCPBackends
	TCPServices() *hatypes.TCPServices
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
	frontends   *hatypes.Frontends
	backends    *hatypes.Backends
	tcpbackends *hatypes.TCPBackends
	tcpservices *hatypes.TCPServices
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
		frontends:   &hatypes.Frontends{},
		backends:    hatypes.CreateBackends(options.shardCount),
		tcpbackends: hatypes.CreateTCPBackends(),
		tcpservices: hatypes.CreateTCPServices(),
		userlists:   hatypes.CreateUserlists(),
	}
}

func (c *config) Frontends() *hatypes.Frontends {
	return c.frontends
}

// SyncConfig does final synchronization, just before write
// maps and config files to disk. These tasks should be done
// during ingress, services and endpoint parsing, but most of
// them need to start after all objects are parsed.
func (c *config) SyncConfig() {
	for _, f := range c.frontends.Items() {
		c.syncFrontend(f)
	}
	c.syncPeers()
}

func (c *config) syncFrontend(f *hatypes.Frontend) {
	if f.IsHTTPS {
		if f.HasSSLPassthrough() {
			// using ssl-passthrough config, so need a `mode tcp`
			// frontend with `inspect-delay` and `req.ssl_sni`
			if f.Name == "_front_https" {
				f.TLSProxyName = "_front__tls" // backward compatible name
			} else {
				f.TLSProxyName = fmt.Sprintf("_front__tls_%d", f.Port())
			}
			f.HTTPSSocket = fmt.Sprintf("unix@%s/var/run/haproxy/%s_socket.sock", c.global.LocalFSPrefix, f.Name)
			f.HTTPSProxy = true
		} else {
			// One single HAProxy's frontend and bind
			f.TLSProxyName = ""
			f.HTTPSSocket = ""
			f.HTTPSProxy = f.AcceptProxy
		}
	}
	for _, host := range f.HostsAdd() {
		if !host.SSLPassthrough && c.global.StrictHost && host.FindPath("/", hatypes.MatchBegin) == nil {
			back := c.backends.DefaultBackend
			defaultHost := f.DefaultHost()
			if defaultHost != nil {
				path := defaultHost.FindPath("/")
				if len(path) > 0 {
					back = path[0].Backend
				}
			}
			if back == nil {
				back = c.backends.AcquireNotFoundBackend()
			}
			host.AddPath(back, "/", hatypes.MatchBegin)
		}
	}
}

func (c *config) syncPeers() {
	peers := &c.global.Peers
	if len(peers.Servers) > 0 {
		// aggregating global and backend tables in a way haproxy.tmpl and peers.lua.tmpl can use.
		peers.Tables = []hatypes.PeersTable{{
			GroupName: hatypes.PeersGroupNameGlobal,
			Table:     peers.GlobalTable,
		}}
		for _, back := range c.backends.Items() {
			if back.PeersTable != "" {
				peers.Tables = append(peers.Tables, hatypes.PeersTable{
					GroupName: back.ID,
					Table:     back.PeersTable,
				})
			}
		}
		sort.Slice(peers.Tables, func(i, j int) bool {
			g1 := peers.Tables[i].GroupName
			g2 := peers.Tables[j].GroupName
			if g1 == hatypes.PeersGroupNameGlobal {
				return true
			}
			if g2 == hatypes.PeersGroupNameGlobal {
				return false
			}
			return g1 < g2
		})
	}
}

// WriteTCPServicesMaps reads the model and writes haproxy's maps
// used in the tcp services. Should be called before write the main
// config file. This func doesn't change model state, except the
// link to the tcp services maps.
func (c *config) WriteTCPServicesMaps() error {
	if !c.tcpservices.Changed() {
		return nil
	}
	mapBuilder := hatypes.CreateMaps(c.global.MatchOrder)
	for _, tcpPort := range c.tcpservices.Items() {
		sniMap := mapBuilder.AddMap(fmt.Sprintf("%s/_tcp_sni_%d.map", c.options.mapsDir, tcpPort.Port()))
		for _, tcpHost := range tcpPort.BuildSortedItems() {
			sniMap.AddHostnameMapping(tcpHost.Hostname(), false, tcpHost.Backend.String())
		}
		tcpPort.SNIMap = sniMap
	}
	err := writeMaps(mapBuilder, c.options.mapsTemplate)
	return err
}

// WriteFrontendMaps reads the model and writes haproxy's maps
// used in the frontend. Should be called before write the main
// config file. This func doesn't change model state, except the
// link to the frontend maps.
func (c *config) WriteFrontendsMaps() error {
	for _, f := range c.frontends.Items() {
		if f.HTTPMaps == nil || f.HTTPSMaps == nil || f.HostsChanged() {
			if err := c.writeFrontendMaps(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *config) writeFrontendMaps(f *hatypes.Frontend) error {
	// This method is being called once per frontend, having distinct calls for HTTP and HTTPS.
	// TODO Bear with us, we know this is currently not ideal. Work in progress, this is part
	// of a major refactor that is decoupling the plain HTTP/s model used up to v0.16.
	mapBuilder := hatypes.CreateMaps(c.global.MatchOrder)
	mapsFilenamePrefix := path.Join(c.options.mapsDir, f.Name)
	buildCommonMaps := func(m *hatypes.FrontendCommonMaps) {
		*m = hatypes.FrontendCommonMaps{
			DefaultHostMap:   mapBuilder.AddMap(mapsFilenamePrefix + "_defaulthost.map"),
			RedirFromRootMap: mapBuilder.AddMap(mapsFilenamePrefix + "_redir_fromroot.map"),
			RedirFromMap:     mapBuilder.AddMap(mapsFilenamePrefix + "_redir_from.map"),
			RedirToMap:       mapBuilder.AddMap(mapsFilenamePrefix + "_redir_to.map"),
			VarNamespaceMap:  mapBuilder.AddMap(mapsFilenamePrefix + "_namespace.map"),
		}
	}
	var httpMaps *hatypes.FrontendHTTPMaps
	var httpsMaps *hatypes.FrontendHTTPSMaps
	var commonMaps *hatypes.FrontendCommonMaps
	if f.IsHTTPS {
		httpsMaps = &hatypes.FrontendHTTPSMaps{
			HTTPSHostMap:          mapBuilder.AddMap(mapsFilenamePrefix + "_host.map"),
			SSLPassthroughMap:     mapBuilder.AddMap(mapsFilenamePrefix + "_sslpassthrough.map"),
			TLSAuthList:           mapBuilder.AddMap(mapsFilenamePrefix + "_tls_auth.list"),
			TLSNeedCrtList:        mapBuilder.AddMap(mapsFilenamePrefix + "_tls_needcrt.list"),
			TLSInvalidCrtPagesMap: mapBuilder.AddMap(mapsFilenamePrefix + "_tls_invalidcrt_pages.map"),
			TLSMissingCrtPagesMap: mapBuilder.AddMap(mapsFilenamePrefix + "_tls_missingcrt_pages.map"),
		}
		commonMaps = &httpsMaps.FrontendCommonMaps
		buildCommonMaps(commonMaps)
	} else {
		httpMaps = &hatypes.FrontendHTTPMaps{
			HTTPHostMap:     mapBuilder.AddMap(mapsFilenamePrefix + "_host.map"),
			RedirRootSSLMap: mapBuilder.AddMap(mapsFilenamePrefix + "_redir_root_ssl.map"),
		}
		commonMaps = &httpMaps.FrontendCommonMaps
		buildCommonMaps(commonMaps)
	}
	hasVarNamespace := f.HasVarNamespace()
	defaultHost := f.DefaultHost()
	if defaultHost != nil && !defaultHost.SSLPassthrough {
		for _, path := range defaultHost.Paths {
			// using DefaultHost ID as hostname, see types.maps.go/buildMapKey()
			commonMaps.DefaultHostMap.AddHostnamePathMapping(hatypes.DefaultHost, path, path.Backend.ID)
		}
	}
	defaultCrtFile := c.frontends.DefaultCrtFile
	var crtListItems []*hatypes.HostsMapEntry
	if f.IsHTTPS {
		// TODO crtList* to be removed after implement a template to the crt list
		f.CrtListFile = mapsFilenamePrefix + "_bind_crt.list"
		crtListItems = append(crtListItems, &hatypes.HostsMapEntry{Key: defaultCrtFile + " !*"})
	}
	for _, host := range f.BuildSortedHosts() {
		for _, path := range host.Paths {
			// IMPLEMENT check if host.Alias.AliasName was already used as a hostname
			if path.Backend != nil {
				backendID := path.Backend.ID
				if f.IsHTTPS && host.SSLPassthrough {
					// no ssl offload, cannot inspect incoming path, so tracking root only
					if path.Path() == "/" {
						httpsMaps.SSLPassthroughMap.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, backendID)
					}
				} else if f.IsHTTPS {
					httpsMaps.HTTPSHostMap.AddHostnamePathMapping(host.Hostname, path, backendID)
					httpsMaps.HTTPSHostMap.AddAliasPathMapping(host.Alias, path, backendID)
				} else {
					httpMaps.HTTPHostMap.AddHostnamePathMapping(host.Hostname, path, backendID)
					httpMaps.HTTPHostMap.AddAliasPathMapping(host.Alias, path, backendID)
				}
			} else if path.RedirTo != "" {
				commonMaps.RedirToMap.AddHostnamePathMapping(host.Hostname, path, path.RedirTo)
				commonMaps.RedirToMap.AddAliasPathMapping(host.Alias, path, path.RedirTo)
			}
			if hasVarNamespace {
				// add "-" on missing paths to avoid overlap
				var ns string
				if host.VarNamespace {
					ns = path.Backend.Namespace
				} else {
					ns = "-"
				}
				commonMaps.VarNamespaceMap.AddHostnamePathMapping(host.Hostname, path, ns)
			}
		}
		if host.SSLPassthrough {
			continue
		}
		if host.Redirect.RedirectHost != "" {
			commonMaps.RedirFromMap.AddHostnameMapping(host.Redirect.RedirectHost, host.ExtendedWildcard, host.Hostname)
		}
		if host.Redirect.RedirectHostRegex != "" {
			commonMaps.RedirFromMap.AddHostnameMappingRegex(host.Redirect.RedirectHostRegex, host.Hostname)
		}
		if f.IsHTTPS && host.HasTLSAuth() {
			if host.TLS.CAVerify != hatypes.CAVerifySkipCheck {
				httpsMaps.TLSAuthList.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, "")
			}
			if !host.TLS.CAVerifyOptional() {
				httpsMaps.TLSNeedCrtList.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, "")
			}
			page := host.TLS.CAErrorPage
			if page != "" {
				httpsMaps.TLSInvalidCrtPagesMap.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, page)
				if !host.TLS.CAVerifyOptional() {
					httpsMaps.TLSMissingCrtPagesMap.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, page)
				}
			}
		}
		// TODO wildcard/alias/alias-regex hostname can overlap
		// a configured domain which doesn't have rootRedirect
		if host.RootRedirect != "" {
			// looking for root path configuration - if ssl redirect is enabled,
			// we need to redirect to https before redirect the path.
			redirectssl := func() bool {
				redir := c.global.SSL.SSLRedirect
				for _, path := range host.FindPath("/") {
					// any root path `/` is fine ...
					redir = path.SSLRedirect
					if !path.Link.IsComposeMatch() {
						// ... but gives precedence for a root path `/` without method, header or cookie matching
						return redir
					}
				}
				return redir
			}
			if !f.IsHTTPS && redirectssl() {
				httpMaps.RedirRootSSLMap.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, "")
			}
			commonMaps.RedirFromRootMap.AddHostnameMapping(host.Hostname, host.ExtendedWildcard, host.RootRedirect)
		}
		if !f.IsHTTPS {
			continue
		}
		//
		tls := host.TLS
		crtFile := tls.TLSFilename
		if crtFile == "" {
			crtFile = defaultCrtFile
		}
		if crtFile != defaultCrtFile ||
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
			crtListItems = append(crtListItems, &hatypes.HostsMapEntry{Key: crtListEntry})
		}
	}
	if f.IsHTTPS {
		if err := c.options.mapsTemplate.WriteOutput(crtListItems, f.CrtListFile); err != nil {
			return err
		}
	}
	if err := writeMaps(mapBuilder, c.options.mapsTemplate); err != nil {
		return err
	}
	f.HTTPMaps = httpMaps
	f.HTTPSMaps = httpsMaps
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
		if !backend.NeedACL() {
			continue
		}
		mapsFilenamePrefix := path.Join(c.options.mapsDir, "_back_"+backend.ID)
		for _, pathsMap := range backend.PathsMaps() {
			frontend := pathsMap.Frontends[0]
			pathsMap.ReqMap = mapBuilder.AddMap(mapsFilenamePrefix + frontend + "_req.map")
			pathsMap.DefMap = mapBuilder.AddMap(mapsFilenamePrefix + frontend + "_def.map")
			for _, path := range pathsMap.Paths {
				if path.IsDefaultHost() {
					// using DefaultHost ID as hostname, see types/maps.go/buildMapKey()
					pathsMap.DefMap.AddHostnamePathMapping(hatypes.DefaultHost, path, path.ID)
				} else {
					pathsMap.ReqMap.AddHostnamePathMapping(path.Hostname(), path, path.ID)
				}
			}
		}
	}
	return writeMaps(mapBuilder, c.options.mapsTemplate)
}

func writeMaps(maps *hatypes.HostsMaps, template *template.Config) error {
	for _, hmap := range maps.Items {
		for _, matchFile := range hmap.MatchFiles() {
			if err := template.WriteOutput(matchFile.Values(), matchFile.Filename()); err != nil {
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

func (c *config) TCPServices() *hatypes.TCPServices {
	return c.tcpservices
}

func (c *config) Backends() *hatypes.Backends {
	return c.backends
}

func (c *config) Userlists() *hatypes.Userlists {
	return c.userlists
}

func (c *config) Clear() {
	config := createConfig(c.options)

	// copying backend state, so shards with all the backends removed can be
	// properly identified and updated when a full reconciliation happens
	config.backends = c.backends
	config.backends.Clear()

	*c = *config
}

func (c *config) Shrink() {
	c.frontends.Shrink()
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
	c.frontends.Commit()
	c.backends.Commit()
	c.tcpbackends.Commit()
	c.tcpservices.Commit()
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
