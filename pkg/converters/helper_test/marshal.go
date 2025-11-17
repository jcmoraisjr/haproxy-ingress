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

package helper_test

import (
	"sort"

	yaml "gopkg.in/yaml.v2"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

type (
	// backend
	backendMock struct {
		ID               string
		Endpoints        []endpointMock    `yaml:",omitempty"`
		Paths            []backendPathMock `yaml:",omitempty"`
		BalanceAlgorithm string            `yaml:",omitempty"`
		MaxConnServer    int               `yaml:",omitempty"`
		ModeTCP          bool              `yaml:",omitempty"`
	}
	backendPathMock struct {
		Path        string
		Match       string
		MaxBodySize int64
	}
	endpointMock struct {
		IP     string
		Port   int
		Drain  bool  `yaml:",omitempty"`
		Weight int   `yaml:",omitempty"`
		PUID   int32 `yaml:",omitempty"`
	}
	// host
	hostMock struct {
		Hostname     string
		Paths        []pathMock
		RootRedirect string  `yaml:",omitempty"`
		TLS          tlsMock `yaml:",omitempty"`
		Passthrough  bool    `yaml:",omitempty"`
	}
	pathMock struct {
		Path      string
		Match     string        `yaml:",omitempty"`
		Headers   []headersMock `yaml:",omitempty"`
		BackendID string        `yaml:"backend"`
	}
	headersMock struct {
		Name  string
		Value string
		Regex bool
	}
	tlsMock struct {
		TLSFilename string `yaml:",omitempty"`
		CAFilename  string `yaml:",omitempty"`
	}
	// tcp
	tcpServiceMock struct {
		Backends       []string
		DefaultBackend string
		Port           int
		ProxyProt      bool
		TLS            []tlsMock
	}
)

// MarshalBackends ...
func MarshalBackends(habackends ...*hatypes.Backend) string {
	return yamlMarshal(marshalBackends(false, habackends...))
}

// MarshalBackendsWeight ...
func MarshalBackendsWeight(habackends ...*hatypes.Backend) string {
	return yamlMarshal(marshalBackends(true, habackends...))
}

func marshalBackends(weight bool, habackends ...*hatypes.Backend) []backendMock {
	backends := []backendMock{}
	for _, b := range habackends {
		endpoints := []endpointMock{}
		for _, e := range b.Endpoints {
			endpoint := endpointMock{IP: e.IP, Port: e.Port, Drain: e.Weight == 0, PUID: e.PUID}
			if weight {
				endpoint.Weight = e.Weight
			}
			endpoints = append(endpoints, endpoint)
		}
		var paths []backendPathMock
		for _, p := range b.Paths {
			if p.MaxBodySize > 0 {
				paths = append(paths, backendPathMock{Path: p.Path(), Match: string(p.Match()), MaxBodySize: p.MaxBodySize})
			}
		}
		backends = append(backends, backendMock{
			ID:               b.ID,
			Endpoints:        endpoints,
			Paths:            paths,
			BalanceAlgorithm: b.BalanceAlgorithm,
			MaxConnServer:    b.Server.MaxConn,
			ModeTCP:          b.ModeTCP,
		})
	}
	return backends
}

// MarshalHost ...
func MarshalHost(hafront *hatypes.Host) string {
	return yamlMarshal(marshalHosts(hafront)[0])
}

// MarshalHosts ...
func MarshalHosts(hafronts ...*hatypes.Host) string {
	return yamlMarshal(marshalHosts(hafronts...))
}

func marshalHosts(hafronts ...*hatypes.Host) []hostMock {
	hosts := []hostMock{}
	for _, f := range hafronts {
		paths := []pathMock{}
		for _, p := range f.Paths {
			var match string
			if p.Match() != hatypes.MatchBegin {
				match = string(p.Match())
			}
			headers := p.Headers()
			var hmock []headersMock
			for _, h := range headers {
				hmock = append(hmock, headersMock{
					Regex: h.Regex,
					Name:  h.Name,
					Value: h.Value,
				})
			}
			paths = append(paths, pathMock{Path: p.Path(), Match: match, Headers: hmock, BackendID: p.Backend.ID})
		}
		hosts = append(hosts, hostMock{
			Hostname:     f.Hostname,
			Paths:        paths,
			RootRedirect: f.RootRedirect,
			TLS:          tlsMock{TLSFilename: f.TLS.TLSFilename},
			Passthrough:  f.SSLPassthrough,
		})
	}
	return hosts
}

// MarshalTCPServices ...
func MarshalTCPServices(hatcpserviceports ...*hatypes.TCPServicePort) string {
	tcpServices := []tcpServiceMock{}
	for _, haSvc := range hatcpserviceports {
		var backends []string
		for _, h := range haSvc.Hosts() {
			backends = append(backends, h.Backend.String())
		}
		sort.Strings(backends)
		var defaultBackend string
		if haSvc.DefaultHost() != nil {
			defaultBackend = haSvc.DefaultHost().Backend.String()
		}
		svc := tcpServiceMock{
			Backends:       backends,
			DefaultBackend: defaultBackend,
			Port:           haSvc.Port(),
			ProxyProt:      haSvc.ProxyProt,
		}
		for _, tls := range haSvc.BuildSortedTLSConfig() {
			svc.TLS = append(svc.TLS, tlsMock{
				TLSFilename: tls.TLSFilename,
				CAFilename:  tls.CAFilename,
			})
		}
		tcpServices = append(tcpServices, svc)
	}
	return yamlMarshal(tcpServices)
}

func yamlMarshal(in interface{}) string {
	out, _ := yaml.Marshal(in)
	return string(out)
}
