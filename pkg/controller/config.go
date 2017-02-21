/*
Copyright 2017 The Kubernetes Authors.

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

package main

import (
	"github.com/golang/glog"
	"github.com/mitchellh/mapstructure"
	"k8s.io/ingress/core/pkg/ingress"
)

type (
	configuration struct {
		Backends            []*ingress.Backend
		DefaultServer       *haproxyServer
		HTTPServers         []*haproxyServer
		HTTPSServers        []*haproxyServer
		TCPEndpoints        []*ingress.Location
		UDPEndpoints        []*ingress.Location
		PassthroughBackends []*ingress.SSLPassthroughBackend
		Syslog              string `json:"syslog-endpoint"`
	}
	// haproxyServer and haproxyLocation build some missing pieces
	// from ingress.Server used by HAProxy
	haproxyServer struct {
		IsDefaultServer bool               `json:"isDefaultServer"`
		Hostname        string             `json:"hostname"`
		SSLCertificate  string             `json:"sslCertificate"`
		SSLPemChecksum  string             `json:"sslPemChecksum"`
		RootLocation    *haproxyLocation   `json:"defaultLocation"`
		Locations       []*haproxyLocation `json:"locations,omitempty"`
	}
	haproxyLocation struct {
		IsRootLocation bool   `json:"isDefaultLocation"`
		Path           string `json:"path"`
		Backend        string `json:"backend"`
		HAMatchPath    string `json:"haMatchPath"`
		HAWhitelist    string `json:"whitelist,omitempty"`
	}
)

func newConfig(cfg *ingress.Configuration, data map[string]string) *configuration {
	haHTTPServers, haHTTPSServers, haDefaultServer := newHAProxyServers(cfg.Servers)
	conf := configuration{
		Backends:            cfg.Backends,
		HTTPServers:         haHTTPServers,
		HTTPSServers:        haHTTPSServers,
		DefaultServer:       haDefaultServer,
		TCPEndpoints:        cfg.TCPEndpoints,
		UDPEndpoints:        cfg.UDPEndpoints,
		PassthroughBackends: cfg.PassthroughBackends,
	}
	if data != nil {
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			WeaklyTypedInput: true,
			Result:           &conf,
			TagName:          "json",
		})
		if err != nil {
			glog.Warningf("error configuring decoder: %v", err)
		}
		if err = decoder.Decode(data); err != nil {
			glog.Warningf("error decoding config: %v", err)
		}
	}
	return &conf
}

func newHAProxyServers(servers []*ingress.Server) (haHTTPServers []*haproxyServer, haHTTPSServers []*haproxyServer, haDefaultServer *haproxyServer) {
	haHTTPServers = make([]*haproxyServer, 0, len(servers))
	haHTTPSServers = make([]*haproxyServer, 0, len(servers))
	for _, server := range servers {
		haLocations, haRootLocation := newHAProxyLocations(server)
		haServer := haproxyServer{
			IsDefaultServer: server.Hostname == "_",
			Hostname:        server.Hostname,
			SSLCertificate:  server.SSLCertificate,
			SSLPemChecksum:  server.SSLPemChecksum,
			RootLocation:    haRootLocation,
			Locations:       haLocations,
		}
		if haServer.IsDefaultServer {
			haDefaultServer = &haServer
		} else if haServer.SSLCertificate == "" {
			haHTTPServers = append(haHTTPServers, &haServer)
		} else {
			haHTTPSServers = append(haHTTPSServers, &haServer)
		}
	}
	return
}

func newHAProxyLocations(server *ingress.Server) (haLocations []*haproxyLocation, haRootLocation *haproxyLocation) {
	locations := server.Locations
	haLocations = make([]*haproxyLocation, len(locations))
	otherPaths := ""
	for i, location := range locations {
		haWhitelist := ""
		for _, cidr := range location.Whitelist.CIDR {
			haWhitelist = haWhitelist + " " + cidr
		}
		haLocation := haproxyLocation{
			IsRootLocation: location.Path == "/",
			Path:           location.Path,
			Backend:        location.Backend,
			HAWhitelist:    haWhitelist,
		}
		// RootLocation `/` means "any other URL" on Ingress.
		// HAMatchPath build this strategy on HAProxy.
		if haLocation.IsRootLocation {
			haRootLocation = &haLocation
		} else {
			otherPaths = otherPaths + " " + location.Path
			haLocation.HAMatchPath = " { path_beg " + haLocation.Path + " }"
		}
		haLocations[i] = &haLocation
	}
	if haRootLocation != nil && otherPaths != "" {
		haRootLocation.HAMatchPath = " !{ path_beg" + otherPaths + " }"
	}
	return
}
