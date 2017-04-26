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

package controller

import (
	"bufio"
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	api "k8s.io/client-go/pkg/api/v1"
	"k8s.io/ingress/core/pkg/ingress"
	"k8s.io/ingress/core/pkg/ingress/defaults"
	"k8s.io/ingress/core/pkg/net/ssl"
	"os"
	"strings"
)

const (
	defaultSSLCiphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
	dhparamFilename   = "dhparam.pem"
)

func newControllerConfig(cfg *ingress.Configuration, haproxy *HAProxyController) *types.ControllerConfig {
	userlists := newUserlists(cfg.Servers)
	haHTTPServers, haHTTPSServers, haDefaultServer := newHAProxyServers(userlists, cfg.Servers)
	conf := types.ControllerConfig{
		Userlists:           userlists,
		Backends:            cfg.Backends,
		HTTPServers:         haHTTPServers,
		HTTPSServers:        haHTTPSServers,
		DefaultServer:       haDefaultServer,
		TCPEndpoints:        cfg.TCPEndpoints,
		UDPEndpoints:        cfg.UDPEndpoints,
		PassthroughBackends: cfg.PassthroughBackends,
		Cfg:                 newHAProxyConfig(haproxy),
	}
	return &conf
}

func newHAProxyConfig(haproxy *HAProxyController) *types.HAProxyConfig {
	conf := types.HAProxyConfig{
		Backend: defaults.Backend{
			SSLRedirect: true,
		},
		SSLCiphers: defaultSSLCiphers,
		SSLOptions: "no-sslv3 no-tls-tickets",
		SSLDHParam: types.SSLDHParam{
			DefaultMaxSize: 1024,
			SecretName:     "",
		},
		TimeoutHTTPRequest:    "5s",
		TimeoutConnect:        "5s",
		TimeoutClient:         "50s",
		TimeoutClientFin:      "50s",
		TimeoutServer:         "50s",
		TimeoutServerFin:      "50s",
		TimeoutTunnel:         "1h",
		TimeoutKeepAlive:      "1m",
		Syslog:                "",
		BalanceAlgorithm:      "roundrobin",
		BackendCheckInterval:  "2s",
		MaxConn:               2000,
		HSTS:                  true,
		HSTSMaxAge:            "15768000",
		HSTSIncludeSubdomains: false,
		HSTSPreload:           false,
		StatsPort:             1936,
		StatsAuth:             "",
	}
	if haproxy.configMap != nil {
		utils.MergeMap(haproxy.configMap.Data, &conf)
	}

	// TODO Ingress core should provide this
	// read ssl-dh-param secret
	if conf.SSLDHParam.SecretName != "" {
		secretName := conf.SSLDHParam.SecretName
		secret, exists, err := haproxy.storeLister.Secret.GetByKey(secretName)
		if err != nil {
			glog.Warningf("error reading secret %v: %v", secretName, err)
		} else if exists {
			if dh, ok := secret.(*api.Secret).Data[dhparamFilename]; ok {
				pem := strings.Replace(secretName, "/", "-", -1)
				if pemFileName, err := ssl.AddOrUpdateDHParam(pem, dh); err == nil {
					conf.SSLDHParam.Filename = pemFileName
					conf.SSLDHParam.PemSHA = ssl.PemSHA1(pemFileName)
				} else {
					glog.Warningf("error creating dh-param file %v: %v", pem, err)
				}
			} else {
				glog.Warningf("secret %v does not contain file %v", secretName, dhparamFilename)
			}
		} else {
			glog.Warningf("secret not found: %v", secretName)
		}
	}

	return &conf
}

func newHAProxyServers(userlists map[string]types.Userlist, servers []*ingress.Server) ([]*types.HAProxyServer, []*types.HAProxyServer, *types.HAProxyServer) {
	haHTTPServers := make([]*types.HAProxyServer, 0, len(servers))
	haHTTPSServers := make([]*types.HAProxyServer, 0, len(servers))
	var haDefaultServer *types.HAProxyServer
	for _, server := range servers {
		haLocations, haRootLocation := newHAProxyLocations(userlists, server)
		haServer := types.HAProxyServer{
			// Ingress uses `_` hostname as default server
			IsDefaultServer: server.Hostname == "_",
			Hostname:        server.Hostname,
			SSLCertificate:  server.SSLCertificate,
			SSLPemChecksum:  server.SSLPemChecksum,
			RootLocation:    haRootLocation,
			Locations:       haLocations,
			SSLRedirect:     serverSSLRedirect(server),
		}
		if haServer.IsDefaultServer {
			haDefaultServer = &haServer
		} else if haServer.SSLCertificate == "" {
			haHTTPServers = append(haHTTPServers, &haServer)
		} else {
			haHTTPSServers = append(haHTTPSServers, &haServer)
			if !haServer.SSLRedirect {
				haHTTPServers = append(haHTTPServers, &haServer)
			}
		}
	}
	return haHTTPServers, haHTTPSServers, haDefaultServer
}

func newHAProxyLocations(userlists map[string]types.Userlist, server *ingress.Server) ([]*types.HAProxyLocation, *types.HAProxyLocation) {
	locations := server.Locations
	haLocations := make([]*types.HAProxyLocation, len(locations))
	var haRootLocation *types.HAProxyLocation
	otherPaths := ""
	for i, location := range locations {
		haWhitelist := ""
		for _, cidr := range location.Whitelist.CIDR {
			haWhitelist = haWhitelist + " " + cidr
		}
		users, ok := userlists[location.BasicDigestAuth.File]
		if !ok {
			users = types.Userlist{}
		}
		haLocation := types.HAProxyLocation{
			IsRootLocation:  location.Path == "/",
			Path:            location.Path,
			Backend:         location.Backend,
			Redirect:        location.Redirect,
			CertificateAuth: location.CertificateAuth,
			Userlist:        users,
			HAWhitelist:     haWhitelist,
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
	return haLocations, haRootLocation
}

// This could be improved creating a list of auth secrets (or even configMaps)
// on Ingress and saving usr(s)/pwd in auth.BasicDigest struct
func newUserlists(servers []*ingress.Server) map[string]types.Userlist {
	userlists := map[string]types.Userlist{}
	for _, server := range servers {
		for _, location := range server.Locations {
			fileName := location.BasicDigestAuth.File
			authType := location.BasicDigestAuth.Type
			if fileName != "" && authType == "basic" {
				_, ok := userlists[fileName]
				if !ok {
					slashPos := strings.LastIndex(fileName, "/")
					dotPos := strings.LastIndex(fileName, ".")
					listName := fileName[slashPos+1 : dotPos]
					users, err := readUsers(fileName, listName)
					if err != nil {
						glog.Errorf("Unexpected error reading %v: %v", listName, err)
						break
					}
					userlists[fileName] = types.Userlist{
						ListName: listName,
						Realm:    location.BasicDigestAuth.Realm,
						Users:    users,
					}
				}
			}
		}
	}
	return userlists
}

func readUsers(fileName string, listName string) ([]types.AuthUser, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	users := []types.AuthUser{}
	for scanner.Scan() {
		line := scanner.Text()
		sep := strings.Index(line, ":")
		if sep == -1 {
			glog.Warningf("Missing ':' on userlist '%v'", listName)
			break
		}
		userName := line[0:sep]
		if userName == "" {
			glog.Warningf("Missing username on userlist '%v'", listName)
			break
		}
		if sep == len(line)-1 || line[sep:] == "::" {
			glog.Warningf("Missing '%v' password on userlist '%v'", userName, listName)
			break
		}
		user := types.AuthUser{}
		// if usr::pwd
		if string(line[sep+1]) == ":" {
			user = types.AuthUser{
				Username:  userName,
				Password:  line[sep+2:],
				Encrypted: false,
			}
		} else {
			user = types.AuthUser{
				Username:  userName,
				Password:  line[sep+1:],
				Encrypted: true,
			}
		}
		users = append(users, user)
	}
	return users, nil
}

// serverSSLRedirect Configure a global (per hostname) ssl redirect only if
// all locations also configure ssl redirect.
// A location that doesn't configure ssl redirect will be ignored if it is
// also a default backend (eg. undeclared root context)
func serverSSLRedirect(server *ingress.Server) bool {
	for _, location := range server.Locations {
		if !location.Redirect.SSLRedirect && !location.IsDefBackend {
			return false
		}
	}
	return true
}
