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
	"crypto/md5"
	"fmt"
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/file"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/hsts"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	api "k8s.io/api/core/v1"
	"os"
	"regexp"
	"strings"
)

const (
	defaultSSLCiphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
	dhparamFilename   = "dhparam.pem"
)

type haConfig struct {
	ingress           *ingress.Configuration
	haproxyController *HAProxyController
	userlists         map[string]types.Userlist
	haServers         []*types.HAProxyServer
	haProxies         []*types.HAProxyServer
	haDefaultServer   *types.HAProxyServer
	haproxyConfig     *types.HAProxyConfig
}

func newControllerConfig(ingressConfig *ingress.Configuration, haproxyController *HAProxyController) (*types.ControllerConfig, error) {
	cfg := &haConfig{}
	cfg.ingress = ingressConfig
	cfg.haproxyController = haproxyController
	cfg.createUserlists()
	cfg.createHAProxyServers()
	err := cfg.createDefaultCert()
	if err != nil {
		return &types.ControllerConfig{}, err
	}
	return &types.ControllerConfig{
		Userlists:           cfg.userlists,
		Servers:             cfg.ingress.Servers,
		Backends:            cfg.ingress.Backends,
		HAServers:           cfg.haServers,
		HAProxies:           cfg.haProxies,
		DefaultServer:       cfg.haDefaultServer,
		TCPEndpoints:        cfg.ingress.TCPEndpoints,
		UDPEndpoints:        cfg.ingress.UDPEndpoints,
		PassthroughBackends: cfg.ingress.PassthroughBackends,
		Cfg:                 newHAProxyConfig(haproxyController),
	}, nil
}

func newHAProxyConfig(haproxyController *HAProxyController) *types.HAProxyConfig {
	conf := types.HAProxyConfig{
		Backend: defaults.Backend{
			HSTS:                  true,
			HSTSMaxAge:            "15768000",
			HSTSIncludeSubdomains: false,
			HSTSPreload:           false,
			ProxyBodySize:         "",
			SSLRedirect:           true,
		},
		SSLCiphers: defaultSSLCiphers,
		SSLOptions: "no-sslv3 no-tls-tickets",
		SSLDHParam: types.SSLDHParam{
			DefaultMaxSize: 1024,
			SecretName:     "",
		},
		LoadServerState:             false,
		TimeoutHTTPRequest:          "5s",
		TimeoutConnect:              "5s",
		TimeoutClient:               "50s",
		TimeoutClientFin:            "50s",
		TimeoutServer:               "50s",
		TimeoutServerFin:            "50s",
		TimeoutTunnel:               "1h",
		TimeoutKeepAlive:            "1m",
		Syslog:                      "",
		BalanceAlgorithm:            "roundrobin",
		BackendCheckInterval:        "2s",
		Forwardfor:                  "add",
		MaxConn:                     2000,
		SSLHeadersPrefix:            "X-SSL",
		HealthzPort:                 10253,
		HTTPStoHTTPPort:             0,
		StatsPort:                   1936,
		StatsAuth:                   "",
		CookieKey:                   "Ingress",
		DynamicScaling:              false,
		BackendServerSlotsIncrement: 32,
		StatsSocket:                 "/var/run/haproxy-stats.sock",
		UseProxyProtocol:            false,
		StatsProxyProtocol:          false,
		UseHostOnHTTPS:              false,
		HTTPLogFormat:               "",
		HTTPSLogFormat:              "",
		TCPLogFormat:                "",
	}
	if haproxyController.configMap != nil {
		utils.MergeMap(haproxyController.configMap.Data, &conf)
		configDHParam(haproxyController, &conf)
		configForwardfor(&conf)
	}
	return &conf
}

// TODO Ingress core should provide this
// read ssl-dh-param secret
func configDHParam(haproxyController *HAProxyController, conf *types.HAProxyConfig) {
	if conf.SSLDHParam.SecretName != "" {
		secretName := conf.SSLDHParam.SecretName
		secret, exists, err := haproxyController.storeLister.Secret.GetByKey(secretName)
		if err != nil {
			glog.Warningf("error reading secret %v: %v", secretName, err)
		} else if exists {
			if dh, ok := secret.(*api.Secret).Data[dhparamFilename]; ok {
				pem := strings.Replace(secretName, "/", "-", -1)
				if pemFileName, err := ssl.AddOrUpdateDHParam(pem, dh); err == nil {
					conf.SSLDHParam.Filename = pemFileName
					conf.SSLDHParam.PemSHA = file.SHA1(pemFileName)
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
}

func configForwardfor(conf *types.HAProxyConfig) {
	if conf.Forwardfor != "add" && conf.Forwardfor != "ignore" && conf.Forwardfor != "ifmissing" {
		glog.Warningf("Invalid forwardfor value option on configmap: %v. Using 'add' instead", conf.Forwardfor)
		conf.Forwardfor = "add"
	}
}

func (cfg *haConfig) createHAProxyServers() {
	haServers := make([]*types.HAProxyServer, 0, len(cfg.ingress.Servers))
	var haDefaultServer *types.HAProxyServer
	for _, server := range cfg.ingress.Servers {
		if server.SSLPassthrough {
			// remove SSLPassthrough hosts from haServers array
			continue
		}
		haLocations, haRootLocation := cfg.newHAProxyLocations(server)
		sslRedirect := serverSSLRedirect(server)
		isDefaultServer := server.Hostname == "_"
		isCACert := server.CertificateAuth.AuthSSLCert.CAFileName != ""
		haServer := types.HAProxyServer{
			IsDefaultServer: isDefaultServer,
			IsCACert:        isCACert,
			UseHTTP:         server.SSLCertificate == "" || !sslRedirect || isDefaultServer,
			UseHTTPS:        server.SSLCertificate != "" || isDefaultServer,
			Hostname:        server.Hostname,
			HostnameLabel:   labelizeHostname(server.Hostname),
			HostnameSocket:  sockHostname(labelizeHostname(server.Hostname)),
			ACLLabel:        labelizeACL(server.Hostname),
			SSLCertificate:  server.SSLCertificate,
			SSLPemChecksum:  server.SSLPemChecksum,
			RootLocation:    haRootLocation,
			Locations:       haLocations,
			SSLRedirect:     sslRedirect,
			HSTS:            serverHSTS(server),
			HasRateLimit:    serverHasRateLimit(server),
			CertificateAuth: server.CertificateAuth,
			Alias:           server.Alias,
		}
		if isDefaultServer {
			haDefaultServer = &haServer
		} else {
			haServers = append(haServers, &haServer)
		}
	}
	cfg.haServers = haServers
	cfg.haProxies = append(haServers, haDefaultServer)
	cfg.haDefaultServer = haDefaultServer
}

func (cfg *haConfig) createDefaultCert() error {
	// HAProxy uses the first file from ssldir as the default certificate
	defaultCert := fmt.Sprintf("%v/%v", ingress.DefaultSSLDirectory, "+default.pem")
	os.Remove(defaultCert)
	err := os.Link(cfg.haDefaultServer.SSLCertificate, defaultCert)
	return err
}

func (cfg *haConfig) newHAProxyLocations(server *ingress.Server) ([]*types.HAProxyLocation, *types.HAProxyLocation) {
	locations := server.Locations
	haLocations := make([]*types.HAProxyLocation, len(locations))
	var haRootLocation *types.HAProxyLocation
	otherPaths := ""
	for i, location := range locations {
		haLocation := types.HAProxyLocation{
			IsRootLocation: location.Path == "/",
			Path:           location.Path,
			Backend:        location.Backend,
			HSTS:           location.HSTS,
			Rewrite:        location.Rewrite,
			Redirect:       location.Redirect,
			Proxy:          location.Proxy,
			RateLimit:      location.RateLimit,
		}
		for _, cidr := range location.Whitelist.CIDR {
			haLocation.HAWhitelist = haLocation.HAWhitelist + " " + cidr
		}
		for _, cidr := range location.RateLimit.Whitelist {
			haLocation.HARateLimitWhiteList = haLocation.HARateLimitWhiteList + " " + cidr
		}
		if userList, ok := cfg.userlists[location.BasicDigestAuth.ListName]; ok {
			haLocation.Userlist = userList
		} else {
			haLocation.Userlist = types.Userlist{}
		}
		// RootLocation `/` means "any other URL" on Ingress.
		// HAMatchPath build this strategy on HAProxy.
		if haLocation.IsRootLocation {
			haRootLocation = &haLocation
		} else {
			otherPaths = otherPaths + " " + location.Path
			haLocation.HAMatchPath = " { path -m beg " + haLocation.Path + " }"
			haLocation.HAMatchTxnPath = " { var(txn.path) -m beg " + haLocation.Path + " }"
		}
		haLocations[i] = &haLocation
	}
	if haRootLocation != nil && otherPaths != "" {
		haRootLocation.HAMatchPath = " !{ path -m beg " + otherPaths + " }"
		haRootLocation.HAMatchTxnPath = " !{ var(txn.path) -m beg " + otherPaths + " }"
	}
	return haLocations, haRootLocation
}

func labelizeHostname(hostname string) string {
	if hostname == "_" {
		return "default-backend"
	}
	re := regexp.MustCompile(`[^a-zA-Z0-9:_\-.]`)
	return re.ReplaceAllLiteralString(hostname, "_")
}

func labelizeACL(hostname string) string {
	if hostname == "_" {
		return ""
	}
	return fmt.Sprintf("host-%v", labelizeHostname(hostname))
}

func sockHostname(hostname string) string {
	if len(hostname) > 65 {
		return fmt.Sprintf("%x", md5.Sum([]byte(hostname)))
	}
	return hostname
}

// This could be improved creating a list of auth secrets (or even configMaps)
// on Ingress and saving usr(s)/pwd in auth.BasicDigest struct
func (cfg *haConfig) createUserlists() {
	userlists := map[string]types.Userlist{}
	for _, server := range cfg.ingress.Servers {
		for _, location := range server.Locations {
			listName := location.BasicDigestAuth.ListName
			fileName := location.BasicDigestAuth.File
			authType := location.BasicDigestAuth.Type
			if authType == "basic" {
				if _, ok := userlists[listName]; !ok {
					users, err := readUsers(fileName, listName)
					if err != nil {
						glog.Errorf("unexpected error reading userlist %v: %v", listName, err)
						users = []types.AuthUser{}
					}
					userlists[listName] = types.Userlist{
						ListName: listName,
						Realm:    location.BasicDigestAuth.Realm,
						Users:    users,
					}
				}
			}
		}
	}
	cfg.userlists = userlists
}

func readUsers(fileName string, listName string) ([]types.AuthUser, error) {
	if fileName == "" {
		return []types.AuthUser{}, nil
	}
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
			glog.Warningf("missing ':' in userlist '%v'", listName)
			break
		}
		userName := line[0:sep]
		if userName == "" {
			glog.Warningf("missing username in userlist '%v'", listName)
			break
		}
		if sep == len(line)-1 || line[sep:] == "::" {
			glog.Warningf("missing '%v' password in userlist '%v'", userName, listName)
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
func serverSSLRedirect(server *ingress.Server) bool {
	for _, location := range server.Locations {
		if !location.Rewrite.SSLRedirect {
			return false
		}
	}
	return true
}

// serverHSTS return a common hsts.Config between all locations
// if such configurations exists, otherwise return nil which
// mean difference on at least one location
func serverHSTS(server *ingress.Server) *hsts.Config {
	var hsts *hsts.Config
	hsts = nil
	for _, location := range server.Locations {
		if hsts == nil {
			hsts = &location.HSTS
		} else if !location.HSTS.Equal(hsts) {
			return nil
		}
	}
	return hsts
}

func serverHasRateLimit(server *ingress.Server) bool {
	for _, location := range server.Locations {
		if location.RateLimit.Connections.Limit > 0 || location.RateLimit.RPS.Limit > 0 {
			return true
		}
	}
	return false
}
