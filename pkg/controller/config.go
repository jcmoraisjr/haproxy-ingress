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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/balance"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/cors"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/dnsresolvers"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/hsts"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/oauth"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/proxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/waf"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	api "k8s.io/api/core/v1"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	haDefaultServer   *types.HAProxyServer
	haPassthrough     []*types.HAProxyPassthrough
	haproxyConfig     *types.HAProxyConfig
	DNSResolvers      map[string]dnsresolvers.DNSResolver
	procs             *types.HAProxyProcs
}

func newControllerConfig(ingressConfig *ingress.Configuration, haproxyController *HAProxyController) (*types.ControllerConfig, error) {
	cfg := &haConfig{
		ingress:           ingressConfig,
		haproxyController: haproxyController,
		haproxyConfig:     newHAProxyConfig(haproxyController),
	}
	cfg.createUserlists()
	cfg.createHAProxyServers()
	err := cfg.createFrontendCertsDir()
	if err != nil {
		return &types.ControllerConfig{}, err
	}
	cfg.createDNSResolvers()
	cfg.createProcs()
	return &types.ControllerConfig{
		ConfigFrontend:      cfg.configFrontend(),
		Userlists:           cfg.userlists,
		Servers:             cfg.ingress.Servers,
		Backends:            cfg.ingress.Backends,
		HAServers:           cfg.haServers,
		DefaultServer:       cfg.haDefaultServer,
		TCPEndpoints:        cfg.ingress.TCPEndpoints,
		UDPEndpoints:        cfg.ingress.UDPEndpoints,
		PassthroughBackends: cfg.ingress.PassthroughBackends,
		HAPassthrough:       cfg.haPassthrough,
		StatsSSLCert:        cfg.statsSSLCert(),
		Procs:               cfg.procs,
		Cfg:                 cfg.haproxyConfig,
		DNSResolvers:        cfg.DNSResolvers,
	}, nil
}

func newHAProxyConfig(haproxyController *HAProxyController) *types.HAProxyConfig {
	conf := types.HAProxyConfig{
		Backend: defaults.Backend{
			BackendServerSlotsIncrement: 32,
			BalanceAlgorithm:            "roundrobin",
			HSTS:                        true,
			HSTSMaxAge:                  "15768000",
			HSTSIncludeSubdomains:       false,
			HSTSPreload:                 false,
			ProxyBodySize:               "",
			SSLRedirect:                 true,
		},
		SSLCiphers: defaultSSLCiphers,
		SSLOptions: "no-sslv3 no-tls-tickets",
		SSLDHParam: types.SSLDHParam{
			DefaultMaxSize: 2048,
			SecretName:     "",
		},
		NbprocBalance:          1,
		NbprocSSL:              0,
		Nbthread:               1,
		LoadServerState:        false,
		TimeoutHTTPRequest:     "5s",
		TimeoutConnect:         "5s",
		TimeoutClient:          "50s",
		TimeoutClientFin:       "50s",
		TimeoutQueue:           "5s",
		TimeoutServer:          "50s",
		TimeoutServerFin:       "50s",
		TimeoutStop:            "",
		TimeoutTunnel:          "1h",
		TimeoutKeepAlive:       "1m",
		BindIPAddrTCP:          "*",
		BindIPAddrHTTP:         "*",
		BindIPAddrStats:        "*",
		BindIPAddrHealthz:      "*",
		Syslog:                 "",
		ModSecurity:            "",
		ModSecTimeoutHello:     "100ms",
		ModSecTimeoutIdle:      "30s",
		ModSecTimeoutProc:      "1s",
		BackendCheckInterval:   "2s",
		ConfigFrontend:         "",
		Forwardfor:             "add",
		MaxConn:                2000,
		NoTLSRedirect:          "/.well-known/acme-challenge",
		SSLHeadersPrefix:       "X-SSL",
		HealthzPort:            10253,
		HTTPStoHTTPPort:        0,
		StatsPort:              1936,
		StatsAuth:              "",
		StatsSSLCert:           "",
		CookieKey:              "Ingress",
		StrictHost:             true,
		DynamicScaling:         false,
		StatsSocket:            "/var/run/haproxy-stats.sock",
		UseProxyProtocol:       false,
		StatsProxyProtocol:     false,
		UseHostOnHTTPS:         false,
		HTTPPort:               80,
		HTTPLogFormat:          "",
		HTTPSPort:              443,
		HTTPSLogFormat:         "",
		TCPLogFormat:           "",
		DrainSupport:           false,
		DNSResolvers:           "",
		DNSTimeoutRetry:        "1s",
		DNSHoldObsolete:        "0s",
		DNSHoldValid:           "1s",
		DNSAcceptedPayloadSize: 8192,
		DNSClusterDomain:       "cluster.local",
	}
	if haproxyController.configMap != nil {
		utils.MergeMap(haproxyController.configMap.Data, &conf)
		configDHParam(haproxyController, &conf)
		configForwardfor(&conf)
	}
	validateConfig(&conf)
	return &conf
}

func validateConfig(conf *types.HAProxyConfig) {
	b := conf.BalanceAlgorithm
	if !balance.IsValidBalance(b) {
		glog.Warningf("invalid default algorithm '%v', using roundrobin instead", b)
		conf.BalanceAlgorithm = "roundrobin"
	}
	bs := conf.ProxyBodySize
	if !proxy.IsValidProxyBodySize(bs) {
		if bs != "unlimited" {
			glog.Warningf("invalid proxy body size '%v', using unlimited", bs)
		}
		conf.ProxyBodySize = ""
	}
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

func (cfg *haConfig) createDNSResolvers() {
	resolvers := map[string]dnsresolvers.DNSResolver{}
	data := strings.Split(cfg.haproxyConfig.DNSResolvers, "\n")
	for _, resolver := range data {
		resolverData := strings.Split(resolver, "=")
		if len(resolverData) != 2 {
			if len(resolver) != 0 {
				glog.Infof("misconfigured DNS resolver: %s", resolver)
			}
			continue
		}
		nameservers := map[string]string{}
		nameserversData := strings.Split(resolverData[1], ",")
		for _, nameserver := range nameserversData {
			nameserverData := strings.Split(nameserver, ":")
			if len(nameserverData) == 1 {
				nameservers[nameserverData[0]] = "53"
			} else {
				nameservers[nameserverData[0]] = nameserverData[1]
			}
		}
		resolvers[resolverData[0]] = dnsresolvers.DNSResolver{
			Name:        resolverData[0],
			Nameservers: nameservers,
		}
	}

	//resolvers := dnsresolvers.ParseDNSResolvers(cfg.haproxyConfig.DNSResolvers)
	for _, backend := range cfg.ingress.Backends {
		backendUseResolver := backend.UseResolver
		if backendUseResolver == "" {
			continue
		}
		if _, ok := resolvers[backendUseResolver]; !ok {
			glog.Warningf("resolver name %s not found, not using DNS resolving", backendUseResolver)
			backend.UseResolver = ""
		}
	}
	cfg.DNSResolvers = resolvers
}

func (cfg *haConfig) statsSSLCert() *ingress.SSLCert {
	secretName := cfg.haproxyConfig.StatsSSLCert
	if secretName == "" {
		return &ingress.SSLCert{}
	}
	sslCert, err := cfg.haproxyController.controller.GetCertificate(secretName)
	if err != nil {
		glog.Warningf("error loading stats cert/key: %v", err)
		return &ingress.SSLCert{}
	}
	return sslCert
}

func (cfg *haConfig) configFrontend() []string {
	config := cfg.haproxyConfig.ConfigFrontend
	if config == "" {
		return []string{}
	}
	return strings.Split(strings.TrimRight(config, "\n"), "\n")
}

func (cfg *haConfig) createHAProxyServers() {
	haServers := make([]*types.HAProxyServer, 0, len(cfg.ingress.Servers))
	haPassthrough := make([]*types.HAProxyPassthrough, 0, len(cfg.ingress.PassthroughBackends))
	var haDefaultServer *types.HAProxyServer
	for _, server := range cfg.ingress.PassthroughBackends {
		haServer := &types.HAProxyPassthrough{
			Hostname:           server.Hostname,
			Alias:              false,
			ACLLabel:           labelizeACL(server.Hostname),
			Backend:            server.Backend,
			HTTPPassBackend:    server.HTTPPassBackend,
			HostnameIsWildcard: idHasWildcard(server.Hostname),
		}
		haPassthrough = append(haPassthrough, haServer)
	}
	for _, server := range cfg.ingress.Servers {
		if server.SSLPassthrough.HasSSLPassthrough {
			// remove SSLPassthrough hosts from haServers array
			continue
		}
		haLocations, haRootLocation := cfg.newHAProxyLocations(server)
		sslRedirect := serverSSLRedirect(haLocations)
		isDefaultServer := server.Hostname == "_"
		isCACert := server.CertificateAuth.AuthSSLCert.CAFileName != ""
		haServer := types.HAProxyServer{
			IsDefaultServer:    isDefaultServer,
			IsCACert:           isCACert,
			UseHTTP:            server.SSLCertificate == "" || !sslRedirect || isDefaultServer,
			UseHTTPS:           server.SSLCertificate != "" || isDefaultServer,
			Hostname:           server.Hostname,
			HostnameIsWildcard: idHasWildcard(server.Hostname),
			HostnameLabel:      labelizeHostname(server.Hostname),
			HostnameSocket:     sockHostname(labelizeHostname(server.Hostname)),
			ACLLabel:           labelizeACL(server.Hostname),
			SSLCertificate:     server.SSLCertificate,
			SSLPemChecksum:     server.SSLPemChecksum,
			RootLocation:       haRootLocation,
			Locations:          haLocations,
			SSLRedirect:        sslRedirect,
			HSTS:               serverHSTS(server),
			CORS:               serverCORS(server),
			WAF:                serverWAF(server),
			HasRateLimit:       serverHasRateLimit(server),
			OAuth:              serverOAuth(server),
			CertificateAuth:    server.CertificateAuth,
			Alias:              server.Alias,
			AliasIsRegex:       idHasRegex(server.Alias),
		}
		if isDefaultServer {
			haDefaultServer = &haServer
		} else {
			haServers = append(haServers, &haServer)
		}
	}
	sort.SliceStable(haServers, func(i, j int) bool {
		// Move hosts without wildcard and alias without regex to the top,
		// following are hosts without wildcard whose alias has regex, and
		// finally with the least precedence are hosts with wildcards
		a, b := 0, 0
		if haServers[i].HostnameIsWildcard {
			a = 2
		} else if haServers[i].AliasIsRegex {
			a = 1
		}
		if haServers[j].HostnameIsWildcard {
			b = 2
		} else if haServers[j].AliasIsRegex {
			b = 1
		}
		return a < b
	})
	sort.SliceStable(haPassthrough, func(i, j int) bool {
		// Move hosts without wildcard to the top
		// if not isWildcard means priority, if isWildcard means less priority
		return !haPassthrough[i].HostnameIsWildcard && haPassthrough[j].HostnameIsWildcard
	})
	cfg.haServers = haServers
	cfg.haPassthrough = haPassthrough
	cfg.haDefaultServer = haDefaultServer
}

func (cfg *haConfig) createFrontendCertsDir() error {
	// HAProxy uses the first file from ssldir as the default certificate
	// TODO use a hash suffix and lazy removing in order to preserve
	// the old configuration if parsing the new one does not work
	certsDir := ingress.DefaultSSLDirectory + "/shared-frontend/"
	if err := os.RemoveAll(certsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(certsDir, 700); err != nil {
		return err
	}
	defaultCertFile := cfg.haDefaultServer.SSLCertificate
	if err := os.Link(defaultCertFile, certsDir+"+default.pem"); err != nil {
		return err
	}
	certUsed := make(map[string]bool, len(cfg.haServers))
	for _, server := range cfg.haServers {
		certFile := server.SSLCertificate
		// only if it's an unused non default certificate
		if certFile != "" && !certUsed[certFile] && certFile != defaultCertFile {
			certFileName := filepath.Base(certFile)
			if err := os.Link(certFile, certsDir+certFileName); err != nil {
				return err
			}
		}
		certUsed[certFile] = true
	}
	return nil
}

func (cfg *haConfig) createProcs() {
	balance := cfg.haproxyConfig.NbprocBalance
	if balance < 1 {
		glog.Warningf("invalid value of nbproc-balance configmap option (%v), using 1", balance)
		balance = 1
	}
	if balance > 1 {
		// need to visit (at least) statistics and healthz bindings as well
		// as admin socket before using more than one balance backend
		glog.Warningf("nbproc-balance configmap option (%v) greater than 1 is not yet supported, using 1", balance)
		balance = 1
	}
	ssl := cfg.haproxyConfig.NbprocSSL
	if ssl < 0 {
		glog.Warningf("invalid value of nbproc-ssl configmap option (%v), using 0", ssl)
		ssl = 0
	}
	procs := balance + ssl
	threads := cfg.haproxyConfig.Nbthread
	if threads < 1 {
		glog.Warningf("invalid value of nbthread configmap option (%v), using 1", threads)
		threads = 1
	}
	bindprocBalance := "1"
	if balance > 1 {
		bindprocBalance = fmt.Sprintf("1-%v", balance)
	}
	bindprocSSL := ""
	if ssl == 0 {
		bindprocSSL = bindprocBalance
	} else if ssl == 1 {
		bindprocSSL = fmt.Sprintf("%v", balance+1)
	} else if ssl > 1 {
		bindprocSSL = fmt.Sprintf("%v-%v", balance+1, procs)
	}
	cpumap := ""
	if threads > 1 {
		if procs == 1 {
			cpumap = fmt.Sprintf("auto:1/1-%v 0-%v", threads, threads-1)
		}
	} else if procs > 1 {
		cpumap = fmt.Sprintf("auto:1-%v 0-%v", procs, procs-1)
	}
	cfg.procs = &types.HAProxyProcs{
		Nbproc:          procs,
		NbprocBalance:   balance,
		NbprocSSL:       ssl,
		Nbthread:        threads,
		BindprocBalance: bindprocBalance,
		BindprocSSL:     bindprocSSL,
		CPUMap:          cpumap,
	}
}

func (cfg *haConfig) newHAProxyLocations(server *ingress.Server) ([]*types.HAProxyLocation, *types.HAProxyLocation) {
	locations := server.Locations
	haLocations := make([]*types.HAProxyLocation, len(locations))
	var haRootLocation *types.HAProxyLocation
	otherPaths := ""
	for i, location := range locations {
		// Template trust only in the SSLRedirect attr to configure
		// the redirect itself and the URL rewrite
		// So turn SSLRedirect off despite of its original configuration
		// if there isn't a certificate to this server
		haLocation := types.HAProxyLocation{
			IsRootLocation: location.Path == "/",
			IsDefBackend:   location.IsDefBackend,
			Path:           location.Path,
			Backend:        location.Backend,
			OAuth:          location.OAuth,
			CORS:           location.CorsConfig,
			HSTS:           location.HSTS,
			WAF:            location.WAF,
			Rewrite:        location.Rewrite,
			Redirect:       location.Redirect,
			SSLRedirect:    location.Rewrite.SSLRedirect && server.SSLCertificate != "" && cfg.allowRedirect(location.Path),
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

func (cfg *haConfig) allowRedirect(path string) bool {
	for _, restrictPath := range strings.Split(cfg.haproxyConfig.NoTLSRedirect, ",") {
		if restrictPath != "" && strings.HasPrefix(path, restrictPath) {
			return false
		}
	}
	return true
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

var (
	regexHasWildcard  = regexp.MustCompile(`^\*\.`)
	regexIsValidIdent = regexp.MustCompile(`^[a-zA-Z0-9\-.]+$`)
)

func idHasWildcard(identifier string) bool {
	return regexHasWildcard.MatchString(identifier)
}

func idHasRegex(identifier string) bool {
	return identifier != "" && !regexIsValidIdent.MatchString(identifier)
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
func serverSSLRedirect(locations []*types.HAProxyLocation) bool {
	for _, location := range locations {
		if !location.SSLRedirect {
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

func serverCORS(server *ingress.Server) *cors.CorsConfig {
	var cors *cors.CorsConfig
	cors = nil
	for _, location := range server.Locations {
		if cors == nil {
			cors = &location.CorsConfig
		} else if !location.CorsConfig.Equal(cors) {
			return nil
		}
	}
	return cors
}

func serverWAF(server *ingress.Server) *waf.Config {
	var waf *waf.Config
	waf = nil
	for _, location := range server.Locations {
		if waf == nil {
			waf = &location.WAF
		} else if !location.WAF.Equal(waf) {
			return nil
		}
	}
	return waf
}

func serverHasRateLimit(server *ingress.Server) bool {
	for _, location := range server.Locations {
		if location.RateLimit.Connections.Limit > 0 || location.RateLimit.RPS.Limit > 0 {
			return true
		}
	}
	return false
}

func serverOAuth(server *ingress.Server) *oauth.Config {
	for _, location := range server.Locations {
		if location.OAuth.OAuthImpl != "" {
			return &location.OAuth
		}
	}
	return nil
}
