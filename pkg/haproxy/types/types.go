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

package types

// Global ...
type Global struct {
	Bind            GlobalBindConfig
	Procs           ProcsConfig
	Syslog          SyslogConfig
	MaxConn         int
	Timeout         TimeoutConfig
	SSL             SSLConfig
	DNS             DNSConfig
	ModSecurity     ModSecurityConfig
	Cookie          CookieConfig
	DrainSupport    DrainConfig
	ForwardFor      string
	LoadServerState bool
	AdminSocket     string
	Healthz         HealthzConfig
	Stats           StatsConfig
	StrictHost      bool
	UseHTX          bool
	CustomConfig    []string
	CustomDefaults  []string
	CustomFrontend  []string
}

// GlobalBindConfig ...
type GlobalBindConfig struct {
	AcceptProxy    bool
	HTTPBind       string
	HTTPSBind      string
	TCPBindIP      string
	FrontingBind   string
	FrontingSockID int
}

// ProcsConfig ...
type ProcsConfig struct {
	Nbproc          int
	Nbthread        int
	NbprocBalance   int
	NbprocSSL       int
	BindprocBalance string
	BindprocSSL     string
	CPUMap          string
}

// SyslogConfig ...
type SyslogConfig struct {
	Endpoint       string
	Format         string
	HTTPLogFormat  string
	HTTPSLogFormat string
	Length         int
	Tag            string
	TCPLogFormat   string
}

// TimeoutConfig ...
type TimeoutConfig struct {
	HostTimeoutConfig
	BackendTimeoutConfig
	Stop string
}

// SSLConfig ...
type SSLConfig struct {
	ALPN                string
	BackendCiphers      string
	BackendCipherSuites string
	BackendOptions      string
	Ciphers             string // TLS up to 1.2
	CipherSuites        string // TLS 1.3
	DHParam             DHParamConfig
	Engine              string
	HeadersPrefix       string
	ModeAsync           bool
	Options             string
}

// DHParamConfig ...
type DHParamConfig struct {
	Filename       string
	DefaultMaxSize int
}

// DNSConfig ...
type DNSConfig struct {
	ClusterDomain string
	Resolvers     []*DNSResolver
}

// DNSResolver ...
type DNSResolver struct {
	Name                string
	Nameservers         []*DNSNameserver
	AcceptedPayloadSize int
	HoldObsolete        string
	HoldValid           string
	TimeoutRetry        string
}

// DNSNameserver ...
type DNSNameserver struct {
	Name     string
	Endpoint string
}

// ModSecurityConfig ...
type ModSecurityConfig struct {
	Endpoints []string
	Timeout   ModSecurityTimeoutConfig
}

// CookieConfig ...
type CookieConfig struct {
	Key string
}

// DrainConfig ...
type DrainConfig struct {
	Drain      bool
	Redispatch bool
}

// HealthzConfig ...
type HealthzConfig struct {
	BindIP string
	Port   int
}

// StatsConfig ...
type StatsConfig struct {
	AcceptProxy bool
	Auth        string
	BindIP      string
	Port        int
	TLSFilename string
	TLSHash     string
}

// ModSecurityTimeoutConfig ...
type ModSecurityTimeoutConfig struct {
	Hello      string
	Idle       string
	Processing string
}

// TCPBackend ...
type TCPBackend struct {
	Name          string
	Port          int
	Endpoints     []*TCPEndpoint
	CheckInterval string
	SSL           TCPSSL
	ProxyProt     TCPProxyProt
}

// TCPEndpoint ...
type TCPEndpoint struct {
	Name   string
	IP     string
	Port   int
	Target string
}

// TCPSSL ...
type TCPSSL struct {
	Filename string
}

// TCPProxyProt ...
type TCPProxyProt struct {
	Decode        bool
	EncodeVersion string
}

// HostsMapEntry ...
type HostsMapEntry struct {
	Key   string
	Value string
}

// HostsMap ...
type HostsMap struct {
	Match     []*HostsMapEntry
	MatchFile string
	Regex     []*HostsMapEntry
	RegexFile string
}

// HostsMaps ...
type HostsMaps struct {
	Items []*HostsMap
}

// FrontendGroup ...
type FrontendGroup struct {
	Frontends []*Frontend
	//
	DefaultBind       *BindConfig
	HasSSLPassthrough bool
	ToHTTPBind        BindConfig
	//
	Maps              *HostsMaps
	HTTPFrontsMap     *HostsMap
	HTTPRootRedirMap  *HostsMap
	HTTPSRedirMap     *HostsMap
	SSLPassthroughMap *HostsMap
}

// Frontend ...
type Frontend struct {
	Name  string
	Bind  BindConfig
	Hosts []*Host
	//
	Timeout HostTimeoutConfig
	//
	Maps                       *HostsMaps
	HostBackendsMap            *HostsMap
	MaxBodySizeMap             *HostsMap
	RootRedirMap               *HostsMap
	SNIBackendsMap             *HostsMap
	TLSInvalidCrtErrorList     *HostsMap
	TLSInvalidCrtErrorPagesMap *HostsMap
	TLSNoCrtErrorList          *HostsMap
	TLSNoCrtErrorPagesMap      *HostsMap
	VarNamespaceMap            *HostsMap
}

// BindConfig ...
type BindConfig struct {
	Name   string
	Socket string
	ID     int
	//
	AcceptProxy bool
	ALPN        string
	TLS         []*BindTLSConfig
	//
	UseServerList *HostsMap
	CrtList       *HostsMap
}

// BindTLSConfig ...
type BindTLSConfig struct {
	CAFilename  string
	CAHash      string
	CRLFilename string
	CRLHash     string
	CrtFilename string
	CrtHash     string
	Hostnames   []string
}

// Host ...
//
// Wildcard `*` hostname is a catch all and will be used if no other hostname,
// alias or regex matches the request. If wildcard hostname is not declared,
// the default backend will be used. If the default backend is empty,
// a default 404 page generated by HAProxy will be used.
type Host struct {
	Hostname string
	Paths    []*HostPath
	//
	Alias                  HostAliasConfig
	HTTPPassthroughBackend string
	RootRedirect           string
	SSLPassthrough         bool
	Timeout                HostTimeoutConfig
	TLS                    HostTLSConfig
	VarNamespace           bool
}

// HostPath ...
//
// Root context `/` path is a catch all and will be used if no other path
// matches the request on this host. If a root context path is not
// declared, the default backend will be used. If the default backend is
// empty, a default 404 page generated by HAProxy will be used.
type HostPath struct {
	Path    string
	Backend HostBackend
}

// HostBackend ...
type HostBackend struct {
	ID        string
	Namespace string
	Name      string
	Port      string
}

// HostAliasConfig ...
type HostAliasConfig struct {
	AliasName  string
	AliasRegex string
}

// HostTimeoutConfig ...
type HostTimeoutConfig struct {
	Client    string
	ClientFin string
}

// HostTLSConfig ...
type HostTLSConfig struct {
	CAErrorPage      string
	CAFilename       string
	CAHash           string
	CAVerifyOptional bool
	CRLFilename      string
	CRLHash          string
	TLSFilename      string
	TLSHash          string
}

// Backend ...
type Backend struct {
	//
	// core config
	//
	ID        string
	Namespace string
	Name      string
	Port      string
	Endpoints []*Endpoint
	BlueGreen BlueGreenConfig
	Paths     []*BackendPath
	PathsMap  *HostsMap
	//
	// per backend config
	//
	AgentCheck       AgentCheck
	BalanceAlgorithm string
	Cookie           Cookie
	CustomConfig     []string
	Dynamic          DynBackendConfig
	HealthCheck      HealthCheck
	Limit            BackendLimit
	ModeTCP          bool
	OAuth            OAuthConfig
	Resolver         string
	Server           ServerConfig
	Timeout          BackendTimeoutConfig
	TLS              BackendTLSConfig
	WhitelistTCP     []string
	//
	// per path config
	//
	// TODO refactor
	//
	// The current implementation is tricky. A small refactor is welcome
	// but can wait a little more. Multipath unit tests need to do a
	// better job as well.
	//
	// Following some tips in order to multipath work properly:
	//
	//   1. On backend annotation parsing, do not filter
	//      mapper.GetBackendConfig/Str() slice, instead populate
	//      haproxy type even with empty data. Backend.NeedACL() need
	//      to know all paths in order to work properly. Filter out
	//      empty/disabled items in the template.
	//
	//   2. Every config array added here, need also to be added
	//      in Backend.NeedACL() - haproxy/types/backend.go.
	//      Template uses this func in order to know if a config
	//      has two or more paths, and so need to be configured with ACL.
	//
	AuthHTTP      []*BackendConfigAuth
	Cors          []*BackendConfigCors
	HSTS          []*BackendConfigHSTS
	MaxBodySize   []*BackendConfigInt
	RewriteURL    []*BackendConfigStr
	SSLRedirect   []*BackendConfigBool
	WAF           []*BackendConfigWAF
	WhitelistHTTP []*BackendConfigWhitelist
}

// Endpoint ...
type Endpoint struct {
	Enabled   bool
	Label     string
	IP        string
	Name      string
	Port      int
	Target    string
	TargetRef string
	Weight    int
}

// BlueGreenConfig ...
type BlueGreenConfig struct {
	CookieName string
	HeaderName string
}

// BackendPaths ...
type BackendPaths struct {
	Items []*BackendPath
}

// BackendPath ...
type BackendPath struct {
	ID       string
	Hostname string
	Hostpath string
	Path     string
}

// BackendConfigBool ...
type BackendConfigBool struct {
	Paths  BackendPaths
	Config bool
}

// BackendConfigInt ...
type BackendConfigInt struct {
	Paths  BackendPaths
	Config int64
}

// BackendConfigStr ...
type BackendConfigStr struct {
	Paths  BackendPaths
	Config string
}

// BackendConfigAuth ...
type BackendConfigAuth struct {
	Paths        BackendPaths
	UserlistName string
	Realm        string
}

// BackendConfigCors ...
type BackendConfigCors struct {
	Paths  BackendPaths
	Config Cors
}

// BackendConfigWAF defines Web Application Firewall Configurations
type BackendConfigWAF struct {
	Paths  BackendPaths
	Config WAF
}

// BackendConfigHSTS ...
type BackendConfigHSTS struct {
	Paths  BackendPaths
	Config HSTS
}

// BackendConfigWhitelist ...
type BackendConfigWhitelist struct {
	Paths  BackendPaths
	Config []string
}

// AgentCheck ...
type AgentCheck struct {
	Addr     string
	Interval string
	Port     int
	Send     string
}

// DynBackendConfig ...
type DynBackendConfig struct {
	BlockSize    int
	DynUpdate    bool
	MinFreeSlots int
}

// HealthCheck ...
type HealthCheck struct {
	Addr      string
	FallCount int
	Interval  string
	Port      int
	RiseCount int
	URI       string
}

// BackendLimit ...
type BackendLimit struct {
	Connections int
	RPS         int
	Whitelist   []string
}

// OAuthConfig ...
type OAuthConfig struct {
	Impl        string
	BackendName string
	URIPrefix   string
	Headers     map[string]string
}

// ServerConfig ...
type ServerConfig struct {
	CAFilename    string
	CAHash        string
	Ciphers       string // TLS up to 1.2
	CipherSuites  string // TLS 1.3
	CRLFilename   string
	CRLHash       string
	CrtFilename   string
	CrtHash       string
	InitialWeight int
	MaxConn       int
	MaxQueue      int
	Options       string
	Protocol      string
	Secure        bool
	SendProxy     string
}

// BackendTimeoutConfig ...
type BackendTimeoutConfig struct {
	Connect     string
	HTTPRequest string
	KeepAlive   string
	Queue       string
	Server      string
	ServerFin   string
	Tunnel      string
}

// BackendTLSConfig ...
type BackendTLSConfig struct {
	AddCertHeader bool
	HasTLSAuth    bool
}

// UserlistConfig ...
type UserlistConfig struct {
	Name  string
	Realm string
}

// Cookie ...
type Cookie struct {
	Name     string
	Dynamic  bool
	Shared   bool
	Strategy string
}

// Cors ...
type Cors struct {
	Enabled bool
	//
	AllowCredentials bool
	AllowHeaders     string
	AllowMethods     string
	AllowOrigin      string
	ExposeHeaders    string
	MaxAge           int
}

// HSTS ...
type HSTS struct {
	Enabled    bool
	MaxAge     int
	Subdomains bool
	Preload    bool
}

// WAF Defines the WAF Config structure for the Backend
type WAF struct {
	// Mode defines On or DetectionOnly
	Mode string
	// Which WAF Module should be used
	Module string
}

// Userlist ...
type Userlist struct {
	Name  string
	Users []User
}

// User ...
type User struct {
	Name      string
	Passwd    string
	Encrypted bool
}
