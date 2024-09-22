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

import (
	"container/list"
	"net"
	"time"
)

// AcmeData ...
type AcmeData struct {
	storages    *AcmeStorages
	Emails      string
	Endpoint    string
	Expiring    time.Duration
	TermsAgreed bool
}

// AcmeStorages ...
type AcmeStorages struct {
	items, itemsAdd, itemsDel map[string]*AcmeCerts
}

// AcmeCerts ...
type AcmeCerts struct {
	certs          map[string]struct{}
	preferredChain string
}

// Acme ...
type Acme struct {
	Enabled bool
	Prefix  string
	Shared  bool
	Socket  string
}

// Global ...
type Global struct {
	Bind                    GlobalBindConfig
	Procs                   ProcsConfig
	Syslog                  SyslogConfig
	MaxConn                 int
	Timeout                 TimeoutConfig
	SSL                     SSLConfig
	DNS                     DNSConfig
	ModSecurity             ModSecurityConfig
	Cookie                  CookieConfig
	DrainSupport            DrainConfig
	Acme                    Acme
	ForwardFor              string
	LoadServerState         bool
	AdminSocket             string
	LocalFSPrefix           string
	External                ExternalConfig
	Healthz                 HealthzConfig
	Master                  MasterConfig
	MatchOrder              []MatchType
	Prometheus              PromConfig
	Security                SecurityConfig
	Stats                   StatsConfig
	CloseSessionsDuration   time.Duration
	TimeoutStopDuration     time.Duration
	StrictHost              bool
	UseHTX                  bool
	DefaultBackendRedir     string
	DefaultBackendRedirCode int
	NoRedirects             []string
	CustomConfig            []string
	CustomDefaults          []string
	CustomFrontendEarly     []string
	CustomFrontendLate      []string
	CustomProxy             map[string][]string
	CustomHTTPLuaResponses  []HTTPResponse
	CustomHTTPHAResponses   []HTTPResponse
	CustomSections          []string
	CustomTCP               []string
}

// GlobalBindConfig ...
type GlobalBindConfig struct {
	AcceptProxy      bool
	HTTPBind         string
	HTTPSBind        string
	TCPBindIP        string
	FrontingBind     string
	FrontingSockID   int
	FrontingUseProto bool
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
	Endpoint string
	Format   string
	Length   int
	Tag      string
	//
	AuthLogFormat  string
	HTTPLogFormat  string
	HTTPSLogFormat string
	TCPLogFormat   string
}

// TimeoutConfig ...
type TimeoutConfig struct {
	BackendTimeoutConfig
	Client    string
	ClientFin string
	Stats     string
	Stop      string
}

// SSLConfig ...
type SSLConfig struct {
	ALPN                string
	BackendCiphers      string
	BackendCipherSuites string
	Ciphers             string // TLS up to 1.2
	CipherSuites        string // TLS 1.3
	DHParam             DHParamConfig
	Engine              string
	HeadersPrefix       string
	ModeAsync           bool
	Options             string
	RedirectCode        int
	SSLRedirect         bool
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
	Args      []string
	UseCoraza bool
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

// ExternalConfig ...
type ExternalConfig struct {
	HasLua     bool
	IsExternal bool
}

// HealthzConfig ...
type HealthzConfig struct {
	BindIP string
	Port   int
}

// MasterConfig ...
type MasterConfig struct {
	ExitOnFailure    bool
	IsMasterWorker   bool
	WorkerMaxReloads int
}

// PromConfig ...
type PromConfig struct {
	BindIP string
	Port   int
}

// SecurityConfig ...
type SecurityConfig struct {
	Groupname string
	UseChroot bool
	Username  string
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
	// Backend
	Connect string
	Server  string
	// SPOE
	Hello      string
	Idle       string
	Processing string
}

// HTTPResponse ...
type HTTPResponse struct {
	Name         string
	Headers      []HTTPHeader
	Body         []string
	StatusCode   int
	StatusReason string
}

// HTTPHeader ...
type HTTPHeader struct {
	Name  string
	Value string
}

// TCPServices ...
type TCPServices struct {
	items   map[int]*TCPServicePort
	changed bool
}

// TCPServicePort ...
type TCPServicePort struct {
	port         int
	hosts        map[string]*TCPServiceHost
	defaultHost  *TCPServiceHost
	CustomConfig []string
	LogFormat    string
	ProxyProt    bool
	TLS          map[string]*TCPServiceTLSConfig
	//
	SNIMap *HostsMap
}

// TCPServiceHost ...
type TCPServiceHost struct {
	hostname string
	Backend  BackendID
}

type TCPServiceTLSConfig struct {
	TLSConfig
	Hostname string
}

// CAVerify ...
type CAVerify string

// ...
const (
	CAVerifySkipCheck CAVerify = "skip-check"
	CAVerifyOptional  CAVerify = "optional"
	CAVerifyAlways    CAVerify = "always"
)

// TLSConfig ...
type TLSConfig struct {
	ALPN          string
	CAFilename    string
	CAHash        string
	CAVerify      CAVerify
	Ciphers       string
	CipherSuites  string
	CRLFilename   string
	CRLHash       string
	Options       string
	TLSCommonName string
	TLSFilename   string
	TLSHash       string
	TLSNotAfter   time.Time
}

// TCPBackends ...
type TCPBackends struct {
	items, itemsAdd, itemsDel map[int]*TCPBackend
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
	Filename    string
	CAFilename  string
	CRLFilename string
}

// TCPProxyProt ...
type TCPProxyProt struct {
	Decode        bool
	EncodeVersion string
}

// HostsMapEntry ...
type HostsMapEntry struct {
	hostname string
	path     string
	match    MatchType
	order    int
	_upper   *list.Element
	_elem    *list.Element
	Key      string
	Value    string
}

type hostsMapMatchFile struct {
	entries  []*HostsMapEntry
	match    MatchType
	priority bool
}

// MatchFile ...
type MatchFile struct {
	matchFile *hostsMapMatchFile
	filename  string
	first     bool
	last      bool
}

// HostsMap ...
type HostsMap struct {
	basename   string
	matchOrder []MatchType
	matchFiles []*MatchFile
	rawhosts   map[string][]*HostsMapEntry
	rawfiles   map[MatchType]*hostsMapMatchFile
}

// HostsMaps ...
type HostsMaps struct {
	Items      []*HostsMap
	matchOrder []MatchType
}

// FrontendMaps ...
type FrontendMaps struct {
	HTTPHostMap  *HostsMap
	HTTPSHostMap *HostsMap
	//
	RedirFromRootMap  *HostsMap
	RedirRootSSLMap   *HostsMap
	RedirFromMap      *HostsMap
	RedirToMap        *HostsMap
	SSLPassthroughMap *HostsMap
	VarNamespaceMap   *HostsMap
	//
	TLSAuthList           *HostsMap
	TLSNeedCrtList        *HostsMap
	TLSInvalidCrtPagesMap *HostsMap
	TLSMissingCrtPagesMap *HostsMap
	//
	DefaultHostMap *HostsMap
}

// AuthProxy ...
type AuthProxy struct {
	BindList   []*AuthProxyBind
	Name       string
	RangeEnd   int
	RangeStart int
}

// AuthProxyBind ...
type AuthProxyBind struct {
	AuthBackendName string
	Backend         BackendID
	LocalPort       int
	SocketID        int
}

// Frontend ...
type Frontend struct {
	changed     bool
	Maps        *FrontendMaps
	Name        string
	BindName    string
	BindSocket  string
	BindID      int
	AcceptProxy bool
	AuthProxy   AuthProxy
	//
	DefaultCrtFile string
	DefaultCrtHash string
	CrtListFile    string
	//
	RedirectFromCode int
	RedirectToCode   int
}

// DefaultHost ...
const DefaultHost = "<default>"

// Hosts ...
type Hosts struct {
	items, itemsAdd, itemsDel map[string]*Host
	//
	sslPassthroughCount int
	hasCommit           bool
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
	Redirect               HostRedirectConfig
	HTTPPassthroughBackend string
	RootRedirect           string
	TLS                    HostTLSConfig
	VarNamespace           bool
	//
	hosts          *Hosts
	sslPassthrough bool
}

// MatchType ...
type MatchType string

// ...
const (
	MatchBegin  = MatchType("begin")
	MatchExact  = MatchType("exact")
	MatchPrefix = MatchType("prefix")
	MatchRegex  = MatchType("regex")
)

// DefaultMatchOrder ...
var DefaultMatchOrder = []MatchType{MatchExact, MatchPrefix, MatchBegin, MatchRegex}

// PathLink is a unique identifier of a request
// configuration. Several request based configurations
// uses this identifier to distinguish if an acl should
// or should not be applied.
type PathLink struct {
	hostname string
	path     string
	match    MatchType
}

// HostPath ...
//
// Root context `/` path is a catch all and will be used if no other path
// matches the request on this host. If a root context path is not
// declared, the default backend will be used. If the default backend is
// empty, a default 404 page generated by HAProxy will be used.
type HostPath struct {
	order   int
	Path    string
	Link    PathLink
	Match   MatchType
	Backend HostBackend
	RedirTo string
}

// HostBackend ...
type HostBackend struct {
	ID        string
	Namespace string
	Name      string
	Port      string
	ModeTCP   *bool
}

// HostAliasConfig ...
type HostAliasConfig struct {
	AliasName  string
	AliasRegex string
}

// HostRedirectConfig ...
type HostRedirectConfig struct {
	RedirectHost      string
	RedirectHostRegex string
}

// HostTLSConfig ...
type HostTLSConfig struct {
	TLSConfig
	CAErrorPage    string
	UseDefaultCrt  bool
	FollowRedirect bool
}

// EndpointNaming ...
type EndpointNaming int

// ...
const (
	EpSequence EndpointNaming = iota
	EpIPPort
	EpTargetRef
)

// EndpointCookieStrategy ...
type EndpointCookieStrategy int

// ...
const (
	EpCookieName EndpointCookieStrategy = iota
	EpCookiePodUID
)

// Backends ...
type Backends struct {
	items, itemsAdd, itemsDel map[string]*Backend
	//
	authBackends   map[string]*Backend
	shards         []map[string]*Backend
	changedShards  map[int]bool
	DefaultBackend *Backend
}

// BackendID ...
type BackendID struct {
	id        string
	Namespace string
	Name      string
	Port      string
}

// Backend ...
type Backend struct {
	//
	// core config
	//
	// IMPLEMENT
	// use BackendID
	hash64    uint64
	shard     int
	ID        string
	Namespace string
	Name      string
	Port      string
	DNSPort   string
	SourceIPs []net.IP
	Endpoints []*Endpoint
	EpNaming  EndpointNaming
	//
	// Paths
	//
	Paths               []*BackendPath
	PathsMap            *HostsMap
	PathsDefaultHostMap *HostsMap
	pathConfig          map[string]*BackendPathConfig
	//
	// per backend config
	//
	AgentCheck       AgentCheck
	AllowedIPTCP     AccessConfig
	BalanceAlgorithm string
	BlueGreen        BlueGreenConfig
	Cookie           Cookie
	CustomConfig     []string
	DeniedIPTCP      AccessConfig
	Dynamic          DynBackendConfig
	EpCookieStrategy EndpointCookieStrategy
	Headers          []*BackendHeader
	HealthCheck      HealthCheck
	Limit            BackendLimit
	ModeTCP          bool
	Resolver         string
	Server           ServerConfig
	Timeout          BackendTimeoutConfig
	TLS              BackendTLSConfig
}

// Endpoint ...
type Endpoint struct {
	Enabled     bool
	Label       string
	IP          string
	Name        string
	Port        int
	SourceIP    string
	Target      string
	TargetRef   string
	Weight      int
	CookieValue string
	PUID        int32 // Proxy Unique ID, referenced as "id" in haproxy server lines
}

// BlueGreenConfig ...
type BlueGreenConfig struct {
	CookieName string
	HeaderName string
}

// BackendPathConfig ...
type BackendPathConfig struct {
	items []*BackendPathItem
}

// BackendPathItem ...
type BackendPathItem struct {
	paths  []*BackendPath
	config interface{}
}

// HostResolver ...
type HostResolver interface {
	UseTLS() bool
}

// BackendPath ...
type BackendPath struct {
	//
	// core fields, filter out new fields in `Backend.createPathConfig()`
	//
	ID   string
	Link PathLink
	Host HostResolver
	//
	// config fields
	//
	AllowedIPHTTP AccessConfig
	AuthHTTP      AuthHTTP
	AuthExternal  AuthExternal
	Cors          Cors
	DeniedIPHTTP  AccessConfig
	HSTS          HSTS
	MaxBodySize   int64
	RewriteURL    string
	SSLRedirect   bool
	WAF           WAF
}

// BackendHeader ...
type BackendHeader struct {
	Name  string
	Value string
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

// AccessConfig ...
type AccessConfig struct {
	Rule         []string
	Exception    []string
	SourceHeader string
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
	SNI           string
	VerifyHost    string
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
	AddCertHeader    bool
	FingerprintLower bool
	HasTLSAuth       bool
	Sha2Bits         int
}

// UserlistConfig ...
type UserlistConfig struct {
	Name  string
	Realm string
}

// Cookie ...
type Cookie struct {
	Name     string
	Domain   string
	Dynamic  bool
	Preserve bool
	SameSite bool
	Shared   bool
	Strategy string
	Keywords string
}

// AuthExternal ...
type AuthExternal struct {
	AllowedPath     string
	AlwaysDeny      bool
	AuthBackendName string
	AuthPath        string
	HeadersFail     []string
	HeadersRequest  []string
	HeadersSucceed  []string
	HeadersVars     map[string]string
	Method          string
	RedirectOnFail  string
}

// AuthHTTP ...
type AuthHTTP struct {
	UserlistName string
	Realm        string
}

// Cors ...
type Cors struct {
	Enabled bool
	//
	AllowCredentials bool
	AllowHeaders     string
	AllowMethods     string
	AllowOrigin      []string
	AllowOriginRegex []string
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

// Userlists ...
type Userlists struct {
	items, itemsAdd, itemsDel map[string]*Userlist
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
