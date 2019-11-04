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

package annotations

import (
	"fmt"
	"regexp"
	"strings"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func (c *updater) buildGlobalBind(d *globalData) {
	d.global.Bind.AcceptProxy = d.mapper.Get(ingtypes.GlobalUseProxyProtocol).Bool()
	d.global.Bind.HTTPBindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrHTTP).Value
	d.global.Bind.HTTPSBindIP = d.global.Bind.HTTPBindIP
	d.global.Bind.TCPBindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrTCP).Value
	d.global.Bind.HTTPPort = d.mapper.Get(ingtypes.GlobalHTTPPort).Int()
	d.global.Bind.HTTPSPort = d.mapper.Get(ingtypes.GlobalHTTPSPort).Int()
}

func (c *updater) buildGlobalProc(d *globalData) {
	balance := d.mapper.Get(ingtypes.GlobalNbprocBalance).Int()
	if balance < 1 {
		c.logger.Warn("invalid value of nbproc-balance configmap option (%v), using 1", balance)
		balance = 1
	}
	if balance > 1 {
		// need to visit (at least) statistics and healthz bindings as well
		// as admin socket before using more than one balance backend
		c.logger.Warn("nbproc-balance configmap option (%v) greater than 1 is not yet supported, using 1", balance)
		balance = 1
	}
	ssl := d.mapper.Get(ingtypes.GlobalNbprocSSL).Int()
	if ssl < 0 {
		c.logger.Warn("invalid value of nbproc-ssl configmap option (%v), using 0", ssl)
		ssl = 0
	}
	if ssl > 0 {
		c.logger.Warn("v08 controller does not support nbproc-ssl, using 0")
		ssl = 0
	}
	procs := balance + ssl
	threads := d.mapper.Get(ingtypes.GlobalNbthread).Int()
	if threads < 1 {
		c.logger.Warn("invalid value of nbthread configmap option (%v), using 1", threads)
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
	d.global.Procs.Nbproc = procs
	d.global.Procs.Nbthread = threads
	d.global.Procs.NbprocBalance = balance
	d.global.Procs.NbprocSSL = ssl
	d.global.Procs.BindprocBalance = bindprocBalance
	d.global.Procs.BindprocSSL = bindprocSSL
	d.global.Procs.CPUMap = cpumap
}

func (c *updater) buildGlobalStats(d *globalData) {
	d.global.Stats.AcceptProxy = d.mapper.Get(ingtypes.GlobalStatsProxyProtocol).Bool()
	d.global.Stats.Auth = d.mapper.Get(ingtypes.GlobalStatsAuth).Value
	d.global.Stats.BindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrStats).Value
	d.global.Stats.Port = d.mapper.Get(ingtypes.GlobalStatsPort).Int()
	if tlsSecret := d.mapper.Get(ingtypes.GlobalStatsSSLCert).Value; tlsSecret != "" {
		if tls, err := c.cache.GetTLSSecretPath("", tlsSecret); err == nil {
			d.global.Stats.TLSFilename = tls.Filename
			d.global.Stats.TLSHash = tls.SHA1Hash
		} else {
			c.logger.Warn("ignore TLS config on stats endpoint: %v", err)
		}
	}
}

func (c *updater) buildGlobalSyslog(d *globalData) {
	d.global.Syslog.Endpoint = d.mapper.Get(ingtypes.GlobalSyslogEndpoint).Value
	d.global.Syslog.Format = d.mapper.Get(ingtypes.GlobalSyslogFormat).Value
	d.global.Syslog.HTTPLogFormat = d.mapper.Get(ingtypes.GlobalHTTPLogFormat).Value
	d.global.Syslog.HTTPSLogFormat = d.mapper.Get(ingtypes.GlobalHTTPSLogFormat).Value
	d.global.Syslog.Length = d.mapper.Get(ingtypes.GlobalSyslogLength).Int()
	d.global.Syslog.Tag = d.mapper.Get(ingtypes.GlobalSyslogTag).Value
	d.global.Syslog.TCPLogFormat = d.mapper.Get(ingtypes.GlobalTCPLogFormat).Value
}

func (c *updater) buildGlobalTimeout(d *globalData) {
	d.global.Timeout.Client = c.validateTime(d.mapper.Get(ingtypes.HostTimeoutClient))
	d.global.Timeout.ClientFin = c.validateTime(d.mapper.Get(ingtypes.HostTimeoutClientFin))
	d.global.Timeout.Connect = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutConnect))
	d.global.Timeout.HTTPRequest = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutHTTPRequest))
	d.global.Timeout.KeepAlive = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutKeepAlive))
	d.global.Timeout.Queue = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutQueue))
	d.global.Timeout.Server = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutServer))
	d.global.Timeout.ServerFin = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutServerFin))
	d.global.Timeout.Stop = c.validateTime(d.mapper.Get(ingtypes.GlobalTimeoutStop))
	d.global.Timeout.Tunnel = c.validateTime(d.mapper.Get(ingtypes.BackTimeoutTunnel))
}

func (c *updater) buildGlobalSSL(d *globalData) {
	ssl := &d.global.SSL
	ssl.Ciphers = d.mapper.Get(ingtypes.GlobalSSLCiphers).Value
	ssl.CipherSuites = d.mapper.Get(ingtypes.GlobalSSLCipherSuites).Value
	ssl.Options = d.mapper.Get(ingtypes.GlobalSSLOptions).Value
	ssl.BackendCiphers = d.mapper.Get(ingtypes.BackSSLCiphersBackend).Value
	ssl.BackendCipherSuites = d.mapper.Get(ingtypes.BackSSLCipherSuitesBackend).Value
	ssl.BackendOptions = d.mapper.Get(ingtypes.BackSSLOptionsBackend).Value
	if sslDHParam := d.mapper.Get(ingtypes.GlobalSSLDHParam).Value; sslDHParam != "" {
		if dhFile, err := c.cache.GetDHSecretPath("", sslDHParam); err == nil {
			ssl.DHParam.Filename = dhFile.Filename
		} else {
			c.logger.Error("error reading DH params: %v", err)
		}
	}
	ssl.DHParam.DefaultMaxSize = d.mapper.Get(ingtypes.GlobalSSLDHDefaultMaxSize).Int()
	ssl.Engine = d.mapper.Get(ingtypes.GlobalSSLEngine).Value
	ssl.ModeAsync = d.mapper.Get(ingtypes.GlobalSSLModeAsync).Bool()
	ssl.HeadersPrefix = d.mapper.Get(ingtypes.GlobalSSLHeadersPrefix).Value
}

func (c *updater) buildGlobalHealthz(d *globalData) {
	d.global.Healthz.BindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrHealthz).Value
	d.global.Healthz.Port = d.mapper.Get(ingtypes.GlobalHealthzPort).Int()
}

func (c *updater) buildGlobalHTTPStoHTTP(d *globalData) {
	port := d.mapper.Get(ingtypes.GlobalFrontingProxyPort).Int()
	if port == 0 {
		port = d.mapper.Get(ingtypes.GlobalHTTPStoHTTPPort).Int()
	}
	if port == 0 {
		return
	}
	// TODO Change all `ToHTTP` naming to `FrontingProxy`
	d.global.Bind.ToHTTPBindIP = d.mapper.Get(ingtypes.GlobalBindIPAddrHTTP).Value
	d.global.Bind.ToHTTPPort = port
	// Socket ID should be a high number to avoid colision
	// between the same socket ID from distinct frontends
	// TODO match socket and frontend ID in the backend
	d.global.Bind.ToHTTPSocketID = 10011
}

func (c *updater) buildGlobalModSecurity(d *globalData) {
	d.global.ModSecurity.Endpoints = utils.Split(d.mapper.Get(ingtypes.GlobalModsecurityEndpoints).Value, ",")
	d.global.ModSecurity.Timeout.Hello = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutHello))
	d.global.ModSecurity.Timeout.Idle = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutIdle))
	d.global.ModSecurity.Timeout.Processing = c.validateTime(d.mapper.Get(ingtypes.GlobalModsecurityTimeoutProcessing))
}

func (c *updater) buildGlobalDNS(d *globalData) {
	resolvers := d.mapper.Get(ingtypes.GlobalDNSResolvers).Value
	if resolvers == "" {
		return
	}
	payloadSize := d.mapper.Get(ingtypes.GlobalDNSAcceptedPayloadSize).Int()
	holdObsolete := c.validateTime(d.mapper.Get(ingtypes.GlobalDNSHoldObsolete))
	holdValid := c.validateTime(d.mapper.Get(ingtypes.GlobalDNSHoldValid))
	timeoutRetry := c.validateTime(d.mapper.Get(ingtypes.GlobalDNSTimeoutRetry))
	for _, resolver := range utils.LineToSlice(resolvers) {
		if resolver == "" {
			continue
		}
		resolverData := strings.Split(resolver, "=")
		if len(resolverData) != 2 {
			c.logger.Warn("ignoring misconfigured resolver: %s", resolver)
			continue
		}
		dnsResolver := &hatypes.DNSResolver{
			Name:                resolverData[0],
			AcceptedPayloadSize: payloadSize,
			HoldObsolete:        holdObsolete,
			HoldValid:           holdValid,
			TimeoutRetry:        timeoutRetry,
		}
		var i int
		for _, ns := range strings.Split(resolverData[1], ",") {
			if ns == "" {
				continue
			}
			if strings.Index(ns, ":") < 0 {
				// missing port number
				ns += ":53"
			}
			i++
			dnsResolver.Nameservers = append(dnsResolver.Nameservers, &hatypes.DNSNameserver{
				Name:     fmt.Sprintf("ns%02d", i),
				Endpoint: ns,
			})
		}
		d.global.DNS.Resolvers = append(d.global.DNS.Resolvers, dnsResolver)
	}
	d.global.DNS.ClusterDomain = d.mapper.Get(ingtypes.GlobalDNSClusterDomain).Value
}

var (
	forwardRegex = regexp.MustCompile(`^(add|update|ignore|ifmissing)$`)
)

func (c *updater) buildGlobalForwardFor(d *globalData) {
	if forwardFor := d.mapper.Get(ingtypes.GlobalForwardfor).Value; forwardRegex.MatchString(forwardFor) {
		d.global.ForwardFor = forwardFor
	} else {
		if forwardFor != "" {
			c.logger.Warn("Invalid forwardfor value option on configmap: '%s'. Using 'add' instead", forwardFor)
		}
		d.global.ForwardFor = "add"
	}
}

func (c *updater) buildGlobalCustomConfig(d *globalData) {
	d.global.CustomConfig = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigGlobal).Value)
	d.global.CustomDefaults = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigDefaults).Value)
	d.global.CustomFrontend = utils.LineToSlice(d.mapper.Get(ingtypes.GlobalConfigFrontend).Value)
}
