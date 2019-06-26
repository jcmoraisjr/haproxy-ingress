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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func (c *updater) buildGlobalProc(d *globalData) {
	balance := d.config.NbprocBalance
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
	ssl := d.config.NbprocSSL
	if ssl < 0 {
		c.logger.Warn("invalid value of nbproc-ssl configmap option (%v), using 0", ssl)
		ssl = 0
	}
	procs := balance + ssl
	threads := d.config.Nbthread
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

func (c *updater) buildGlobalTimeout(d *globalData) {
	copyHAProxyTime(&d.global.Timeout.Client, d.config.TimeoutClient)
	copyHAProxyTime(&d.global.Timeout.ClientFin, d.config.TimeoutClientFin)
	copyHAProxyTime(&d.global.Timeout.Connect, d.config.TimeoutConnect)
	copyHAProxyTime(&d.global.Timeout.HTTPRequest, d.config.TimeoutHTTPRequest)
	copyHAProxyTime(&d.global.Timeout.KeepAlive, d.config.TimeoutKeepAlive)
	copyHAProxyTime(&d.global.Timeout.Queue, d.config.TimeoutQueue)
	copyHAProxyTime(&d.global.Timeout.Server, d.config.TimeoutServer)
	copyHAProxyTime(&d.global.Timeout.ServerFin, d.config.TimeoutServerFin)
	copyHAProxyTime(&d.global.Timeout.Tunnel, d.config.TimeoutTunnel)
	copyHAProxyTime(&d.global.Timeout.Stop, d.config.TimeoutStop)
}

func (c *updater) buildGlobalSSL(d *globalData) {
	d.global.SSL.Ciphers = d.config.SSLCiphers
	d.global.SSL.Options = d.config.SSLOptions
	if d.config.SSLDHParam != "" {
		if dhFile, err := c.cache.GetDHSecretPath(d.config.SSLDHParam); err == nil {
			d.global.SSL.DHParam.Filename = dhFile.Filename
		} else {
			c.logger.Error("error reading DH params: %v", err)
		}
	}
	d.global.SSL.DHParam.DefaultMaxSize = d.config.SSLDHDefaultMaxSize
	d.global.SSL.Engine = d.config.SSLEngine
	d.global.SSL.ModeAsync = d.config.SSLModeAsync
	d.global.SSL.HeadersPrefix = d.config.SSLHeadersPrefix
}

func (c *updater) buildGlobalModSecurity(d *globalData) {
	d.global.ModSecurity.Endpoints = utils.Split(d.config.ModsecurityEndpoints, ",")
	d.global.ModSecurity.Timeout.Hello = d.config.ModsecurityTimeoutHello
	d.global.ModSecurity.Timeout.Idle = d.config.ModsecurityTimeoutIdle
	d.global.ModSecurity.Timeout.Processing = d.config.ModsecurityTimeoutProcessing
}

var (
	forwardRegex = regexp.MustCompile(`^(add|ignore|ifmissing)$`)
)

func (c *updater) buildGlobalForwardFor(d *globalData) {
	if forwardRegex.MatchString(d.config.Forwardfor) {
		d.global.ForwardFor = d.config.Forwardfor
	} else {
		if d.config.Forwardfor != "" {
			c.logger.Warn("Invalid forwardfor value option on configmap: '%s'. Using 'add' instead", d.config.Forwardfor)
		}
		d.global.ForwardFor = "add"
	}
}

func (c *updater) buildGlobalCustomConfig(d *globalData) {
	if d.config.ConfigGlobal != "" {
		d.global.CustomConfig = strings.Split(strings.TrimRight(d.config.ConfigGlobal, "\n"), "\n")
	}
	if d.config.ConfigGlobals.ConfigDefaults != "" {
		d.global.CustomDefaults = strings.Split(strings.TrimRight(d.config.ConfigGlobals.ConfigDefaults, "\n"), "\n")
	}
}
