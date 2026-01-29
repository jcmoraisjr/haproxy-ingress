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
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/socket"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type dynUpdater struct {
	logger  types.Logger
	config  *config
	hatmpl  *template.Config
	socket  socket.HAProxySocket
	cmdCnt  int
	metrics types.Metrics
}

type hostPair struct {
	old *hatypes.Host
	cur *hatypes.Host
}

type backendPair struct {
	old *hatypes.Backend
	cur *hatypes.Backend
}

type epPair struct {
	old *hatypes.Endpoint
	cur *hatypes.Endpoint
}

func (i *instance) newDynUpdater() *dynUpdater {
	return &dynUpdater{
		logger:  i.logger,
		config:  i.config.(*config),
		hatmpl:  i.haproxyTmpl,
		socket:  i.conns.DynUpdate(),
		metrics: i.metrics,
	}
}

func (d *dynUpdater) update() bool {
	updated := d.config.hasCommittedData() && d.checkConfigChange()
	if !updated {
		// Need to reload, time to adjust empty slots according to config
		d.alignSlots()
	}
	return updated
}

// checkConfigChange defines if dynamic update was successfully applied.
// The updated host and backend lists are fully verified even if a restart
// should be made in order to leave haproxy as update as possible if a
// reload fails.
func (d *dynUpdater) checkConfigChange() bool {
	// TODO use two steps update and perform full dynamic update only if the reload failed.

	var diff []string
	if d.config.globalOld != nil && !reflect.DeepEqual(d.config.globalOld, d.config.global) {
		diff = append(diff, "global")
	}
	if d.config.tcpbackends.Changed() {
		diff = append(diff, "tcp-services (configmap)")
	}
	if d.config.tcpservices.Changed() {
		diff = append(diff, "tcp-services")
	}
	if d.config.frontends.Changed() {
		diff = append(diff, "frontends")
	}
	if d.config.userlists.Changed() {
		diff = append(diff, "userlists")
	}
	for _, f := range d.config.frontends.Items() {
		if !d.frontendUpdated(f) {
			diff = append(diff, fmt.Sprintf("hosts (%s)", f.Name))
		}
	}
	if !d.backendUpdated() {
		diff = append(diff, "backends")
	}
	if len(diff) > 0 {
		d.logger.InfoV(2, "need to reload due to config changes: %v", diff)
		return false
	}
	return true
}

func (d *dynUpdater) frontendUpdated(f *hatypes.Frontend) bool {
	updated := true

	hosts := make(map[string]*hostPair, len(f.HostsDel()))
	for _, host := range f.HostsDel() {
		hosts[host.Hostname] = &hostPair{old: host}
	}
	for _, host := range f.HostsAdd() {
		id := host.Hostname
		h, found := hosts[id]
		if !found {
			d.logger.InfoV(2, "added host '%s'", id)
			updated = false
		} else {
			h.cur = host
		}
	}

	for _, pair := range hosts {
		if pair.cur == nil {
			d.logger.InfoV(2, "removed host '%s'", pair.old.Hostname)
			updated = false
		} else if !d.checkHostPair(pair) {
			updated = false
		}
	}

	return updated
}

func (d *dynUpdater) backendUpdated() bool {
	updated := true

	// group reusable backends together
	// return false on new backend which cannot be dynamically created
	backends := make(map[string]*backendPair, len(d.config.backends.ItemsDel()))
	for _, backend := range d.config.backends.ItemsDel() {
		backends[backend.BackendID().String()] = &backendPair{old: backend}
	}
	for _, backend := range d.config.backends.ItemsAdd() {
		id := backend.BackendID().String()
		back, found := backends[id]
		if !found {
			d.logger.InfoV(2, "added backend '%s'", id)
			updated = false
		} else {
			back.cur = backend
		}
	}

	// try to dynamically update every single backend
	// true if deep equals or successfully updated
	// false if cannot be dynamically updated or update failed
	for _, pair := range backends {
		if pair.cur != nil && !d.checkBackendPair(pair) {
			updated = false
		}
	}

	return updated
}

func (d *dynUpdater) checkHostPair(pair *hostPair) bool {
	oldHost := pair.old
	curHost := pair.cur

	updated := true

	// check equality of everything but server certificate
	oldHostCopy := *oldHost
	oldHostCopy.TLS.TLSCommonName = curHost.TLS.TLSCommonName
	oldHostCopy.TLS.TLSHash = curHost.TLS.TLSHash
	oldHostCopy.TLS.TLSNotAfter = curHost.TLS.TLSNotAfter
	if !oldHostCopy.Equals(curHost) {
		d.logger.InfoV(2, "diff outside server certificate of host '%s'", curHost.Hostname)
		updated = false
	}

	if curHost.TLS.HasTLS() && oldHost.TLS.TLSHash != curHost.TLS.TLSHash &&
		oldHost.TLS.TLSFilename == curHost.TLS.TLSFilename &&
		!d.execUpdateCert(curHost.Hostname, curHost.TLS.TLSFilename) {
		updated = false
	}

	return updated
}

func (d *dynUpdater) checkBackendPair(pair *backendPair) bool {
	oldBack := pair.old
	curBack := pair.cur

	// Track if dynamic update was successfully applied.
	// Socket updates will continue to be applied even if updated
	// is false, so haproxy will stay as updated as possible even
	// if a reload fail
	updated := true

	// check equality of everything but endpoints
	oldBackCopy := *oldBack
	oldBackCopy.Endpoints = curBack.Endpoints
	if !oldBackCopy.Equals(curBack) {
		d.logger.InfoV(2, "diff outside endpoints of backend '%s'", curBack.ID)
		updated = false
	}

	// can decrease endpoints, cannot increase on classic dynamic scaling
	if curBack.Dynamic.DynScaling == hatypes.DynScalingSlots && len(oldBack.Endpoints) < len(curBack.Endpoints) {
		d.logger.InfoV(2, "added endpoints on backend '%s'", curBack.ID)
		// cannot continue -- missing empty slots in the backend
		return false
	}

	// Resolver == update via DNS discovery
	if curBack.Resolver != "" {
		if updated {
			// DNS based updates finishes prematurely. Ensure the ep
			// list size of the new one is at least as big as the old one.
			for i := len(curBack.Endpoints); i < len(oldBack.Endpoints); i++ {
				curBack.AddEmptyEndpoint()
			}
		}
		return updated
	}

	switch curBack.Dynamic.DynScaling {
	case hatypes.DynScalingAdd:
		updated = d.dynamicallyAddRemoveServers(pair) && updated
	case hatypes.DynScalingSlots:
		updated = d.dynamicallySyncSlots(pair) && updated
	default:
		// TODO check if endpoints are the same and only the order differ
		if updated && !reflect.DeepEqual(oldBack.Endpoints, curBack.Endpoints) {
			d.logger.InfoV(2, "backend '%s' changed and its dynamic update is 'false'", curBack.ID)
			return false
		}
	}
	return updated
}

func (d *dynUpdater) dynamicallySyncSlots(pair *backendPair) bool {
	oldBack := pair.old
	curBack := pair.cur
	updated := true

	// map endpoints of old and new config together
	endpoints := make(map[string]*epPair, len(oldBack.Endpoints))
	targets := make([]string, 0, len(oldBack.Endpoints))
	var empty []*hatypes.Endpoint
	for _, endpoint := range oldBack.Endpoints {
		if endpoint.Enabled {
			endpoints[endpoint.Target] = &epPair{old: endpoint}
			targets = append(targets, endpoint.Target)
		} else {
			empty = append(empty, endpoint)
		}
	}

	// reuse the backend/server which has the same target endpoint, if found,
	// this will save some socket calls and will not mess endpoint metrics
	var added []*hatypes.Endpoint
	for _, endpoint := range curBack.Endpoints {
		if pair, found := endpoints[endpoint.Target]; found {
			pair.cur = endpoint
			pair.cur.Name = pair.old.Name
		} else {
			added = append(added, endpoint)
		}
	}

	// Try to dynamically remove/update/add endpoints.
	// Targets being used here only to have predictable results (tests).
	// Endpoint.Label != "" means use-server of blue/green config, need reload
	sort.Strings(targets)
	for _, target := range targets {
		pair := endpoints[target]
		if pair.cur == nil && len(added) > 0 {
			pair.cur = added[0]
			pair.cur.Name = pair.old.Name
			added = added[1:]
		}
		if pair.cur == nil {
			if !d.execDisableEndpoint(curBack.ID, pair.old) || pair.old.Label != "" {
				updated = false
			}
			empty = append(empty, pair.old)
		} else if !d.checkEndpointPair(curBack, pair) {
			updated = false
		}
	}
	for i := range added {
		// reusing empty slots from oldBack
		added[i].Name = empty[i].Name
		if curBack.Cookie.Preserve && added[i].CookieValue != empty[i].CookieValue {
			// if cookie doesn't match here and preserving the value is
			// important, don't even enable the endpoint before reloading
			updated = false
		} else if !d.execEnableEndpoint(curBack.ID, nil, added[i]) || added[i].Label != "" {
			updated = false
		}
	}

	// copy remaining empty slots from oldBack to curBack, so it can be used in a future update
	for i := len(added); i < len(empty); i++ {
		curBack.AddEmptyEndpoint().Name = empty[i].Name
	}

	return updated
}

func (d *dynUpdater) dynamicallyAddRemoveServers(pair *backendPair) bool {
	oldBack := pair.old
	curBack := pair.cur
	updated := true

	// group endpoints by name
	endpoints := make(map[string]*epPair, len(curBack.Endpoints))
	for _, endpoint := range oldBack.Endpoints {
		endpoints[endpoint.Name] = &epPair{old: endpoint}
	}
	for _, endpoint := range curBack.Endpoints {
		if eppair, found := endpoints[endpoint.Name]; !found {
			endpoints[endpoint.Name] = &epPair{cur: endpoint}
		} else {
			eppair.cur = endpoint
		}
	}

	// creating a predictable list of endpoint names, not only for unit tests,
	// but also as a way to have the same API calls being done in the same order.
	epnames := make([]string, 0, len(endpoints))
	for epname := range endpoints {
		epnames = append(epnames, epname)
	}
	sort.Strings(epnames)

	// iterate the old and cur endpoint pairs, removing the missing and creating the new ones
	for _, epname := range epnames {
		eppair := endpoints[epname]
		switch {
		case eppair.old != nil && eppair.cur != nil:
			if d.checkEndpointPair(curBack, eppair) {
				// either identical or update succeeded, go to the next endpoint
				continue
			}
			// cannot update, trying now to delete + add
			updated = d.execDeleteEndpoint(curBack.ID, eppair.old) && d.execAddEndpoint(curBack, eppair.cur) && updated
		case eppair.old != nil:
			updated = d.execDeleteEndpoint(curBack.ID, eppair.old) && updated
		case eppair.cur != nil:
			updated = d.execAddEndpoint(curBack, eppair.cur) && updated
		}
	}

	return updated
}

func (d *dynUpdater) checkEndpointPair(backend *hatypes.Backend, pair *epPair) bool {
	oldEPCopy := *pair.old
	// SourceIP is lazily updated via FillSourceIPs() after dynupdate run
	// A reload is already scheduled due to backend.SourceIPs changed
	oldEPCopy.SourceIP = pair.cur.SourceIP
	if reflect.DeepEqual(&oldEPCopy, pair.cur) {
		return true
	}
	if backend.Cookie.Preserve && pair.old.CookieValue != pair.cur.CookieValue {
		// if cookie doesn't match here and preserving the value is
		// important, don't even enable the endpoint before reloading
		return false
	}
	updated := d.execEnableEndpoint(backend.ID, pair.old, pair.cur)
	if !updated || pair.old.Label != "" || pair.cur.Label != "" {
		return false
	}
	return true
}

func (d *dynUpdater) alignSlots() {
	backends := d.config.Backends()
	for _, back := range backends.Items() {
		if back.Dynamic.DynScaling != hatypes.DynScalingSlots {
			// no need to add empty slots if won't dynamically update them
			continue
		}
		minFreeSlots := back.Dynamic.MinFreeSlots
		blockSize := back.Dynamic.BlockSize
		if blockSize < 1 {
			blockSize = 1
		}
		var newFreeSlots int
		changed := false
		if minFreeSlots == 0 && len(back.Endpoints) == 0 {
			newFreeSlots = blockSize
		} else {
			totalFreeSlots := 0
			for _, ep := range back.Endpoints {
				if ep.IsEmpty() {
					totalFreeSlots++
				}
			}
			for i := totalFreeSlots; i < minFreeSlots; i++ {
				back.AddEmptyEndpoint()
				changed = true
			}
			// * []endpoints == group of blocks
			// * block == group of slots
			// * slot == a single server
			// newFreeSlots := blockSize - (1 <= <size-of-last-block> <= blockSize)
			newFreeSlots = blockSize - (((len(back.Endpoints) + blockSize - 1) % blockSize) + 1)
		}
		for i := 0; i < newFreeSlots; i++ {
			back.AddEmptyEndpoint()
			changed = true
		}
		if changed {
			// backends from the Items() map are read-only and their changes might not be
			// reflected in the final configuration. Currently only sharded backends have
			// this behavior but this can be expanded to another scenarios in the future,
			// so this should be properly handled by the model.
			//
			// TODO move responsibility to know that a backend was changed to the model.
			backends.BackendChanged(back)
		}
	}
}

var readFile = os.ReadFile

func (d *dynUpdater) execUpdateCert(hostname, filename string) bool {
	// TODO read from the internal storage
	payload, err := readFile(filename)
	if err != nil {
		d.logger.Error("error reading certificate file for %s: %v", hostname, err)
		return false
	}
	// TODO removing an empty line between crt and key, runtime api didn't like it.
	// Remove this work around after the factoring of the ssl storage.
	payloadStr := strings.ReplaceAll(string(payload), "\n\n", "\n")
	cmd := []string{
		fmt.Sprintf("set ssl cert %s <<\n%s\n", filename, payloadStr),
		fmt.Sprintf("commit ssl cert %s", filename),
	}
	msg, err := d.execCommand(d.metrics.HAProxySetSSLCertResponseTime, cmd)
	if err != nil {
		d.logger.Error("error updating certificate for %s: %v", hostname, err)
		return false
	}
	for _, m := range msg {
		if m != "" {
			outmsg := strings.ReplaceAll(strings.TrimRight(m, "\n"), "\n", " \\\\ ")
			d.logger.InfoV(2, "response from server: %s", outmsg)
		}
	}
	if !cmdResponseOK(cmdCommitCrt, msg[1]) {
		d.logger.Warn("cannot update certificate for %s", hostname)
		return false
	}
	d.logger.Info("certificate updated for %s", hostname)
	return true
}

//
// Here starts the exec<...>Endpoint family, a higher level façade to do what needs
// to be done on a single step, eventually orchestrating more than one API call.
//

func (d *dynUpdater) execDisableEndpoint(backname string, ep *hatypes.Endpoint) bool {
	if !d.execDisableServer(backname, ep) {
		return false
	}
	d.logger.InfoV(2, "disabled endpoint '%s' weight '%d' on backend/server '%s/%s'", ep.Target, ep.Weight, backname, ep.Name)
	return true
}

func (d *dynUpdater) execEnableEndpoint(backname string, oldEP, curEP *hatypes.Endpoint) bool {
	if !d.execSetAddrServer(backname, curEP) || !d.execSetWeightServer(backname, curEP) || !d.execEnableServer(backname, curEP) {
		return false
	}
	event := "updated"
	if oldEP == nil {
		event = "added"
	}
	d.logger.InfoV(2, "%s endpoint '%s' weight '%d' on backend/server '%s/%s'", event, curEP.Target, curEP.Weight, backname, curEP.Name)
	return true
}

func (d *dynUpdater) execAddEndpoint(backend *hatypes.Backend, ep *hatypes.Endpoint) bool {
	backname := backend.ID
	if !d.execAddServer(backend, ep) {
		// it should be disabled already, so just remove, and if it
		// fails due to the missing maintenance mode, we're messing
		// something so better to return and ask for a reload.
		if !d.execDeleteServer(backname, ep) {
			return false
		}
		if !d.execAddServer(backend, ep) {
			return false
		}
	}
	if !d.execEnableServer(backname, ep) {
		return false
	}
	d.logger.InfoV(2, "registered new endpoint '%s' weight '%d' on backend/server '%s/%s'", ep.Target, ep.Weight, backname, ep.Name)
	return true
}

func (d *dynUpdater) execDeleteEndpoint(backname string, curEP *hatypes.Endpoint) bool {
	if !d.execDisableServer(backname, curEP) {
		return false
	}
	state := "deleted"
	if !d.execDeleteServer(backname, curEP) {
		// trying to delete, and it should be left in maintenance/disabled mode due to
		// existing connections, which is fine. a reload will remove it, and we'll try
		// to delete again in case we need this name in the future and before a reload.
		state = "disabled"
	}
	d.logger.InfoV(2, "%s endpoint '%s' weight '%d' backend/server '%s/%s'", state, curEP.Target, curEP.Weight, backname, curEP.Name)
	return true
}

//
// Here starts the exec<...>Server family, a lower level abstraction that makes one API call at a time.
//

func (d *dynUpdater) execAddServer(backend *hatypes.Backend, ep *hatypes.Endpoint) bool {
	// TODO this isn't called so frequently, but still missing some benchmark since out hatmpl is really big.
	// regarding p1 and p2 below, see template/funcmap.go, "map" func, having the syntax expected by all template definitions
	cmd, err := d.hatmpl.WriteTemplate("server", map[string]any{"p1": backend, "p2": ep})
	if err != nil {
		// this is a dev error in case it happens, maybe we should panic instead?
		d.logger.Error("error building backend server template: %s", err.Error())
		return false
	}
	return d.execCommandBackendServer(d.metrics.HAProxySetServerResponseTime, backend.Name, ep, "add "+cmd, cmdAddServer)
}

func (d *dynUpdater) execDisableServer(backname string, ep *hatypes.Endpoint) bool {
	cmd := fmt.Sprintf("set server %s/%s state maint", backname, ep.Name)
	return d.execCommandBackendServer(d.metrics.HAProxySetServerResponseTime, backname, ep, cmd, cmdSetServerState)
}

func (d *dynUpdater) execSetAddrServer(backname string, ep *hatypes.Endpoint) bool {
	cmd := fmt.Sprintf("set server %s/%s addr %s port %d", backname, ep.Name, ep.IP, ep.Port)
	return d.execCommandBackendServer(d.metrics.HAProxySetServerResponseTime, backname, ep, cmd, cmdSetServerAddr)
}

func (d *dynUpdater) execSetWeightServer(backname string, ep *hatypes.Endpoint) bool {
	cmd := fmt.Sprintf("set server %s/%s weight %d", backname, ep.Name, ep.Weight)
	return d.execCommandBackendServer(d.metrics.HAProxySetServerResponseTime, backname, ep, cmd, cmdSetServerWeight)
}

func (d *dynUpdater) execEnableServer(backname string, ep *hatypes.Endpoint) bool {
	state := "ready"
	if ep.Weight == 0 {
		state = "drain"
	}
	cmd := fmt.Sprintf("set server %s/%s state %s", backname, ep.Name, state)
	return d.execCommandBackendServer(d.metrics.HAProxySetServerResponseTime, backname, ep, cmd, cmdSetServerState)
}

func (d *dynUpdater) execDeleteServer(backname string, ep *hatypes.Endpoint) bool {
	cmd := fmt.Sprintf("del server %s/%s", backname, ep.Name)
	return d.execCommandBackendServer(d.metrics.HAProxySetServerResponseTime, backname, ep, cmd, cmdDelServer)
}

type cmdClass int

const (
	cmdAddServer cmdClass = iota
	cmdSetServerAddr
	cmdSetServerWeight
	cmdSetServerState
	cmdDelServer
	cmdCommitCrt
)

var backendServerCmdAction = map[cmdClass]string{
	cmdAddServer:       "adding",
	cmdSetServerAddr:   "updating (address)",
	cmdSetServerWeight: "updating (weight)",
	cmdSetServerState:  "updating (state)",
	cmdDelServer:       "deleting",
}

func (d *dynUpdater) execCommandBackendServer(observer func(duration time.Duration), backname string, ep *hatypes.Endpoint, cmd string, cmdcls cmdClass) bool {
	action := backendServerCmdAction[cmdcls]
	if action == "" {
		panic(fmt.Errorf("invalid cmd ID: %d", cmdcls))
	}
	d.logger.InfoV(2, "api call: %s", cmd)
	msgs, err := d.execCommand(observer, []string{cmd})
	if err != nil {
		d.logger.Error("error %s backend server %s/%s: %s", action, backname, ep.Name, err.Error())
		return false
	}
	msg := msgs[0]
	if !cmdResponseOK(cmdcls, msg) {
		if msg == "" {
			msg = "<empty>"
		}
		d.logger.Warn("unrecognized response %s backend server %s/%s: %s", action, backname, ep.Name, msg)
		return false
	}
	if msg == "" {
		d.logger.InfoV(2, "empty response from server")
	} else {
		d.logger.InfoV(2, "response from server: %s", msg)
	}
	return true
}

func (d *dynUpdater) execCommand(observer func(duration time.Duration), cmd []string) ([]string, error) {
	msg, err := d.socket.Send(observer, cmd...)
	d.cmdCnt = d.cmdCnt + len(cmd)
	return msg, err
}

func cmdResponseOK(cmdcls cmdClass, response string) bool {
	switch cmdcls {
	case cmdAddServer:
		return response == "New server registered."
	case cmdSetServerAddr:
		return response == "nothing changed" || strings.HasPrefix(response, "IP changed from ") || strings.HasPrefix(response, "no need to change ")
	case cmdSetServerWeight, cmdSetServerState:
		return response == ""
	case cmdDelServer:
		return response == "Server deleted."
	case cmdCommitCrt:
		return strings.Contains(response, "Success")
	}
	panic(fmt.Errorf("invalid cmd ID: %d", cmdcls))
}
