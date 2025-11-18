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
	"strconv"
	"strings"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/socket"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type dynUpdater struct {
	logger  types.Logger
	config  *config
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
	// TODO move this check to the host type
	oldHostCopy := *oldHost
	oldHostCopy.TLS.TLSCommonName = curHost.TLS.TLSCommonName
	oldHostCopy.TLS.TLSHash = curHost.TLS.TLSHash
	oldHostCopy.TLS.TLSNotAfter = curHost.TLS.TLSNotAfter
	if !reflect.DeepEqual(&oldHostCopy, curHost) {
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
	// TODO move this check to the backend type
	oldBackCopy := *oldBack
	oldBackCopy.ID = curBack.ID
	oldBackCopy.Dynamic = curBack.Dynamic
	oldBackCopy.Endpoints = curBack.Endpoints
	if !reflect.DeepEqual(&oldBackCopy, curBack) {
		d.logger.InfoV(2, "diff outside endpoints of backend '%s'", curBack.ID)
		updated = false
	}

	// can decrease endpoints, cannot increase
	if len(oldBack.Endpoints) < len(curBack.Endpoints) {
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

	// DynUpdate is disabled, check if differs and quit
	// TODO check if endpoints are the same and only the order differ
	if !curBack.Dynamic.DynUpdate {
		if updated && !reflect.DeepEqual(oldBack.Endpoints, curBack.Endpoints) {
			d.logger.InfoV(2, "backend '%s' changed and its dynamic-scaling is 'false'", curBack.ID)
			return false
		}
		return updated
	}

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
		if !back.Dynamic.DynUpdate {
			// no need to add empty slots if won't dynamically update
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
	if !cmdResponseOK("commit ssl cert", msg[1]) {
		d.logger.Warn("cannot update certificate for %s", hostname)
		return false
	}
	d.logger.Info("certificate updated for %s", hostname)
	return true
}

func (d *dynUpdater) execDisableEndpoint(backname string, ep *hatypes.Endpoint) bool {
	server := fmt.Sprintf("set server %s/%s ", backname, ep.Name)
	cmd := []string{
		server + "state maint",
		server + "addr 127.0.0.1 port 1023",
		server + "weight 0",
	}
	msg, err := d.execCommand(d.metrics.HAProxySetServerResponseTime, cmd)
	if err != nil {
		d.logger.Error("error disabling endpoint %s/%s: %v", backname, ep.Name, err)
		return false
	}
	for _, m := range msg {
		if m != "" {
			if !cmdResponseOK("set server", m) {
				d.logger.Warn("unrecognized response disabling endpoint %s/%s: %s", backname, ep.Name, m)
				return false
			}
			d.logger.InfoV(2, "response from server: %s", m)
		}
	}
	d.logger.InfoV(2, "disabled endpoint '%s' on backend/server '%s/%s'", ep.Target, backname, ep.Name)
	return true
}

func (d *dynUpdater) execEnableEndpoint(backname string, oldEP, curEP *hatypes.Endpoint) bool {
	state := map[bool]string{true: "ready", false: "drain"}[curEP.Weight > 0]
	server := fmt.Sprintf("set server %s/%s ", backname, curEP.Name)
	cmd := []string{
		server + "addr " + curEP.IP + " port " + strconv.Itoa(curEP.Port),
		server + "state " + state,
		server + "weight " + strconv.Itoa(curEP.Weight),
	}
	msg, err := d.execCommand(d.metrics.HAProxySetServerResponseTime, cmd)
	if err != nil {
		d.logger.Error("error adding/updating endpoint %s/%s: %v", backname, curEP.Name, err)
		return false
	}
	for _, m := range msg {
		if m != "" {
			if !cmdResponseOK("set server", m) {
				d.logger.Warn("unrecognized response adding/updating endpoint %s/%s: %s", backname, curEP.Name, m)
				return false
			}
			d.logger.InfoV(2, "response from server: %s", m)
		}
	}
	event := map[bool]string{true: "updated", false: "added"}[oldEP != nil]
	d.logger.InfoV(2, "%s endpoint '%s' weight '%d' state '%s' on backend/server '%s/%s'",
		event, curEP.Target, curEP.Weight, state, backname, curEP.Name)
	return true
}

func (d *dynUpdater) execCommand(observer func(duration time.Duration), cmd []string) ([]string, error) {
	msg, err := d.socket.Send(observer, cmd...)
	d.cmdCnt = d.cmdCnt + len(cmd)
	return msg, err
}

func cmdResponseOK(cmd, response string) bool {
	switch cmd {
	case "set server":
		return response == "" || strings.HasPrefix(response, "IP changed from ") || strings.HasPrefix(response, "no need to change ")
	case "commit ssl cert":
		return strings.Contains(response, "Success")
	default:
		panic(fmt.Errorf("invalid cmd: %s", cmd))
	}
}
