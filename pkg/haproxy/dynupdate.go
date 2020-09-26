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
	"reflect"
	"sort"
	"strconv"
	"time"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type dynUpdater struct {
	logger  types.Logger
	config  *config
	socket  string
	cmd     func(socket string, observer func(duration time.Duration), commands ...string) ([]string, error)
	cmdCnt  int
	metrics types.Metrics
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
		socket:  i.config.Global().AdminSocket,
		cmd:     utils.HAProxyCommand,
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

func (d *dynUpdater) checkConfigChange() bool {
	// updated defines if dynamic update was successfully applied.
	// The udpated backend list is fully verified even if a restart
	// should be made (updated=false) in order to leave haproxy as
	// update as possible if a reload fails.
	// TODO use two steps update and perform full dynamic update
	//      only if the reload failed.
	updated := true

	var diff []string
	if d.config.globalOld != nil && !reflect.DeepEqual(d.config.globalOld, d.config.global) {
		diff = append(diff, "global")
	}
	if d.config.tcpbackends.Changed() {
		diff = append(diff, "tcp-services")
	}
	if d.config.hosts.Changed() {
		diff = append(diff, "hosts")
	}
	if d.config.userlists.Changed() {
		diff = append(diff, "userlists")
	}
	if len(diff) > 0 {
		d.logger.InfoV(2, "diff outside backends: %v", diff)
		updated = false
	}

	// group reusable backends together
	// return false on new backend which cannot be dynamically created
	backends := make(map[string]*backendPair, len(d.config.backends.ItemsDel()))
	for _, backend := range d.config.backends.ItemsDel() {
		backends[backend.ID] = &backendPair{old: backend}
	}
	for _, backend := range d.config.backends.ItemsAdd() {
		back, found := backends[backend.ID]
		if !found {
			d.logger.InfoV(2, "added backend '%s'", backend.ID)
			updated = false
		} else {
			back.cur = backend
		}
	}

	// try to dynamically update every single backend
	// true if deep equals or sucessfully updated
	// false if cannot be dynamically updated or update failed
	for _, pair := range backends {
		if pair.cur != nil && !d.checkBackendPair(pair) {
			updated = false
		}
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
	curBack.SortEndpoints()

	return updated
}

func (d *dynUpdater) checkEndpointPair(backend *hatypes.Backend, pair *epPair) bool {
	if reflect.DeepEqual(pair.old, pair.cur) {
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
	for _, back := range d.config.Backends().Items() {
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
			}
			// * []endpoints == group of blocks
			// * block == group of slots
			// * slot == a single server
			// newFreeSlots := blockSize - (1 <= <size-of-last-block> <= blockSize)
			newFreeSlots = blockSize - (((len(back.Endpoints) + blockSize - 1) % blockSize) + 1)
		}
		for i := 0; i < newFreeSlots; i++ {
			back.AddEmptyEndpoint()
		}
	}
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
	d.logger.InfoV(2, "disabled endpoint '%s' on backend/server '%s/%s'", ep.Target, backname, ep.Name)
	for _, m := range msg {
		d.logger.InfoV(2, m)
	}
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
	event := map[bool]string{true: "updated", false: "added"}[oldEP != nil]
	d.logger.InfoV(2, "%s endpoint '%s' weight '%d' state '%s' on backend/server '%s/%s'",
		event, curEP.Target, curEP.Weight, state, backname, curEP.Name)
	for _, m := range msg {
		d.logger.InfoV(2, m)
	}
	return true
}

func (d *dynUpdater) execCommand(observer func(duration time.Duration), cmd []string) ([]string, error) {
	msg, err := d.cmd(d.socket, observer, cmd...)
	d.cmdCnt = d.cmdCnt + len(cmd)
	return msg, err
}
