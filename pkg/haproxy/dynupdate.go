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

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type dynUpdater struct {
	logger types.Logger
	old    *config
	cur    *config
	socket string
	cmd    func(socket string, commands ...string) ([]string, error)
	cmdCnt int
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
	var old, cur *config
	if i.oldConfig != nil {
		old = i.oldConfig.(*config)
	}
	if i.curConfig != nil {
		cur = i.curConfig.(*config)
	}
	return &dynUpdater{
		logger: i.logger,
		old:    old,
		cur:    cur,
		socket: i.curConfig.Global().StatsSocket,
		cmd:    utils.HAProxyCommand,
	}
}

func (d *dynUpdater) update() bool {
	updated := d.checkConfigPair()
	if !updated {
		// Need to reload, time to adjust empty slots according to config
		d.alignSlots()
	}
	return updated
}

func (d *dynUpdater) checkConfigPair() bool {
	oldConfig := d.old
	curConfig := d.cur
	if oldConfig == nil || curConfig == nil {
		return false
	}

	// check equality of everything but backends
	oldConfigCopy := *oldConfig
	oldConfigCopy.backends = curConfig.backends
	oldConfigCopy.defaultBackend = curConfig.defaultBackend
	if !reflect.DeepEqual(&oldConfigCopy, curConfig) {
		var diff []string
		if !reflect.DeepEqual(oldConfig.global, curConfig.global) {
			diff = append(diff, "global")
		}
		if !reflect.DeepEqual(oldConfig.tcpbackends, curConfig.tcpbackends) {
			diff = append(diff, "tcp-services")
		}
		if !reflect.DeepEqual(oldConfig.hosts, curConfig.hosts) {
			diff = append(diff, "hosts")
		}
		if !reflect.DeepEqual(oldConfig.userlists, curConfig.userlists) {
			diff = append(diff, "userlists")
		}
		d.logger.InfoV(2, "diff outside backends - %v", diff)
		return false
	}

	// map backends of old and new config together
	// return false if len or names doesn't match
	if len(curConfig.backends) != len(curConfig.backends) {
		d.logger.InfoV(2, "added or removed backend(s)")
		return false
	}
	backends := make(map[string]*backendPair, len(oldConfig.backends))
	for _, backend := range oldConfig.backends {
		backends[backend.ID] = &backendPair{old: backend}
	}
	for _, backend := range curConfig.backends {
		back, found := backends[backend.ID]
		if !found {
			d.logger.InfoV(2, "removed backend %s", backend.ID)
			return false
		}
		back.cur = backend
	}

	// try to dynamically update every single backend
	// true if deep equals or sucessfully updated
	// false if cannot be dynamically updated or update failed
	for _, pair := range backends {
		if !d.checkBackendPair(pair) {
			return false
		}
	}

	return true
}

func (d *dynUpdater) checkBackendPair(pair *backendPair) bool {
	oldBack := pair.old
	curBack := pair.cur

	// check equality of everything but endpoints
	oldBackCopy := *oldBack
	oldBackCopy.Dynamic = curBack.Dynamic
	oldBackCopy.Endpoints = curBack.Endpoints
	if !reflect.DeepEqual(&oldBackCopy, curBack) {
		d.logger.InfoV(2, "diff outside endpoints")
		return false
	}

	// most of the backends are equal, save some proc stopping here if deep equals
	if reflect.DeepEqual(oldBack.Endpoints, curBack.Endpoints) {
		return true
	}

	// can decrease endpoints, cannot increase
	if len(oldBack.Endpoints) < len(curBack.Endpoints) {
		d.logger.InfoV(2, "added endpoints")
		return false
	}

	// map endpoints of old and new config together
	endpoints := make(map[string]*epPair, len(oldBack.Endpoints))
	targets := make([]string, 0, len(oldBack.Endpoints))
	var empty []string
	for _, endpoint := range oldBack.Endpoints {
		if endpoint.Enabled {
			endpoints[endpoint.Target] = &epPair{old: endpoint}
			targets = append(targets, endpoint.Target)
		} else {
			empty = append(empty, endpoint.Name)
		}
	}

	// From this point we cannot simply `return false` because endpoint.Name
	// is being updated, need to be updated until the end, and endpoints slice
	// need to be sorted
	updated := true

	// reuse the backend/server which has the same target endpoint, if found,
	// this will save some socket calls and will not mess endpoint metrics
	var added []*hatypes.Endpoint
	for _, endpoint := range curBack.Endpoints {
		if pair, found := endpoints[endpoint.Target]; found {
			endpoint.Name = pair.old.Name
			pair.cur = endpoint
		} else {
			added = append(added, endpoint)
		}
	}

	// try to dynamically remove/update/add endpoints
	// targets used here only to have predictable results
	sort.Strings(targets)
	for _, target := range targets {
		pair := endpoints[target]
		if pair.cur == nil {
			if updated && !d.execDisableEndpoint(curBack.ID, pair.old) {
				updated = false
			}
			empty = append(empty, pair.old.Name)
		} else if updated && !d.checkEndpointPair(curBack.ID, pair) {
			updated = false
		}
	}
	for i := range added {
		// reusing empty slots from oldBack
		added[i].Name = empty[i]
		if updated && !d.execEnableEndpoint(curBack.ID, nil, added[i]) {
			updated = false
		}
	}

	// copy remaining empty slots from oldBack to curBack, so it can be used in a future update
	for i := len(added); i < len(empty); i++ {
		curBack.AddEmptyEndpoint().Name = empty[i]
	}
	curBack.SortEndpoints()

	return updated
}

func (d *dynUpdater) checkEndpointPair(backname string, pair *epPair) bool {
	if reflect.DeepEqual(pair.old, pair.cur) {
		return true
	}
	return d.execEnableEndpoint(backname, pair.old, pair.cur)
}

func (d *dynUpdater) alignSlots() {
	if d.cur == nil {
		return
	}
	for _, back := range d.cur.backends {
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
	msg, err := d.execCommand(cmd)
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
	msg, err := d.execCommand(cmd)
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

func (d *dynUpdater) execCommand(cmd []string) ([]string, error) {
	msg, err := d.cmd(d.socket, cmd...)
	d.cmdCnt = d.cmdCnt + len(cmd)
	return msg, err
}
