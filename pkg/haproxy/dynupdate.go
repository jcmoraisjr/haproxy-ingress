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
	socket string
	cmd    func(socket string, commands ...string) ([]string, error)
}

type backendPair struct {
	old *hatypes.Backend
	cur *hatypes.Backend
}

type epPair struct {
	old *hatypes.Endpoint
	cur *hatypes.Endpoint
}

func (i *instance) newDynUpdater(socket string) *dynUpdater {
	return &dynUpdater{
		logger: i.logger,
		socket: socket,
		cmd:    utils.HAProxyCommand,
	}
}

func (d *dynUpdater) dynUpdate(old, cur Config) bool {
	if old == nil || cur == nil {
		return false
	}
	oldConfig := old.(*config)
	curConfig := cur.(*config)
	if oldConfig == nil || curConfig == nil {
		return false
	}

	// check equality of everything but backends
	oldConfigCopy := *oldConfig
	oldConfigCopy.backends = curConfig.backends
	if !reflect.DeepEqual(&oldConfigCopy, curConfig) {
		return false
	}

	// map backends of old and new config together
	// return false if len or names doesn't match
	if len(curConfig.backends) != len(curConfig.backends) {
		return false
	}
	backends := make(map[string]*backendPair, len(oldConfig.backends))
	for _, backend := range oldConfig.backends {
		backends[backend.ID] = &backendPair{old: backend}
	}
	for _, backend := range curConfig.backends {
		back, found := backends[backend.ID]
		if !found {
			return false
		}
		back.cur = backend
	}

	// try to dynamically update every single backend
	// true if deep equals or sucessfully updated
	// false if cannot be dynamically updated or update failed
	for _, pair := range backends {
		if !d.updateBackendPair(pair) {
			return false
		}
	}

	return true
}

func (d *dynUpdater) updateBackendPair(pair *backendPair) bool {
	oldBack := pair.old
	curBack := pair.cur

	// check equality of everything but endpoints
	oldBackCopy := *oldBack
	oldBackCopy.Endpoints = curBack.Endpoints
	if !reflect.DeepEqual(&oldBackCopy, curBack) {
		return false
	}

	// can decrease endpoints, cannot increase
	if len(oldBack.Endpoints) < len(curBack.Endpoints) {
		return false
	}

	// map endpoints of old and new config together
	endpoints := make(map[string]*epPair, len(oldBack.Endpoints))
	var empty []string
	for _, endpoint := range oldBack.Endpoints {
		if endpoint.Enabled {
			endpoints[endpoint.Target] = &epPair{old: endpoint}
		} else {
			empty = append(empty, endpoint.Name)
		}
	}

	// current endpoint names will be overwritten from its
	// old counterpart, this will save some socket calls
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
	for _, pair := range endpoints {
		if pair.cur == nil {
			if !d.execDisableEndpoint(curBack.ID, pair.old) {
				return false
			}
			empty = append(empty, pair.old.Name)
		} else if !d.updateEndpointPair(curBack.ID, pair) {
			return false
		}
	}
	sort.Strings(empty)
	for i := range added {
		added[i].Name = empty[i]
		if !d.execEnableEndpoint(curBack.ID, added[i]) {
			return false
		}
	}

	return true
}

func (d *dynUpdater) updateEndpointPair(backname string, pair *epPair) bool {
	if reflect.DeepEqual(pair.old, pair.cur) {
		return true
	}
	return d.execEnableEndpoint(backname, pair.cur)
}

func (d *dynUpdater) execDisableEndpoint(backname string, ep *hatypes.Endpoint) bool {
	server := fmt.Sprintf("set server %s/%s ", backname, ep.Name)
	cmd := []string{
		server + "state maint",
		server + "addr 127.0.0.1 port 1023",
		server + "weight 0",
	}
	msg, err := d.cmd(d.socket, cmd...)
	if err != nil {
		d.logger.Error("error disabling endpoint %s/%s: %v", backname, ep.Name, err)
		return false
	}
	for _, m := range msg {
		d.logger.Info(m)
	}
	d.logger.InfoV(2, "disabled endpoint %s on backend/server %s/%s", ep.Target, backname, ep.Name)
	return true
}

func (d *dynUpdater) execEnableEndpoint(backname string, ep *hatypes.Endpoint) bool {
	stateReady := map[bool]string{true: "ready", false: "drain"}
	server := fmt.Sprintf("set server %s/%s ", backname, ep.Name)
	cmd := []string{
		server + "addr " + ep.IP + " port " + strconv.Itoa(ep.Port),
		server + "state " + stateReady[ep.Weight > 0],
		server + "weight " + strconv.Itoa(ep.Weight),
	}
	msg, err := d.cmd(d.socket, cmd...)
	if err != nil {
		d.logger.Error("error adding endpoint %s/%s: %v", backname, ep.Name, err)
		return false
	}
	for _, m := range msg {
		d.logger.Info(m)
	}
	d.logger.InfoV(2, "added endpoint %s on backend/server %s/%s", ep.Target, backname, ep.Name)
	return true
}
