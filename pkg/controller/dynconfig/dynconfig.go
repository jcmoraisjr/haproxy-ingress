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

package dynconfig

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"reflect"
	"sort"
)

const (
	useResolverAnnotation = "ingress.kubernetes.io/haproxy-use-resolver"
)

// DynConfig has configurations used to update a running HAProxy instance
type DynConfig struct {
	currentConfig  *types.ControllerConfig
	updatedConfig  *types.ControllerConfig
	curBackendsMap map[string]*ingress.Backend
	updBackendsMap map[string]*ingress.Backend
	curKeys        []string
	updKeys        []string
	dynamicScaling bool
	statsSocket    string
	slotsUpdated   bool
}

// convert a list of ingress backends to a map with backend names as keys
func ingressBackendsRemap(backends []*ingress.Backend) (map[string]*ingress.Backend, []string) {
	backendsMap := map[string]*ingress.Backend{}
	var keys []string
	for _, ingBackend := range backends {
		backendsMap[ingBackend.Name] = ingBackend
		keys = append(keys, ingBackend.Name)
	}
	sort.Strings(keys)
	return backendsMap, keys
}

// convert a list of endpoints to a map with address:port as keys
func ingressEndpointsRemap(endpoints []ingress.Endpoint) map[string]*ingress.Endpoint {
	endpointMap := map[string]*ingress.Endpoint{}
	for i, e := range endpoints {
		endpointMap[fmt.Sprintf("%s:%s", e.Address, e.Port)] = &endpoints[i]
	}
	return endpointMap
}

// return elements in s1 but not in s2
func endpointsSubtract(s1, s2 map[string]*ingress.Endpoint) map[string]*ingress.Endpoint {
	s3 := map[string]*ingress.Endpoint{}
	for k, v := range s1 {
		_, ok := s2[k]
		if !ok {
			s3[k] = v
		}
	}
	return s3
}

// remove Ingress Endpoint from a backend by disabling a specific server slot
func removeEndpoint(statsSocket, backendName, backendServerName string) bool {
	err1 := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s state maint\n", backendName, backendServerName))
	err2 := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s addr 127.0.0.1 port 81\n", backendName, backendServerName))
	err3 := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s weight 1\n", backendName, backendServerName))
	if err1 != nil || err2 != nil || err3 != nil {
		glog.Warningln("failed socket command srv remove")
		return false
	}
	glog.V(2).Infof("removed endpoint %v from backend %v", backendServerName, backendName)
	return true
}

// add Ingress Endpoint to a backend in a specific server slot
func addEndpoint(statsSocket, backendName, backendServerName, address, port string, weight int) bool {
	var state string
	if weight == 0 {
		state = "drain"
	} else {
		state = "ready"
	}

	err1 := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s addr %s port %s\n", backendName, backendServerName, address, port))
	err2 := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s state %s\n", backendName, backendServerName, state))
	err3 := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s weight %d\n", backendName, backendServerName, weight))
	if err1 != nil || err2 != nil || err3 != nil {
		glog.Warningln("failed socket command srv add")
		return false
	}
	glog.V(2).Infof("added endpoint %v:%v to server %v/%v", address, port, backendName, backendServerName)
	return true
}

func setEndpointWeight(statsSocket, backendName, backendServerName string, weight int) bool {
	var state string
	if weight == 0 {
		state = "drain"
	} else {
		state = "ready"
	}
	err := utils.SendToSocket(statsSocket, fmt.Sprintf("set server %s/%s weight %d\nset server %s/%s state %s\n",
		backendName, backendServerName, weight, backendName, backendServerName, state))
	if err != nil {
		glog.Warningln("failed socket command srv weight")
		return false
	}
	glog.V(2).Infof("updated weight of %v/%v to %v", backendName, backendServerName, weight)
	return true
}

// ConfigBackends populate template variables and optionally issue socket commands to
// reconfigure haproxy without reloading
// Return true if configuration was dynamically applied, otherwise (false) a reload is required
func ConfigBackends(curCfg, updCfg *types.ControllerConfig) bool {
	ubm, uk := ingressBackendsRemap(updCfg.Backends)
	cbm := ubm
	ck := uk
	if curCfg != nil {
		cbm, ck = ingressBackendsRemap(curCfg.Backends)
	}
	d := &DynConfig{
		currentConfig:  curCfg,
		updatedConfig:  updCfg,
		curBackendsMap: cbm,
		updBackendsMap: ubm,
		curKeys:        ck,
		updKeys:        uk,
		dynamicScaling: updCfg.Cfg.DynamicScaling,
		statsSocket:    updCfg.Cfg.StatsSocket,
		slotsUpdated:   false,
	}

	// check if this is the very first update
	if d.currentConfig == nil {
		d.fillBackendServerSlots()
		return false
	}

	// check equality of everything but backends
	currentConfigCopy := *d.currentConfig
	currentConfigCopy.Backends = d.updatedConfig.Backends
	if !d.updatedConfig.Equal(&currentConfigCopy) {
		d.fillBackendServerSlots()
		return false
	}

	// check if the number and name of backends are the same
	if !reflect.DeepEqual(d.curKeys, d.updKeys) {
		d.fillBackendServerSlots()
		return false
	}

	// at this point we have the same names and number of backends, we can modify
	// existing HAProxyBackendSlots, should not need reloading
	if d.dynamicUpdateBackends() {
		return true
	}

	d.fillBackendServerSlots()
	return false
}

// dynamicUpdateBackends tries to update backends using socket, without the need of reloading
// Return true if changing was sucessfully applied, false otherwise
func (d *DynConfig) dynamicUpdateBackends() bool {
	reloadRequired := false
	backendSlots := d.currentConfig.BackendSlots
	d.updatedConfig.BackendSlots = backendSlots
	for _, backendName := range d.curKeys {
		updLen := len(d.updBackendsMap[backendName].Endpoints)
		totalSlots := backendSlots[backendName].TotalSlots
		if updLen > totalSlots {
			// need to resize number of empty slots by SlotsIncrement amount
			reloadRequired = true
			continue
		}
		if _, ok := d.updBackendsMap[backendName].Service.Annotations[useResolverAnnotation]; ok {
			glog.Infof("DNS used for %s\n", backendName)
			continue
		}
		curBackend := d.curBackendsMap[backendName]
		updBackend := d.updBackendsMap[backendName]

		if !reloadRequired {
			// check if everything but endpoints are equal
			updBackendCopy := *updBackend
			updBackendCopy.Endpoints = curBackend.Endpoints
			if !curBackend.Equal(&updBackendCopy) {
				reloadRequired = true
				continue
			}
		}

		// everything fits so try to reconfigure endpoints without reloading
		// do it with maps posing as sets
		curEndpoints := ingressEndpointsRemap(curBackend.Endpoints)
		updEndpoints := ingressEndpointsRemap(updBackend.Endpoints)

		// check for new/updated/removed entries in this backend, issue socket commands
		backendSlots := d.updatedConfig.BackendSlots[backendName]

		// update endpoints
		if !reloadRequired {
			reloadRequired = !d.dynamicUpdateEndpoints(backendName, updEndpoints, backendSlots)
		}

		// remove endpoints
		toRemoveEndpoints := endpointsSubtract(curEndpoints, updEndpoints)
		for k := range toRemoveEndpoints {
			reloadRequired = reloadRequired || !removeEndpoint(d.statsSocket, backendName, backendSlots.FullSlots[k].BackendServerName)
			backendSlots.EmptySlots = append(backendSlots.EmptySlots, backendSlots.FullSlots[k].BackendServerName)
			delete(backendSlots.FullSlots, k)
		}

		// add endpoints only work if using dynamic scaling
		if d.dynamicScaling {
			// add endpoints
			sort.Strings(backendSlots.EmptySlots)
			toAddEndpoints := endpointsSubtract(updEndpoints, curEndpoints)
			for k, endpoint := range toAddEndpoints {
				// rearrange slots
				backendSlots.FullSlots[k] = types.HAProxyBackendSlot{
					BackendServerName: backendSlots.EmptySlots[0],
					BackendEndpoint:   endpoint,
				}
				backendSlots.EmptySlots = backendSlots.EmptySlots[1:]
				reloadRequired = reloadRequired || !addEndpoint(d.statsSocket, backendName, backendSlots.FullSlots[k].BackendServerName, endpoint.Address, endpoint.Port, endpoint.Weight)
			}
			d.updatedConfig.BackendSlots[backendName] = backendSlots
		}
	}
	return !reloadRequired
}

// dynamicUpdateEndpoint tries to update without reload
// Return true if changing was sucessfully applied, false otherwise
func (d *DynConfig) dynamicUpdateEndpoints(backendName string, updEndpoints map[string]*ingress.Endpoint, backendSlots *types.HAProxyBackendSlots) bool {
	for name, updEndpoint := range updEndpoints {
		backendSlot, found := backendSlots.FullSlots[name]
		if !found {
			// new endpoint; if dynamic scaling, continue without invalidate,
			// otherwise need to reload (return false)
			if !d.dynamicScaling {
				return false
			}
			continue
		}
		curEndpoint := backendSlot.BackendEndpoint

		// check if only Weight differs
		updEndpointCopy := *updEndpoint
		updEndpointCopy.Weight = curEndpoint.Weight
		if !curEndpoint.Equal(&updEndpointCopy) {
			return false
		}

		if curEndpoint.Weight != updEndpoint.Weight {
			backendServerName := backendSlots.FullSlots[name].BackendServerName
			backendSlots.FullSlots[name] = types.HAProxyBackendSlot{
				BackendServerName: backendServerName,
				BackendEndpoint:   updEndpoint,
			}
			if !setEndpointWeight(d.statsSocket, backendName, backendServerName, updEndpoint.Weight) {
				return false
			}
		}
	}
	return true
}

// fill-out backends with available endpoints, add empty slots if required
func (d *DynConfig) fillBackendServerSlots() {

	d.updatedConfig.BackendSlots = map[string]*types.HAProxyBackendSlots{}

	for _, backendName := range d.updKeys {
		newBackend := types.HAProxyBackendSlots{}
		newBackend.FullSlots = map[string]types.HAProxyBackendSlot{}

		if resolver, ok := d.updBackendsMap[backendName].Service.Annotations[useResolverAnnotation]; ok {
			// glog.Infof("%s configured resolvers %v\n", backendName, updatedConfig.DNSResolvers)
			if DNSResolver, ok := d.updatedConfig.DNSResolvers[resolver]; ok {
				fullSlotCnt := len(d.updBackendsMap[backendName].Endpoints)
				newBackend.TotalSlots = (int(fullSlotCnt/d.updatedConfig.Cfg.BackendServerSlotsIncrement) + 1) * d.updatedConfig.Cfg.BackendServerSlotsIncrement
				d.updatedConfig.DNSResolvers[resolver] = DNSResolver
				newBackend.UseResolver = resolver
			} else {
				glog.Infof("Backend %s DNSResolver %s not found, not using DNS\n", backendName, resolver)
				newBackend.UseResolver = ""
			}
		}

		if newBackend.UseResolver == "" {
			if d.dynamicScaling {
				for i, endpoint := range d.updBackendsMap[backendName].Endpoints {
					curEndpoint := endpoint
					newBackend.FullSlots[fmt.Sprintf("%s:%s", endpoint.Address, endpoint.Port)] = types.HAProxyBackendSlot{
						BackendServerName: fmt.Sprintf("server%04d", i),
						BackendEndpoint:   &curEndpoint,
					}
				}
				// add up to SlotsIncrement empty slots
				increment := d.updBackendsMap[backendName].SlotsIncrement
				fullSlotCnt := len(newBackend.FullSlots)
				extraSlotCnt := (int(fullSlotCnt/increment)+1)*increment - fullSlotCnt
				for i := 0; i < extraSlotCnt; i++ {
					newBackend.EmptySlots = append(newBackend.EmptySlots, fmt.Sprintf("server%04d", i+fullSlotCnt))
				}
				newBackend.TotalSlots = fullSlotCnt + extraSlotCnt
			} else {
				// use addr:port as BackendServerName, don't generate empty slots
				for _, endpoint := range d.updBackendsMap[backendName].Endpoints {
					curEndpoint := endpoint
					target := fmt.Sprintf("%s:%s", endpoint.Address, endpoint.Port)
					newBackend.FullSlots[target] = types.HAProxyBackendSlot{
						BackendServerName: target,
						BackendEndpoint:   &curEndpoint,
					}
				}
			}
		}
		d.updatedConfig.BackendSlots[backendName] = &newBackend
	}
}
