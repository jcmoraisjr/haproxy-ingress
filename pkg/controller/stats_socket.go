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

package controller

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"reflect"
	"sort"
)

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
	err := utils.SendToSocket(statsSocket,
		fmt.Sprintf("set server %s/%s state maint\n", backendName, backendServerName))
	if err != nil {
		glog.Warningln("failed socket command srv remove")
		return false
	}
	return true
}

// add Ingress Endpoint to a backend in a specific server slot
func addEndpoint(statsSocket, backendName, backendServerName, address, port string, draining bool) bool {
	weight := 100
	state := "ready"
	if draining {
		weight = 0
		state = "drain"
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
	return true
}

func setEndpointDrainState(statsSocket, backendName, backendServerName string, draining bool) bool {
	weight := 100
	state := "ready"
	if draining {
		weight = 0
		state = "drain"
	}
	err := utils.SendToSocket(statsSocket, fmt.Sprintf("set server %s/%s weight %d\nset server %s/%s state %s\n",
		backendName, backendServerName, weight, backendName, backendServerName, state))
	if err != nil {
		glog.Warningln("failed socket command srv weight")
		return false
	}
	return true
}

// populate template variables and optionally issue socket commands to reconfigure haproxy without reloading
func reconfigureBackends(currentConfig, updatedConfig *types.ControllerConfig) bool {
	reloadRequired := true
	reconfigureEmptySlots := false

	if currentConfig != nil {
		// store backend lists for retrieval
		curBackends := currentConfig.Backends
		updBackends := updatedConfig.Backends
		// store BackendSlots for retrieval
		curBackendSlots := currentConfig.BackendSlots

		// exclude backend lists and slots from reflect.DeepEqual
		updatedConfig.Backends = []*ingress.Backend{}
		currentConfig.Backends = updatedConfig.Backends
		currentConfig.BackendSlots = updatedConfig.BackendSlots

		// check equality of everything but backends and Ingress status
		// Ingress status can change on us, but that change is meaningless for our purposes, so copy that (and the ResourceVersion which will update
		// along with it) from the new to the old config to exclude it from the comparison.
		if len(currentConfig.Servers) > 0 && len(currentConfig.Servers[0].Locations) > 0 && len(updatedConfig.Servers) > 0 && len(updatedConfig.Servers[0].Locations) > 0 {
			currentConfig.Servers[0].Locations[0].Ingress.ObjectMeta.ResourceVersion = updatedConfig.Servers[0].Locations[0].Ingress.ObjectMeta.ResourceVersion
			currentConfig.Servers[0].Locations[0].Ingress.Status.LoadBalancer.Ingress = updatedConfig.Servers[0].Locations[0].Ingress.Status.LoadBalancer.Ingress
		}
		if !reflect.DeepEqual(updatedConfig, currentConfig) {
			reconfigureEmptySlots = true
		} else {
			// set up maps
			curBackendsMap, curKeys := ingressBackendsRemap(curBackends)
			updBackendsMap, updKeys := ingressBackendsRemap(updBackends)

			if !reflect.DeepEqual(curKeys, updKeys) {
				// backend names or number of backends is different
				reconfigureEmptySlots = true
			} else if updatedConfig.Cfg.DrainSupport && onlyDrainStateChanged(curBackendsMap, updBackendsMap) {
				// Everything is the same except for the server's weight, so we can use the stats socket to update all of the server weights.
				reloadRequired = false
				updatedConfig.BackendSlots = curBackendSlots
				for _, backendName := range curKeys {
					backendSlots := updatedConfig.BackendSlots[backendName]
					updEndpoints := ingressEndpointsRemap(updBackendsMap[backendName].Endpoints)
					for name, endpoint := range updEndpoints {
						if backendSlots.FullSlots[name].BackendEndpoint.Draining != endpoint.Draining {
							backendServerName := backendSlots.FullSlots[name].BackendServerName
							backendSlots.FullSlots[name] = types.HAProxyBackendSlot{
								BackendServerName: backendServerName,
								BackendEndpoint:   endpoint,
							}
							reloadRequired = reloadRequired || !setEndpointDrainState(currentConfig.Cfg.StatsSocket, backendName, backendServerName, endpoint.Draining)
						}
					}
				}
			} else if updatedConfig.Cfg.DynamicScaling {
				// same names and nr of backends, we can modify existing HAProxyBackendSlots, should not need reloading
				reloadRequired = false
				updatedConfig.BackendSlots = curBackendSlots
				for _, backendName := range curKeys {
					updLen := len(updBackendsMap[backendName].Endpoints)
					totalSlots := len(curBackendSlots[backendName].EmptySlots) + len(curBackendSlots[backendName].FullSlots)
					if updLen > totalSlots || updLen < (totalSlots-updatedConfig.Cfg.BackendServerSlotsIncrement) {
						// need to resize number of empty slots by BackendServerSlotsIncrement amount
						reconfigureEmptySlots = true
					} else {
						// everything fits so reconfigure endpoints without reloading
						// do it with maps posing as sets
						curEndpoints := ingressEndpointsRemap(curBackendsMap[backendName].Endpoints)
						updEndpoints := ingressEndpointsRemap(updBackendsMap[backendName].Endpoints)

						toRemoveEndpoints := endpointsSubtract(curEndpoints, updEndpoints)
						toAddEndpoints := endpointsSubtract(updEndpoints, curEndpoints)

						// check for new/removed entries in this backend, issue socket commands
						backendSlots := updatedConfig.BackendSlots[backendName]
						// remove endpoints
						for k := range toRemoveEndpoints {
							reloadRequired = reloadRequired || !removeEndpoint(currentConfig.Cfg.StatsSocket, backendName, backendSlots.FullSlots[k].BackendServerName)
							backendSlots.EmptySlots = append(backendSlots.EmptySlots, backendSlots.FullSlots[k].BackendServerName)
							delete(backendSlots.FullSlots, k)
						}
						sort.Strings(backendSlots.EmptySlots)
						// add endpoints
						for k, endpoint := range toAddEndpoints {
							// rearrange slots
							backendSlots.FullSlots[k] = types.HAProxyBackendSlot{
								BackendServerName: backendSlots.EmptySlots[0],
								BackendEndpoint:   endpoint,
							}
							backendSlots.EmptySlots = backendSlots.EmptySlots[1:]
							reloadRequired = reloadRequired || !addEndpoint(currentConfig.Cfg.StatsSocket, backendName, backendSlots.FullSlots[k].BackendServerName, endpoint.Address, endpoint.Port, endpoint.Draining)
						}
						updatedConfig.BackendSlots[backendName] = backendSlots
					}
				}
			} else {
				reconfigureEmptySlots = true
			}
		}
		// restore backend lists
		currentConfig.Backends = curBackends
		updatedConfig.Backends = updBackends
		// restore backend slots
		currentConfig.BackendSlots = curBackendSlots
	}

	if currentConfig == nil || reconfigureEmptySlots {
		fillBackendServerSlots(updatedConfig)
		reloadRequired = true
	}

	return reloadRequired
}

// Determines whether or not the endpoints lists in curBackendsMap and updBackendsMap differ only in state of Draining.
// NOTE: This function assumes that the keys in the incoming maps are identical
func onlyDrainStateChanged(curBackendsMap, updBackendsMap map[string]*ingress.Backend) bool {
	for name, curBackend := range curBackendsMap {
		// If the backend structs differ in something other than endpoints, then we can abort early
		tmpEndpoints := curBackend.Endpoints
		curBackend.Endpoints = updBackendsMap[name].Endpoints
		backendsEqual := reflect.DeepEqual(curBackend, updBackendsMap[name])
		curBackend.Endpoints = tmpEndpoints
		if !backendsEqual {
			return false
		}

		// If the endpoints length changed, then we can abort early
		if len(curBackend.Endpoints) != len(updBackendsMap[name].Endpoints) {
			return false
		}

		updEndpoints := ingressEndpointsRemap(updBackendsMap[name].Endpoints)
		for i, e := range curBackend.Endpoints {
			key := fmt.Sprintf("%s:%s", e.Address, e.Port)
			if ue, ok := updEndpoints[key]; ok {
				ce := curBackend.Endpoints[i]
				ce.Draining = ue.Draining
				// On delete, Kind can be updated from 'Pod' to empty string. This also causes a bump in ResourceVersion.
				// We want to ignore these changes for our comparison.
				tmpTarget := *ce.Target
				tmpTarget.Kind = ue.Target.Kind
				tmpTarget.ResourceVersion = ue.Target.ResourceVersion
				ce.Target = &tmpTarget
				if !reflect.DeepEqual(&ce, ue) {
					return false
				}
			} else {
				return false
			}
		}
	}
	return true
}

// fill-out backends with available endpoints, add empty slots if required
func fillBackendServerSlots(updatedConfig *types.ControllerConfig) {
	updBackendsMap, updKeys := ingressBackendsRemap(updatedConfig.Backends)
	updatedConfig.BackendSlots = map[string]types.HAProxyBackendSlots{}

	for _, backendName := range updKeys {
		newBackend := types.HAProxyBackendSlots{}
		newBackend.FullSlots = map[string]types.HAProxyBackendSlot{}
		if updatedConfig.Cfg.DynamicScaling {
			for i, endpoint := range updBackendsMap[backendName].Endpoints {
				curEndpoint := endpoint
				newBackend.FullSlots[fmt.Sprintf("%s:%s", endpoint.Address, endpoint.Port)] = types.HAProxyBackendSlot{
					BackendServerName: fmt.Sprintf("server%04d", i),
					BackendEndpoint:   &curEndpoint,
				}
			}
			// add up to BackendServerSlotsIncrement empty slots
			fullSlotCnt := len(newBackend.FullSlots)
			extraSlotCnt := (int(fullSlotCnt/updatedConfig.Cfg.BackendServerSlotsIncrement)+1)*updatedConfig.Cfg.BackendServerSlotsIncrement - fullSlotCnt
			for i := 0; i < extraSlotCnt; i++ {
				newBackend.EmptySlots = append(newBackend.EmptySlots, fmt.Sprintf("server%04d", i+fullSlotCnt))
			}
		} else {
			// use addr:port as BackendServerName, don't generate empty slots
			for _, endpoint := range updBackendsMap[backendName].Endpoints {
				curEndpoint := endpoint
				target := fmt.Sprintf("%s:%s", endpoint.Address, endpoint.Port)
				newBackend.FullSlots[target] = types.HAProxyBackendSlot{
					BackendServerName: target,
					BackendEndpoint:   &curEndpoint,
				}
			}
		}
		updatedConfig.BackendSlots[backendName] = newBackend
	}
}
