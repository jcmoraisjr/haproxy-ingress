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
	"k8s.io/ingress/core/pkg/ingress"
	"reflect"
	"sort"
)

// convert a list of ingress backends to a map with backend names as keys
func ingressBackendsRemap(backends []*ingress.Backend) (map[string]*ingress.Backend, []string) {
	backendsMap := map[string]*ingress.Backend{}
	keys := []string{}
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

// populate template variables and optionally issue socket commands to reconfigure haproxy without reloading
func reconfigureBackends(haproxy *HAProxyController, updatedConfig *types.ControllerConfig) {
	haproxy.ReloadRequired = true
	reconfigureEmptySlots := false

	if !updatedConfig.Cfg.DynamicScaling {
		reconfigureEmptySlots = true
	} else {
		if haproxy.CurrentConfig != nil {
			// store backend lists for retrieval
			curBackends := haproxy.CurrentConfig.Backends
			updBackends := updatedConfig.Backends
			// store BackendSlots for retrieval
			curBackendSlots := haproxy.CurrentConfig.BackendSlots

			// exclude backend lists and slots from reflect.DeepEqual
			updatedConfig.Backends = []*ingress.Backend{}
			haproxy.CurrentConfig.Backends = updatedConfig.Backends
			haproxy.CurrentConfig.BackendSlots = updatedConfig.BackendSlots

			// check equality of everything but backends
			if !reflect.DeepEqual(updatedConfig, haproxy.CurrentConfig) {
				reconfigureEmptySlots = true
			} else {
				// set up maps
				curBackendsMap, curKeys := ingressBackendsRemap(curBackends)
				updBackendsMap, updKeys := ingressBackendsRemap(updBackends)

				if !reflect.DeepEqual(curKeys, updKeys) {
					// backend names or number of backends is different
					reconfigureEmptySlots = true
				} else {
					// same names and nr of backends, we can modify existing HAProxyBackendSlots, should not need reloading
					haproxy.ReloadRequired = false
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
								err := utils.SendToSocket(haproxy.CurrentConfig.Cfg.StatsSocket,
									fmt.Sprintf("set server %s/%s state maint\n", backendName, backendSlots.FullSlots[k].BackendServerName))
								if err != nil {
									glog.Warningln("failed socket command srv remove")
									haproxy.ReloadRequired = true
								}
								backendSlots.EmptySlots = append(backendSlots.EmptySlots, backendSlots.FullSlots[k].BackendServerName)
								delete(backendSlots.FullSlots, k)
							}
							sort.Strings(backendSlots.EmptySlots)
							// add endpoints
							for k, endpoint := range toAddEndpoints {
								// rearrange slots
								backendSlots.FullSlots[k] = types.HAProxyBackendSlot{
									//backendSlots.EmptySlots[len(backendSlots.EmptySlots)-1],
									backendSlots.EmptySlots[0],
									endpoint,
								}
								backendSlots.EmptySlots = backendSlots.EmptySlots[1:]

								// send socket commands
								err1 := utils.SendToSocket(haproxy.CurrentConfig.Cfg.StatsSocket,
									fmt.Sprintf("set server %s/%s addr %s port %s\n", backendName, backendSlots.FullSlots[k].BackendServerName, endpoint.Address, endpoint.Port))
								err2 := utils.SendToSocket(haproxy.CurrentConfig.Cfg.StatsSocket,
									fmt.Sprintf("set server %s/%s state ready\n", backendName, backendSlots.FullSlots[k].BackendServerName))
								if err1 != nil || err2 != nil {
									glog.Warningln("failed socket command srv add")
									haproxy.ReloadRequired = true
								}
							}
							updatedConfig.BackendSlots[backendName] = backendSlots
							// reload if any socket commands were unsuccessful
						}
					}
				}
			}
			// restore backend lists
			haproxy.CurrentConfig.Backends = curBackends
			updatedConfig.Backends = updBackends
			// restore backend slots
			haproxy.CurrentConfig.BackendSlots = curBackendSlots
		}
	}

	// fill-out backends with available endpoints, add empty slots if required
	if haproxy.CurrentConfig == nil || reconfigureEmptySlots {
		haproxy.ReloadRequired = true
		updBackendsMap, updKeys := ingressBackendsRemap(updatedConfig.Backends)
		updatedConfig.BackendSlots = map[string]types.HAProxyBackendSlots{}

		for _, backendName := range updKeys {
			newBackend := types.HAProxyBackendSlots{}
			newBackend.FullSlots = map[string]types.HAProxyBackendSlot{}
			for i, endpoint := range updBackendsMap[backendName].Endpoints {
				newBackend.FullSlots[fmt.Sprintf("%s:%s", endpoint.Address, endpoint.Port)] = types.HAProxyBackendSlot{
					fmt.Sprintf("server%04d", i),
					&endpoint,
				}
			}
			if updatedConfig.Cfg.DynamicScaling {
				// add up to BackendServerSlotsIncrement empty slots
				fullSlotCnt := len(newBackend.FullSlots)
				extraSlotCnt := (int(fullSlotCnt/updatedConfig.Cfg.BackendServerSlotsIncrement)+1)*updatedConfig.Cfg.BackendServerSlotsIncrement - fullSlotCnt
				for i := 0; i < extraSlotCnt; i++ {
					newBackend.EmptySlots = append(newBackend.EmptySlots, fmt.Sprintf("server%04d", i+fullSlotCnt))
				}
			}
			updatedConfig.BackendSlots[backendName] = newBackend
		}
	}

	haproxy.CurrentConfig = updatedConfig
}
