/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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

package tracker

import (
	"fmt"
	"sort"
	"strings"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

// NewTracker ...
func NewTracker() convtypes.Tracker {
	return &tracker{}
}

type (
	stringStringMap  map[string]map[string]empty
	stringBackendMap map[string]map[hatypes.BackendID]empty
	backendStringMap map[hatypes.BackendID]map[string]empty
	//
	empty struct{}
)

type tracker struct {
	ingressHostname stringStringMap
	hostnameIngress stringStringMap
	ingressBackend  stringBackendMap
	backendIngress  backendStringMap
	//
	serviceHostname stringStringMap
	hostnameService stringStringMap
	//
	secretHostname stringStringMap
	hostnameSecret stringStringMap
	//
	serviceHostnameMissing stringStringMap
	hostnameServiceMissing stringStringMap
	//
	secretHostnameMissing stringStringMap
	hostnameSecretMissing stringStringMap
}

func (t *tracker) TrackHostname(rtype convtypes.ResourceType, name, hostname string) {
	validName(name)
	switch rtype {
	case convtypes.IngressType:
		addStringTracking(&t.ingressHostname, name, hostname)
		addStringTracking(&t.hostnameIngress, hostname, name)
	case convtypes.ServiceType:
		addStringTracking(&t.serviceHostname, name, hostname)
		addStringTracking(&t.hostnameService, hostname, name)
	case convtypes.SecretType:
		addStringTracking(&t.secretHostname, name, hostname)
		addStringTracking(&t.hostnameSecret, hostname, name)
	default:
		panic(fmt.Errorf("unsupported resource type %d", rtype))
	}
}

func (t *tracker) TrackBackend(rtype convtypes.ResourceType, name string, backendID hatypes.BackendID) {
	validName(name)
	switch rtype {
	case convtypes.IngressType:
		addStringBackendTracking(&t.ingressBackend, name, backendID)
		addBackendStringTracking(&t.backendIngress, backendID, name)
	default:
		panic(fmt.Errorf("unsupported resource type %d", rtype))
	}
}

func (t *tracker) TrackMissingOnHostname(rtype convtypes.ResourceType, name, hostname string) {
	validName(name)
	switch rtype {
	case convtypes.ServiceType:
		addStringTracking(&t.serviceHostnameMissing, name, hostname)
		addStringTracking(&t.hostnameServiceMissing, hostname, name)
	case convtypes.SecretType:
		addStringTracking(&t.secretHostnameMissing, name, hostname)
		addStringTracking(&t.hostnameSecretMissing, hostname, name)
	default:
		panic(fmt.Errorf("unsupported resource type %d", rtype))
	}
}

func validName(name string) {
	if len(strings.Split(name, "/")) != 2 {
		panic(fmt.Errorf("invalid resource name: %s", name))
	}
}

// GetDirtyLinks lists all hostnames and backendIDs that a
// list of ingress touches directly or indirectly:
//
//   * when a hostname is listed, all other hostnames of all ingress that
//     references it should also be listed;
//   * when a backendID (service+port) is listed, all other backendIDs of
//     all ingress that references it should also be listed.
//
func (t *tracker) GetDirtyLinks(
	oldIngressList []string,
	oldServiceList, addServiceList []string,
	oldSecretList, addSecretList []string,
) (dirtyIngs, dirtyHosts []string, dirtyBacks []hatypes.BackendID) {
	ingsMap := make(map[string]empty)
	hostsMap := make(map[string]empty)
	backsMap := make(map[hatypes.BackendID]empty)

	// recursively fill hostsMap and backsMap from ingress and secrets
	// that directly or indirectly are referenced by them
	var build func([]string)
	build = func(ingNames []string) {
		for _, ingName := range ingNames {
			ingsMap[ingName] = empty{}
			for _, hostname := range t.getHostnamesByIngress(ingName) {
				if _, found := hostsMap[hostname]; !found {
					hostsMap[hostname] = empty{}
					build(t.getIngressByHostname(hostname))
				}
			}
			for _, backend := range t.getBackendsByIngress(ingName) {
				if _, found := backsMap[backend]; !found {
					backsMap[backend] = empty{}
					build(t.getIngressByBackend(backend))
				}
			}
		}
	}
	build(oldIngressList)
	//
	for _, svcName := range oldServiceList {
		for _, hostname := range t.getHostnamesByService(svcName) {
			if _, found := hostsMap[hostname]; !found {
				hostsMap[hostname] = empty{}
				build(t.getIngressByHostname(hostname))
			}
		}
	}
	for _, svcName := range addServiceList {
		for _, hostname := range t.getHostnamesByServiceMissing(svcName) {
			if _, found := hostsMap[hostname]; !found {
				hostsMap[hostname] = empty{}
				build(t.getIngressByHostname(hostname))
			}
		}
	}
	//
	for _, secretName := range oldSecretList {
		for _, hostname := range t.getHostnamesBySecret(secretName) {
			if _, found := hostsMap[hostname]; !found {
				hostsMap[hostname] = empty{}
				build(t.getIngressByHostname(hostname))
			}
		}
	}
	for _, secretName := range addSecretList {
		for _, hostname := range t.getHostnamesBySecretMissing(secretName) {
			if _, found := hostsMap[hostname]; !found {
				hostsMap[hostname] = empty{}
				build(t.getIngressByHostname(hostname))
			}
		}
	}

	// convert hostsMap and backsMap to slices
	if len(ingsMap) > 0 {
		dirtyIngs = make([]string, 0, len(ingsMap))
		for ing := range ingsMap {
			dirtyIngs = append(dirtyIngs, ing)
		}
		sort.Strings(dirtyIngs)
	}
	if len(hostsMap) > 0 {
		dirtyHosts = make([]string, 0, len(hostsMap))
		for host := range hostsMap {
			dirtyHosts = append(dirtyHosts, host)
		}
		sort.Strings(dirtyHosts)
	}
	if len(backsMap) > 0 {
		dirtyBacks = make([]hatypes.BackendID, 0, len(backsMap))
		for back := range backsMap {
			dirtyBacks = append(dirtyBacks, back)
		}
		sort.Slice(dirtyBacks, func(i, j int) bool {
			return dirtyBacks[i].String() < dirtyBacks[j].String()
		})
	}
	return dirtyIngs, dirtyHosts, dirtyBacks
}

func (t *tracker) DeleteHostnames(hostnames []string) {
	for _, hostname := range hostnames {
		for ing := range t.hostnameIngress[hostname] {
			deleteStringTracking(&t.ingressHostname, ing, hostname)
		}
		deleteStringMapKey(&t.hostnameIngress, hostname)
		for service := range t.hostnameService[hostname] {
			deleteStringTracking(&t.serviceHostname, service, hostname)
		}
		deleteStringMapKey(&t.hostnameService, hostname)
		for service := range t.hostnameServiceMissing[hostname] {
			deleteStringTracking(&t.serviceHostnameMissing, service, hostname)
		}
		deleteStringMapKey(&t.hostnameServiceMissing, hostname)
		for secret := range t.hostnameSecret[hostname] {
			deleteStringTracking(&t.secretHostname, secret, hostname)
		}
		deleteStringMapKey(&t.hostnameSecret, hostname)
		for secret := range t.hostnameSecretMissing[hostname] {
			deleteStringTracking(&t.secretHostnameMissing, secret, hostname)
		}
		deleteStringMapKey(&t.hostnameSecretMissing, hostname)
	}
}

func (t *tracker) DeleteBackends(backends []hatypes.BackendID) {
	for _, backend := range backends {
		for ing := range t.backendIngress[backend] {
			deleteStringBackendTracking(&t.ingressBackend, ing, backend)
		}
		deleteBackendStringMapKey(&t.backendIngress, backend)
	}
}

func (t *tracker) getIngressByHostname(hostname string) []string {
	if t.hostnameIngress == nil {
		return nil
	}
	return getStringTracking(t.hostnameIngress[hostname])
}

func (t *tracker) getHostnamesByIngress(ingName string) []string {
	if t.ingressHostname == nil {
		return nil
	}
	return getStringTracking(t.ingressHostname[ingName])
}

func (t *tracker) getIngressByBackend(backendID hatypes.BackendID) []string {
	if t.backendIngress == nil {
		return nil
	}
	return getStringTracking(t.backendIngress[backendID])
}

func (t *tracker) getBackendsByIngress(ingName string) []hatypes.BackendID {
	if t.ingressBackend == nil {
		return nil
	}
	return getBackendTracking(t.ingressBackend[ingName])
}

func (t *tracker) getHostnamesByService(serviceName string) []string {
	if t.serviceHostname == nil {
		return nil
	}
	return getStringTracking(t.serviceHostname[serviceName])
}

func (t *tracker) getHostnamesByServiceMissing(serviceName string) []string {
	if t.serviceHostnameMissing == nil {
		return nil
	}
	return getStringTracking(t.serviceHostnameMissing[serviceName])
}

func (t *tracker) getHostnamesBySecret(secretName string) []string {
	if t.secretHostname == nil {
		return nil
	}
	return getStringTracking(t.secretHostname[secretName])
}

func (t *tracker) getHostnamesBySecretMissing(secretName string) []string {
	if t.secretHostnameMissing == nil {
		return nil
	}
	return getStringTracking(t.secretHostnameMissing[secretName])
}

func addStringTracking(trackingRef *stringStringMap, key, value string) {
	if *trackingRef == nil {
		*trackingRef = stringStringMap{}
	}
	tracking := *trackingRef
	trackingMap, found := tracking[key]
	if !found {
		trackingMap = map[string]empty{}
		tracking[key] = trackingMap
	}
	trackingMap[value] = empty{}
}

func addBackendStringTracking(trackingRef *backendStringMap, key hatypes.BackendID, value string) {
	if *trackingRef == nil {
		*trackingRef = backendStringMap{}
	}
	tracking := *trackingRef
	trackingMap, found := tracking[key]
	if !found {
		trackingMap = map[string]empty{}
		tracking[key] = trackingMap
	}
	trackingMap[value] = empty{}
}

func addStringBackendTracking(trackingRef *stringBackendMap, key string, value hatypes.BackendID) {
	if *trackingRef == nil {
		*trackingRef = stringBackendMap{}
	}
	tracking := *trackingRef
	trackingMap, found := tracking[key]
	if !found {
		trackingMap = map[hatypes.BackendID]empty{}
		tracking[key] = trackingMap
	}
	trackingMap[value] = empty{}
}

func getStringTracking(tracking map[string]empty) []string {
	stringList := make([]string, 0, len(tracking))
	for value := range tracking {
		stringList = append(stringList, value)
	}
	return stringList
}

func getBackendTracking(tracking map[hatypes.BackendID]empty) []hatypes.BackendID {
	backendList := make([]hatypes.BackendID, 0, len(tracking))
	for value := range tracking {
		backendList = append(backendList, value)
	}
	return backendList
}

func deleteStringTracking(trackingRef *stringStringMap, key, value string) {
	if *trackingRef == nil {
		return
	}
	tracking := *trackingRef
	trackingMap := tracking[key]
	delete(trackingMap, value)
	if len(trackingMap) == 0 {
		delete(tracking, key)
	}
	if len(tracking) == 0 {
		*trackingRef = nil
	}
}

func deleteStringBackendTracking(trackingRef *stringBackendMap, key string, value hatypes.BackendID) {
	if *trackingRef == nil {
		return
	}
	tracking := *trackingRef
	trackingMap := tracking[key]
	delete(trackingMap, value)
	if len(trackingMap) == 0 {
		delete(tracking, key)
	}
	if len(tracking) == 0 {
		*trackingRef = nil
	}
}

func deleteStringMapKey(stringMap *stringStringMap, key string) {
	delete(*stringMap, key)
	if len(*stringMap) == 0 {
		*stringMap = nil
	}
}

func deleteBackendStringMapKey(backendMap *backendStringMap, key hatypes.BackendID) {
	delete(*backendMap, key)
	if len(*backendMap) == 0 {
		*backendMap = nil
	}
}
