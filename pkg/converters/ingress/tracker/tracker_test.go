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
	"reflect"
	"sort"
	"testing"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

type hostTracking struct {
	rtype    convtypes.ResourceType
	name     string
	hostname string
}

type backTracking struct {
	rtype   convtypes.ResourceType
	name    string
	backend hatypes.BackendID
}

var (
	back1a = hatypes.BackendID{
		Namespace: "default",
		Name:      "svc1",
		Port:      "8080",
	}
	back1b = hatypes.BackendID{
		Namespace: "default",
		Name:      "svc1",
		Port:      "8080",
	}
	back2a = hatypes.BackendID{
		Namespace: "default",
		Name:      "svc2",
		Port:      "8080",
	}
	back2b = hatypes.BackendID{
		Namespace: "default",
		Name:      "svc2",
		Port:      "8080",
	}
)

func TestGetDirtyLinks(t *testing.T) {
	testCases := []struct {
		trackedHosts []hostTracking
		trackedBacks []backTracking
		//
		trackedMissingHosts []hostTracking
		//
		oldIngressList []string
		oldServiceList []string
		addServiceList []string
		oldSecretList  []string
		addSecretList  []string
		//
		expDirtyIngs  []string
		expDirtyHosts []string
		expDirtyBacks []hatypes.BackendID
	}{
		// 0
		{},
		// 1
		{
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1"},
		},
		// 2
		{
			oldServiceList: []string{"default/svc1"},
		},
		// 3
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
			},
		},
		// 4
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
			},
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1"},
			expDirtyHosts:  []string{"domain1.local"},
		},
		// 5
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.ServiceType, "default/svc1", "domain1.local"},
			},
			oldServiceList: []string{"default/svc1"},
			expDirtyIngs:   []string{"default/ing1"},
			expDirtyHosts:  []string{"domain1.local"},
		},
		// 6
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.SecretType, "default/secret1", "domain1.local"},
			},
			oldSecretList: []string{"default/secret1"},
			expDirtyIngs:  []string{"default/ing1"},
			expDirtyHosts: []string{"domain1.local"},
		},
		// 7
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
			},
			trackedMissingHosts: []hostTracking{
				{convtypes.ServiceType, "default/svc1", "domain1.local"},
			},
			addServiceList: []string{"default/svc1"},
			expDirtyIngs:   []string{"default/ing1"},
			expDirtyHosts:  []string{"domain1.local"},
		},
		// 8
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
			},
			trackedMissingHosts: []hostTracking{
				{convtypes.SecretType, "default/secret1", "domain1.local"},
			},
			addSecretList: []string{"default/secret1"},
			expDirtyIngs:  []string{"default/ing1"},
			expDirtyHosts: []string{"domain1.local"},
		},
		// 9
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain2.local"},
			},
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1"},
			expDirtyHosts:  []string{"domain1.local"},
		},
		// 10
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain1.local"},
				{convtypes.IngressType, "default/ing3", "domain2.local"},
			},
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1", "default/ing2"},
			expDirtyHosts:  []string{"domain1.local"},
		},
		// 11
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain2.local"},
				{convtypes.IngressType, "default/ing3", "domain2.local"},
			},
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1", "default/ing2", "default/ing3"},
			expDirtyHosts:  []string{"domain1.local", "domain2.local"},
		},
		// 12
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain2.local"},
			},
			trackedBacks: []backTracking{
				{convtypes.IngressType, "default/ing1", back1a},
			},
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1"},
			expDirtyHosts:  []string{"domain1.local"},
			expDirtyBacks:  []hatypes.BackendID{back1b},
		},
		// 13
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain2.local"},
				{convtypes.IngressType, "default/ing3", "domain3.local"},
			},
			trackedBacks: []backTracking{
				{convtypes.IngressType, "default/ing1", back1a},
				{convtypes.IngressType, "default/ing2", back2a},
				{convtypes.IngressType, "default/ing3", back1b},
			},
			oldIngressList: []string{"default/ing1"},
			expDirtyIngs:   []string{"default/ing1", "default/ing3"},
			expDirtyHosts:  []string{"domain1.local", "domain3.local"},
			expDirtyBacks:  []hatypes.BackendID{back1b},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		for _, trackedHost := range test.trackedHosts {
			c.tracker.TrackHostname(trackedHost.rtype, trackedHost.name, trackedHost.hostname)
		}
		for _, trackedBack := range test.trackedBacks {
			c.tracker.TrackBackend(trackedBack.rtype, trackedBack.name, trackedBack.backend)
		}
		for _, trackedMissingHost := range test.trackedMissingHosts {
			c.tracker.TrackMissingOnHostname(trackedMissingHost.rtype, trackedMissingHost.name, trackedMissingHost.hostname)
		}
		dirtyIngs, dirtyHosts, dirtyBacks :=
			c.tracker.GetDirtyLinks(
				test.oldIngressList,
				test.oldServiceList,
				test.addServiceList,
				test.oldSecretList,
				test.addSecretList,
			)
		sort.Strings(dirtyIngs)
		sort.Strings(dirtyHosts)
		sort.Slice(dirtyBacks, func(i, j int) bool {
			return dirtyBacks[i].String() < dirtyBacks[j].String()
		})
		c.compareObjects("dirty ingress", i, dirtyIngs, test.expDirtyIngs)
		c.compareObjects("dirty hosts", i, dirtyHosts, test.expDirtyHosts)
		c.compareObjects("dirty backs", i, dirtyBacks, test.expDirtyBacks)
		c.teardown()
	}
}

func TestDeleteHostnames(t *testing.T) {
	testCases := []struct {
		trackedHosts []hostTracking
		//
		trackedMissingHosts []hostTracking
		//
		deleteHostnames []string
		//
		expIngressHostname stringStringMap
		expHostnameIngress stringStringMap
		expServiceHostname stringStringMap
		expHostnameService stringStringMap
		expSecretHostname  stringStringMap
		expHostnameSecret  stringStringMap
		//
		expServiceHostnameMissing stringStringMap
		expHostnameServiceMissing stringStringMap
		expSecretHostnameMissing  stringStringMap
		expHostnameSecretMissing  stringStringMap
	}{
		// 0
		{},
		// 1
		{
			deleteHostnames: []string{"domain1.local"},
		},
		// 2
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
			},
			expIngressHostname: stringStringMap{"default/ing1": {"domain1.local": empty{}}},
			expHostnameIngress: stringStringMap{"domain1.local": {"default/ing1": empty{}}},
		},
		// 3
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local"},
		},
		// 4
		{
			trackedHosts: []hostTracking{
				{convtypes.ServiceType, "default/svc1", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local"},
		},
		// 5
		{
			trackedMissingHosts: []hostTracking{
				{convtypes.ServiceType, "default/svc1", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local"},
		},
		// 6
		{
			trackedHosts: []hostTracking{
				{convtypes.SecretType, "default/secret1", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local"},
		},
		// 7
		{
			trackedMissingHosts: []hostTracking{
				{convtypes.SecretType, "default/secret1", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local"},
		},
		// 8
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing1", "domain2.local"},
			},
			deleteHostnames: []string{"domain1.local", "domain2.local"},
		},
		// 9
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing1", "domain2.local"},
			},
			deleteHostnames:    []string{"domain1.local"},
			expIngressHostname: stringStringMap{"default/ing1": {"domain2.local": empty{}}},
			expHostnameIngress: stringStringMap{"domain2.local": {"default/ing1": empty{}}},
		},
		// 10
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local"},
		},
		// 11
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing2", "domain1.local"},
			},
			deleteHostnames: []string{"domain1.local", "domain2.local"},
		},
		// 12
		{
			trackedHosts: []hostTracking{
				{convtypes.IngressType, "default/ing1", "domain1.local"},
				{convtypes.IngressType, "default/ing1", "domain2.local"},
				{convtypes.IngressType, "default/ing1", "domain3.local"},
				{convtypes.ServiceType, "default/svc1", "domain1.local"},
				{convtypes.ServiceType, "default/svc1", "domain2.local"},
				{convtypes.ServiceType, "default/svc1", "domain3.local"},
				{convtypes.SecretType, "default/secret1", "domain1.local"},
				{convtypes.SecretType, "default/secret1", "domain2.local"},
				{convtypes.SecretType, "default/secret1", "domain3.local"},
			},
			deleteHostnames:    []string{"domain1.local", "domain2.local"},
			expIngressHostname: stringStringMap{"default/ing1": {"domain3.local": empty{}}},
			expHostnameIngress: stringStringMap{"domain3.local": {"default/ing1": empty{}}},
			expServiceHostname: stringStringMap{"default/svc1": {"domain3.local": empty{}}},
			expHostnameService: stringStringMap{"domain3.local": {"default/svc1": empty{}}},
			expSecretHostname:  stringStringMap{"default/secret1": {"domain3.local": empty{}}},
			expHostnameSecret:  stringStringMap{"domain3.local": {"default/secret1": empty{}}},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		for _, trackedHost := range test.trackedHosts {
			c.tracker.TrackHostname(trackedHost.rtype, trackedHost.name, trackedHost.hostname)
		}
		for _, trackedMissingHost := range test.trackedMissingHosts {
			c.tracker.TrackMissingOnHostname(trackedMissingHost.rtype, trackedMissingHost.name, trackedMissingHost.hostname)
		}
		c.tracker.DeleteHostnames(test.deleteHostnames)
		c.compareObjects("ingressHostname", i, c.tracker.ingressHostname, test.expIngressHostname)
		c.compareObjects("hostnameIngress", i, c.tracker.hostnameIngress, test.expHostnameIngress)
		c.compareObjects("serviceHostname", i, c.tracker.serviceHostname, test.expServiceHostname)
		c.compareObjects("hostnameService", i, c.tracker.hostnameService, test.expHostnameService)
		c.compareObjects("secretHostname", i, c.tracker.secretHostname, test.expSecretHostname)
		c.compareObjects("hostnameSecret", i, c.tracker.hostnameSecret, test.expHostnameSecret)
		c.compareObjects("serviceHostnameMissing", i, c.tracker.serviceHostnameMissing, test.expServiceHostnameMissing)
		c.compareObjects("hostnameServiceMissing", i, c.tracker.hostnameServiceMissing, test.expHostnameServiceMissing)
		c.compareObjects("secretHostnameMissing", i, c.tracker.secretHostnameMissing, test.expSecretHostnameMissing)
		c.compareObjects("hostnameSecretMissing", i, c.tracker.hostnameSecretMissing, test.expHostnameSecretMissing)
		c.teardown()
	}
}

func TestDeleteBackends(t *testing.T) {
	testCases := []struct {
		trackedBacks []backTracking
		//
		deleteBackends []hatypes.BackendID
		//
		expIngressBackend stringBackendMap
		expBackendIngress backendStringMap
	}{
		// 0
		{},
		// 1
		{
			deleteBackends: []hatypes.BackendID{back1b},
		},
		// 2
		{
			trackedBacks: []backTracking{
				{convtypes.IngressType, "default/ing1", back1a},
			},
			expBackendIngress: backendStringMap{back1b: {"default/ing1": empty{}}},
			expIngressBackend: stringBackendMap{"default/ing1": {back1b: empty{}}},
		},
		// 3
		{
			trackedBacks: []backTracking{
				{convtypes.IngressType, "default/ing1", back1a},
			},
			deleteBackends: []hatypes.BackendID{back1b},
		},
		// 4
		{
			trackedBacks: []backTracking{
				{convtypes.IngressType, "default/ing1", back1a},
				{convtypes.IngressType, "default/ing2", back1a},
				{convtypes.IngressType, "default/ing2", back2a},
			},
			deleteBackends:    []hatypes.BackendID{back1b},
			expBackendIngress: backendStringMap{back2b: {"default/ing2": empty{}}},
			expIngressBackend: stringBackendMap{"default/ing2": {back2b: empty{}}},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		for _, trackedBack := range test.trackedBacks {
			c.tracker.TrackBackend(trackedBack.rtype, trackedBack.name, trackedBack.backend)
		}
		c.tracker.DeleteBackends(test.deleteBackends)
		c.compareObjects("ingressBackend", i, c.tracker.ingressBackend, test.expIngressBackend)
		c.compareObjects("backendIngress", i, c.tracker.backendIngress, test.expBackendIngress)
		c.teardown()
	}
}

type testConfig struct {
	t       *testing.T
	tracker *tracker
}

func setup(t *testing.T) *testConfig {
	return &testConfig{
		t:       t,
		tracker: NewTracker().(*tracker),
	}
}

func (c *testConfig) teardown() {}

func (c *testConfig) compareObjects(name string, index int, actual, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		c.t.Errorf("%s on %d differs - expected: %v - actual: %v", name, index, expected, actual)
	}
}
