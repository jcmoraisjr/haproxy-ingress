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

package annotations

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/tracker"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	types_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  BUILDERS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

const (
	fakeCAFilename = "/var/haproxy/ssl/fake-ca.crt"
	fakeCAHash     = "1"
)

func TestSplitDualCIDR(t *testing.T) {
	testCases := []struct {
		list     string
		expAllow []string
		expDeny  []string
		logging  string
	}{
		// 0
		{
			list:     "10.0.0.0/8",
			expAllow: []string{"10.0.0.0/8"},
		},
		// 1
		{
			list:     "10.0.0.0/8,192.168.0.0/16",
			expAllow: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		// 2
		{
			list:     "fa00::/64",
			expAllow: []string{"fa00::/64"},
		},
		// 3
		{
			list:    "10.0.0.0/64",
			logging: `WARN skipping invalid IP or cidr on ingress 'default/ing': 10.0.0.0/64`,
		},
		// 4
		{
			list:     "10.0.0.0/64,192.168.0.0/16",
			expAllow: []string{"192.168.0.0/16"},
			logging:  `WARN skipping invalid IP or cidr on ingress 'default/ing': 10.0.0.0/64`,
		},
		// 5
		{
			list:     "10.0.0.0/8,!192.168.0.0/16",
			expAllow: []string{"10.0.0.0/8"},
			expDeny:  []string{"192.168.0.0/16"},
		},
		// 6
		{
			list:     "10.0.0.0/8,!192.168.0.0/64",
			expAllow: []string{"10.0.0.0/8"},
			logging:  `WARN skipping invalid IP or cidr on ingress 'default/ing': 192.168.0.0/64`,
		},
		// 7
		{
			list:     "10.0.0.0/8,!",
			expAllow: []string{"10.0.0.0/8"},
			logging:  `WARN skipping deny of an empty IP or CIDR on ingress 'default/ing'`,
		},
	}
	source := &Source{Name: "ing", Namespace: "default", Type: "ingress"}
	for i, test := range testCases {
		c := setup(t)
		cv := &ConfigValue{
			Source: source,
			Value:  test.list,
		}
		allow, deny := c.createUpdater().splitDualCIDR(cv)
		c.compareObjects("allow list", i, allow, test.expAllow)
		c.compareObjects("deny list", i, deny, test.expDeny)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

type testConfig struct {
	t       *testing.T
	haproxy haproxy.Config
	cache   *conv_helper.CacheMock
	tracker convtypes.Tracker
	logger  *types_helper.LoggerMock
}

func setup(t *testing.T) *testConfig {
	logger := &types_helper.LoggerMock{T: t}
	tracker := tracker.NewTracker()
	instance := haproxy.CreateInstance(logger, haproxy.InstanceOptions{}).Config()
	instance.Global().Peers.LocalPeer.BESuffix = "proxy01" // we need this to properly initialize updater's vars map
	return &testConfig{
		t:       t,
		haproxy: instance,
		cache:   conv_helper.NewCacheMock(tracker),
		tracker: tracker,
		logger:  logger,
	}
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
}

func (c *testConfig) createUpdater() *updater {
	return &updater{
		haproxy: c.haproxy,
		cache:   c.cache,
		logger:  c.logger,
		tracker: c.tracker,
		fakeCA: convtypes.CrtFile{
			Filename: fakeCAFilename,
			SHA1Hash: fakeCAHash,
		},
		options: &convtypes.ConverterOptions{
			DynamicConfig: &convtypes.DynamicConfig{},
		},
		vars: buildGlobalVars(c.haproxy.Global()),
	}
}

func (c *testConfig) createBackendData(svcFullName string, source *Source, ann, annDefault map[string]string) *backData {
	mapper := NewMapBuilder(c.logger, annDefault).NewMapper()
	mapper.AddAnnotations(source, hatypes.CreatePathLink("/", hatypes.MatchBegin), ann)
	svcName := strings.Split(svcFullName, "/")
	namespace := svcName[0]
	name := svcName[1]
	backend := &hatypes.Backend{
		ID:        fmt.Sprintf("%s_%s_%d", namespace, name, 8080),
		Namespace: namespace,
		Name:      name,
	}
	global := c.haproxy.Global()
	return &backData{
		backend: backend,
		mapper:  mapper,
		vars:    buildBackendVars(global, backend, buildGlobalVars(global)),
	}
}

func (c *testConfig) createBackendMappingData(
	svcFullName string,
	source *Source,
	annDefault map[string]string,
	urlAnnValue map[string]map[string]string,
	addPaths []string,
) *backData {
	d := c.createBackendData(svcFullName, source, map[string]string{}, annDefault)
	paths := make(map[string]struct{}, len(urlAnnValue)+len(addPaths))
	for path := range urlAnnValue {
		paths[path] = struct{}{}
	}
	for _, path := range addPaths {
		paths[path] = struct{}{}
	}
	for p := range paths {
		d.backend.AddPath(&hatypes.Path{
			Link:     hatypes.CreatePathLink(p, hatypes.MatchBegin),
			HasHTTPS: true,
		})
	}
	for uri, ann := range urlAnnValue {
		d.mapper.AddAnnotations(source, hatypes.CreatePathLink(uri, hatypes.MatchBegin), ann)
	}
	return d
}

func (c *testConfig) createFrontData(source *Source, isHTTPS bool, ann, annDefault map[string]string) *frontData {
	mapper := NewMapBuilder(c.logger, annDefault).NewMapper()
	fp := NewFrontendPorts(c.logger, c.haproxy, mapper) // mapper having defaults only
	mapper.AddAnnotations(source, hatypes.CreatePathLink("/", hatypes.MatchBegin), ann)
	httpPort, httpsPort, httpPassPort, localPorts := fp.AcquirePorts(mapper) // now mapper having also annotation level keys
	var port int32
	if isHTTPS {
		port = httpsPort
	} else if httpPassPort != 0 {
		port = httpPassPort
	} else {
		port = httpPort
	}
	front := c.haproxy.Frontends().AcquireFrontend(port, isHTTPS)
	if httpPassPort != 0 {
		front.HTTPPassthrough = true
	}
	return &frontData{
		front:      front,
		localPorts: localPorts,
		mapper:     mapper,
		logger:     c.logger,
	}
}

func (c *testConfig) createHostData(source *Source, ann, annDefault map[string]string) *hostData {
	mapper := NewMapBuilder(c.logger, annDefault).NewMapper()
	mapper.AddAnnotations(source, hatypes.CreatePathLink("/", hatypes.MatchBegin), ann)
	return &hostData{
		host:   &hatypes.Host{},
		mapper: mapper,
	}
}

func (c *testConfig) compareObjects(name string, index int, actual, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		c.t.Errorf("%s on %d differs - expected: %v - actual: %v", name, index, expected, actual)
	}
}

func (c *testConfig) compareText(name string, index int, actual, expected string) {
	txtActual := "\n" + strings.Trim(actual, "\n")
	txtExpected := "\n" + strings.Trim(expected, "\n")
	if txtActual != txtExpected {
		c.t.Errorf("\ndiff of %s on %d:%s", name, index, diff.Diff(txtExpected, txtActual))
	}
}

func (c *testConfig) createGlobalData(config map[string]string) *globalData {
	return &globalData{
		global: &hatypes.Global{},
		mapper: NewMapBuilder(c.logger, config).NewMapper(),
	}
}
