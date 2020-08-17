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

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/tracker"
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
	return &testConfig{
		t:       t,
		haproxy: haproxy.CreateInstance(logger, haproxy.InstanceOptions{}).Config(),
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
	}
}

func (c *testConfig) createBackendData(svcFullName string, source *Source, ann, annDefault map[string]string) *backData {
	mapper := NewMapBuilder(c.logger, "ing.k8s.io/", annDefault).NewMapper()
	mapper.AddAnnotations(source, hatypes.CreatePathLink("domain.local", "/"), ann)
	svcName := strings.Split(svcFullName, "/")
	namespace := svcName[0]
	name := svcName[1]
	return &backData{
		backend: &hatypes.Backend{
			ID:        fmt.Sprintf("%s_%s_%d", namespace, name, 8080),
			Namespace: namespace,
			Name:      name,
		},
		mapper: mapper,
	}
}

const testingHostname = "host.local"

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
	for path := range paths {
		b := d.backend.AddBackendPath(hatypes.CreatePathLink(testingHostname, path))
		// ignoring ID which isn't the focus of the test
		// removing on createBackendPaths() as well
		b.ID = ""
	}
	for uri, ann := range urlAnnValue {
		d.mapper.AddAnnotations(source, hatypes.CreatePathLink(testingHostname, uri), ann)
	}
	return d
}

func (c *testConfig) createHostData(source *Source, ann, annDefault map[string]string) *hostData {
	mapper := NewMapBuilder(c.logger, "", annDefault).NewMapper()
	mapper.AddAnnotations(source, hatypes.CreatePathLink("domain.local", "/"), ann)
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

func (c *testConfig) createGlobalData(config map[string]string) *globalData {
	return &globalData{
		global: &hatypes.Global{},
		mapper: NewMapBuilder(c.logger, "", config).NewMapper(),
	}
}
