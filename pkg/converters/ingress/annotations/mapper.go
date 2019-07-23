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
	"sort"
	"strconv"

	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// MapBuilder ...
type MapBuilder struct {
	logger      types.Logger
	annPrefix   string
	annDefaults map[string]string
}

// Mapper ...
type Mapper struct {
	MapBuilder
	maps map[string][]*Map
}

// Map ...
//
// TODO rename URI to Hostpath -- currently this is a little mess.
// Fix also testCase data in order to represent a hostname+path.
// Hostname is the domain name. Path is the declared starting path on ingress
// Together they populate a map_beg() converter in order to match HAProxy's
// `base` sample fetch method.
//
type Map struct {
	Source *Source
	URI    string
	Value  string
}

// Source ...
type Source struct {
	Namespace string
	Name      string
	Type      string
}

// BackendConfig ...
type BackendConfig struct {
	Paths  hatypes.BackendPaths
	Config map[string]string
}

// NewMapBuilder ...
func NewMapBuilder(logger types.Logger, annPrefix string, annDefaults map[string]string) *MapBuilder {
	return &MapBuilder{
		logger:      logger,
		annPrefix:   annPrefix,
		annDefaults: annDefaults,
	}
}

// NewMapper ...
func (b *MapBuilder) NewMapper() *Mapper {
	return &Mapper{
		MapBuilder: *b,
		maps:       map[string][]*Map{},
	}
}

// AddAnnotation ...
func (c *Mapper) AddAnnotation(source *Source, hostpath, key, value string) bool {
	annMaps, found := c.maps[key]
	if hostpath == "" {
		// empty hostpath means default value
		panic("hostpath cannot be empty")
	}
	if found {
		for _, annMap := range annMaps {
			if annMap.URI == hostpath {
				// true if value was used -- either adding or
				// matching a previous one. Map.Source is ignored here.
				return annMap.Value == value
			}
		}
	}
	annMaps = append(annMaps, &Map{
		Source: source,
		URI:    hostpath,
		Value:  value,
	})
	c.maps[key] = annMaps
	return true
}

// AddAnnotations ...
func (c *Mapper) AddAnnotations(source *Source, hostpath string, ann map[string]string) (skipped []string) {
	skipped = make([]string, 0, len(ann))
	for key, value := range ann {
		if added := c.AddAnnotation(source, hostpath, key, value); !added {
			skipped = append(skipped, key)
		}
	}
	return skipped
}

// GetStrMap ...
func (c *Mapper) GetStrMap(key string) ([]*Map, bool) {
	annMaps, found := c.maps[key]
	if found && len(annMaps) > 0 {
		return annMaps, true
	}
	value, found := c.annDefaults[key]
	if found {
		return []*Map{{Value: value}}, true
	}
	return []*Map{}, false
}

// GetStr ...
func (c *Mapper) GetStr(key string) (string, *Source, bool) {
	annMaps, found := c.GetStrMap(key)
	if !found {
		return "", nil, false
	}
	value := annMaps[0].Value
	source := annMaps[0].Source
	if len(annMaps) > 1 {
		sources := make([]*Source, 0, len(annMaps))
		for _, annMap := range annMaps {
			if value != annMap.Value {
				sources = append(sources, annMap.Source)
			}
		}
		if len(sources) > 0 {
			c.logger.Warn(
				"annotation '%s' from %s overrides the same annotation with distinct value from %s",
				c.annPrefix+key, source, sources)
		}
	}
	return value, source, true
}

// GetStrValue ...
func (c *Mapper) GetStrValue(key string) string {
	value, _, _ := c.GetStr(key)
	return value
}

// GetStrFromMap ...
func (c *Mapper) GetStrFromMap(config *BackendConfig, key string) (string, bool) {
	if value, found := config.Config[key]; found {
		return value, true
	}
	value, found := c.annDefaults[key]
	return value, found
}

// GetBool ...
func (c *Mapper) GetBool(key string) (bool, *Source, bool) {
	valueStr, src, found := c.GetStr(key)
	if !found {
		return false, nil, false
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		c.logger.Warn("ignoring annotation '%s' from %s: %v", c.annPrefix+key, src, err)
		return false, src, false
	}
	return value, src, true
}

// GetBoolValue ...
func (c *Mapper) GetBoolValue(key string) bool {
	value, _, _ := c.GetBool(key)
	return value
}

// GetBoolFromMap ...
func (c *Mapper) GetBoolFromMap(backend *hatypes.Backend, config *BackendConfig, key string) bool {
	if valueStr, found := c.GetStrFromMap(config, key); found {
		value, err := strconv.ParseBool(valueStr)
		if err != nil {
			c.logger.Warn("ignoring key '%s' for backend '%s/%s': %v", key, backend.Namespace, backend.Name, err)
		}
		return value
	}
	return false
}

// GetInt ...
func (c *Mapper) GetInt(key string) (int, *Source, bool) {
	valueStr, src, found := c.GetStr(key)
	if !found {
		return 0, nil, false
	}
	value, err := strconv.ParseInt(valueStr, 10, 0)
	if err != nil {
		c.logger.Warn("ignoring annotation '%s' from %s: %v", c.annPrefix+key, src, err)
		return 0, src, false
	}
	return int(value), src, true
}

// GetIntValue ...
func (c *Mapper) GetIntValue(key string) int {
	value, _, _ := c.GetInt(key)
	return value
}

// GetIntFromMap ...
func (c *Mapper) GetIntFromMap(backend *hatypes.Backend, config *BackendConfig, key string) int {
	if valueStr, found := c.GetStrFromMap(config, key); found {
		value, err := strconv.ParseInt(valueStr, 10, 0)
		if err != nil {
			c.logger.Warn("ignoring key '%s' for backend '%s/%s': %v", key, backend.Namespace, backend.Name, err)
		}
		return int(value)
	}
	return 0
}

// GetBackendConfig builds a generic BackendConfig using
// annotation maps registered previously as its data source
//
// An annotation map is a `map[<uri>]<value>` collected on
// ingress/service parsing phase. A HAProxy backend need a group
// of annotation keys - ie a group of maps - grouped by URI in
// order to create and apply ACLs.
//
// The rule of thumb on the final BackendConfig array is:
//
//   1. Every backend path must be declared, so a HAProxy method can
//      just `if len(BackendConfig) > 1 then need-acl`;
//   2. Added annotation means declared annotation (ingress, service
//      or default) so the config reader `Get<Type>FromMap()`` can
//      distinguish between `undeclared` and `declared empty`.
//
func (c *Mapper) GetBackendConfig(backend *hatypes.Backend, keys ...string) []*BackendConfig {
	// all backend paths need to be declared, filling up previously with default values
	rawConfig := make(map[string]map[string]string, len(backend.Paths))
	for _, path := range backend.Paths {
		kv := make(map[string]string, len(keys))
		for _, key := range keys {
			if value, found := c.annDefaults[key]; found {
				kv[key] = value
			}
		}
		rawConfig[path.Hostpath] = kv
	}
	// populate rawConfig with declared annotations, grouping annotation maps by URI
	for _, key := range keys {
		if maps, found := c.GetStrMap(key); found {
			for _, m := range maps {
				// skip default value
				if m.URI != "" {
					if _, found := rawConfig[m.URI]; !found {
						panic(fmt.Sprintf("backend '%s' is missing hostname/path '%s'", backend.Name, m.URI))
					}
					rawConfig[m.URI][key] = m.Value
				}
			}
		}
	}
	// iterate the URIs and create the BackendConfig array
	// most configs should have just one item with default kv
	config := make([]*BackendConfig, 0, 1)
	for uri, kv := range rawConfig {
		path := backend.FindHostPath(uri)
		if cfg := findConfig(config, kv); cfg != nil {
			cfg.Paths.Add(path)
		} else {
			config = append(config, &BackendConfig{
				Paths:  hatypes.NewBackendPaths(path),
				Config: kv,
			})
		}
	}
	// rawConfig is a map which by definition does not have explicit order.
	// sort in order to the same input generates the same output
	sort.SliceStable(config, func(i, j int) bool {
		return config[i].Paths.Items[0].Hostpath < config[j].Paths.Items[0].Hostpath
	})
	return config
}

func findConfig(config []*BackendConfig, kv map[string]string) *BackendConfig {
	for _, cfg := range config {
		if reflect.DeepEqual(cfg.Config, kv) {
			return cfg
		}
	}
	return nil
}

// GetBackendConfigStr ...
func (c *Mapper) GetBackendConfigStr(backend *hatypes.Backend, key string) []*hatypes.BackendConfigStr {
	rawConfig := c.GetBackendConfig(backend, key)
	config := make([]*hatypes.BackendConfigStr, len(rawConfig))
	for i, cfg := range rawConfig {
		config[i] = &hatypes.BackendConfigStr{
			Paths:  cfg.Paths,
			Config: cfg.Config[key],
		}
	}
	return config
}

func (b *BackendConfig) String() string {
	return fmt.Sprintf("%+v", *b)
}

func (m *Map) String() string {
	return fmt.Sprintf("%+v", *m)
}

func (s *Source) String() string {
	return s.Type + " '" + s.Namespace + "/" + s.Name + "'"
}
