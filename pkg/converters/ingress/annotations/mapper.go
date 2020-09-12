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
	maps    map[string][]*Map
	configs map[hatypes.PathLink]*AnnConfig
}

// AnnConfig ...
type AnnConfig struct {
	mapper *Mapper
	keys   map[string]*ConfigValue
}

// Map ...
type Map struct {
	Source *Source
	Link   hatypes.PathLink
	Value  string
}

// Source ...
type Source struct {
	Namespace string
	Name      string
	Type      string
}

// ConfigValue ...
type ConfigValue struct {
	Source *Source
	Value  string
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
		//
		maps:    map[string][]*Map{},
		configs: map[hatypes.PathLink]*AnnConfig{},
	}
}

func newAnnConfig(mapper *Mapper) *AnnConfig {
	return &AnnConfig{
		mapper: mapper,
		keys:   map[string]*ConfigValue{},
	}
}

// Add a new annotation to the current mapper.
// Return the conflict state: true if a conflict was found, false if the annotation was assigned or at least handled
func (c *Mapper) addAnnotation(source *Source, link hatypes.PathLink, key, value string) bool {
	if link.IsEmpty() {
		// empty means default value, cannot register as an annotation
		panic("path link cannot be empty")
	}
	// check overlap
	config, configfound := c.configs[link]
	if !configfound {
		config = newAnnConfig(c)
		c.configs[link] = config
	}
	if cfg, found := config.keys[key]; found {
		return cfg.Value != value
	}
	// validate (bool; int; ...) and normalize (int "01" => "1"; ...)
	realValue := value
	if validator, found := validators[key]; found {
		var ok bool
		if realValue, ok = validator(validate{logger: c.logger, source: source, key: key, value: value}); !ok {
			return false
		}
	}
	// update internal fields
	config.keys[key] = &ConfigValue{
		Source: source,
		Value:  realValue,
	}
	annMaps, _ := c.maps[key]
	annMaps = append(annMaps, &Map{
		Source: source,
		Link:   link,
		Value:  realValue,
	})
	c.maps[key] = annMaps
	return false
}

// AddAnnotations ...
func (c *Mapper) AddAnnotations(source *Source, link hatypes.PathLink, ann map[string]string) (conflicts []string) {
	conflicts = make([]string, 0, len(ann))
	for key, value := range ann {
		if conflict := c.addAnnotation(source, link, key, value); conflict {
			conflicts = append(conflicts, key)
		}
	}
	return conflicts
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
	return nil, false
}

// GetConfig ...
func (c *Mapper) GetConfig(link hatypes.PathLink) *AnnConfig {
	if config, found := c.configs[link]; found {
		return config
	}
	config := newAnnConfig(c)
	c.configs[link] = config
	return config
}

// Get ...
func (c *Mapper) Get(key string) *ConfigValue {
	annMaps, found := c.GetStrMap(key)
	if !found {
		return &ConfigValue{}
	}
	value := &ConfigValue{
		Source: annMaps[0].Source,
		Value:  annMaps[0].Value,
	}
	if len(annMaps) > 1 {
		sources := make([]*Source, 0, len(annMaps))
		for _, annMap := range annMaps {
			if value.Value != annMap.Value {
				sources = append(sources, annMap.Source)
			}
		}
		if len(sources) > 0 {
			c.logger.Warn(
				"annotation '%s' from %s overrides the same annotation with distinct value from %s",
				c.annPrefix+key, value.Source, sources)
		}
	}
	return value
}

// Get ...
func (c *AnnConfig) Get(key string) *ConfigValue {
	if value, found := c.keys[key]; found {
		return value
	}
	if value, found := c.mapper.annDefaults[key]; found {
		return &ConfigValue{Value: value}
	}
	return &ConfigValue{}
}

// String ...
func (cv *ConfigValue) String() string {
	return cv.Value
}

// Bool ...
func (cv *ConfigValue) Bool() bool {
	value, _ := strconv.ParseBool(cv.Value)
	return value
}

// Int ...
func (cv *ConfigValue) Int() int {
	value, _ := strconv.Atoi(cv.Value)
	return value
}

// Int64 ...
func (cv *ConfigValue) Int64() int64 {
	value, _ := strconv.ParseInt(cv.Value, 10, 0)
	return value
}

// FullName ...
func (s *Source) FullName() string {
	return s.Namespace + "/" + s.Name
}

// String ...
func (m *Map) String() string {
	return fmt.Sprintf("%+v", *m)
}

// String ...
func (s *Source) String() string {
	return s.Type + " '" + s.FullName() + "'"
}
