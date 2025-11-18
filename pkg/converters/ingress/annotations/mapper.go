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
	"strings"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type ConfigValueGetter interface {
	Get(key string) *ConfigValue
}

// MapBuilder ...
type MapBuilder struct {
	logger      types.Logger
	annDefaults map[string]string
}

// Mapper ...
type Mapper struct {
	MapBuilder
	configByKey  map[string][]*PathConfig
	configByPath map[hatypes.PathLinkHash]*KeyConfig
}

// KeyConfig ...
type KeyConfig struct {
	mapper *Mapper
	keys   map[string]*ConfigValue
}

// PathConfig ...
type PathConfig struct {
	path  *hatypes.PathLink
	value *ConfigValue
}

// Source ...
type Source struct {
	Namespace string
	Name      string
	Type      convtypes.ResourceType
}

// ConfigValue ...
type ConfigValue struct {
	Source *Source
	Value  string
}

// NewMapBuilder ...
func NewMapBuilder(logger types.Logger, annDefaults map[string]string) *MapBuilder {
	return &MapBuilder{
		logger:      logger,
		annDefaults: annDefaults,
	}
}

// NewMapper ...
func (b *MapBuilder) NewMapper() *Mapper {
	return &Mapper{
		MapBuilder: *b,
		//
		configByKey:  map[string][]*PathConfig{},
		configByPath: map[hatypes.PathLinkHash]*KeyConfig{},
	}
}

func newKeyConfig(mapper *Mapper) *KeyConfig {
	return &KeyConfig{
		mapper: mapper,
		keys:   map[string]*ConfigValue{},
	}
}

// Add a new annotation to the current mapper.
// Return the conflict state: true if a conflict was found, false if the annotation was assigned or at least handled
func (c *Mapper) addAnnotation(source *Source, path *hatypes.PathLink, key, value string) bool {
	if path.IsEmpty() {
		// empty means default value, cannot register as an annotation
		panic("path link cannot be empty")
	}
	// check overlap
	config, configfound := c.configByPath[path.Hash()]
	if !configfound {
		config = newKeyConfig(c)
		c.configByPath[path.Hash()] = config
	}
	if cv, found := config.keys[key]; found {
		// there is a conflict only if values differ
		return cv.Value != value
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
	configValue := &ConfigValue{
		Source: source,
		Value:  realValue,
	}
	config.keys[key] = configValue
	pathConfigs := c.configByKey[key]
	pathConfigs = append(pathConfigs, &PathConfig{
		path:  path,
		value: configValue,
	})
	c.configByKey[key] = pathConfigs
	return false
}

// AddAnnotations ...
func (c *Mapper) AddAnnotations(source *Source, path *hatypes.PathLink, ann map[string]string) (conflicts []string) {
	conflicts = make([]string, 0, len(ann))
	for key, value := range ann {
		if conflict := c.addAnnotation(source, path, key, value); conflict {
			conflicts = append(conflicts, key)
		}
	}
	return conflicts
}

func (c *Mapper) findPathConfig(key string) ([]*PathConfig, bool) {
	configs, found := c.configByKey[key]
	if found && len(configs) > 0 {
		return configs, true
	}
	value, found := c.annDefaults[key]
	if found {
		return []*PathConfig{{value: &ConfigValue{Value: value}}}, true
	}
	return nil, false
}

// GetConfig ...
func (c *Mapper) GetConfig(path *hatypes.PathLink) *KeyConfig {
	if config, found := c.configByPath[path.Hash()]; found {
		return config
	}
	config := newKeyConfig(c)
	c.configByPath[path.Hash()] = config
	return config
}

func (c *Mapper) CopyConfig(dst, src *hatypes.PathLink) {
	c.configByPath[dst.Hash()] = c.GetConfig(src)
}

// Get ...
func (c *Mapper) Get(key string) *ConfigValue {
	configs, found := c.findPathConfig(key)
	if !found {
		return &ConfigValue{}
	}
	value := configs[0].value
	if len(configs) > 1 {
		sources := make([]*Source, 0, len(configs))
		for _, config := range configs {
			if value.Value != config.value.Value {
				sources = append(sources, config.value.Source)
			}
		}
		if len(sources) > 0 {
			c.logger.Warn(
				"configuration key '%s' from %s overrides the same key with distinct value from %s",
				key, value.Source, sources)
		}
	}
	return value
}

// Get ...
func (c *KeyConfig) Get(key string) *ConfigValue {
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

// NamespacedName ...
func (cv *ConfigValue) NamespacedName() (namespace, name string, err error) {
	// TODO this fixes updater.buildBackendProtocol() by allowing a proto://content approach, supported by the cache.
	// This however seems to be wrongly implemented, since cache method signature does not match this behavior.
	// Removing the proto parsing code from the cache seems to be a better approach, so callers have a better idea on
	// what is happening under the hood.
	if strings.Contains(cv.Value, "://") {
		var ns string
		if s := cv.Source; s != nil {
			ns = s.Namespace
		}
		return ns, cv.Value, nil
	}

	value := strings.Split(cv.Value, "/")
	if len(value) > 2 {
		return "", "", fmt.Errorf("unexpected format for resource name: %s", cv.Value)
	}
	if len(value) == 2 {
		return value[0], value[1], nil
	}
	if s := cv.Source; s != nil {
		return s.Namespace, value[0], nil
	}
	return "", "", fmt.Errorf("a globally configured resource name is missing the namespace: %s", cv.Value)
}

// ToLower ...
func (cv *ConfigValue) ToLower() string {
	return strings.ToLower(cv.Value)
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

// Int32 ...
func (cv *ConfigValue) Int32() int32 {
	value, _ := strconv.Atoi(cv.Value)
	return int32(value)
}

// Int64 ...
func (cv *ConfigValue) Int64() int64 {
	value, _ := strconv.ParseInt(cv.Value, 10, 64)
	return value
}

// FullName ...
func (s *Source) FullName() string {
	return s.Namespace + "/" + s.Name
}

// String ...
func (m *PathConfig) String() string {
	return fmt.Sprintf("%+v", *m)
}

// String ...
func (s *Source) String() string {
	if s == nil {
		return "<global>"
	}
	return fmt.Sprintf("%s '%s'", s.Type, s.FullName())
}
