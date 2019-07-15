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
type Map struct {
	Source *Source
	ID     string
	Value  string
}

// Source ...
type Source struct {
	Namespace string
	Name      string
	Type      string
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
func (c *Mapper) AddAnnotation(source *Source, id, key, value string) bool {
	annMaps, found := c.maps[key]
	if found {
		for _, annMap := range annMaps {
			if annMap.ID == id {
				// true if value was used -- either adding or
				// matching a previous one. Map.Source is ignored here.
				return annMap.Value == value
			}
		}
	}
	annMaps = append(annMaps, &Map{
		Source: source,
		ID:     id,
		Value:  value,
	})
	c.maps[key] = annMaps
	return true
}

// AddAnnotations ...
func (c *Mapper) AddAnnotations(source *Source, id string, ann map[string]string) (skipped []string) {
	skipped = make([]string, 0, len(ann))
	for key, value := range ann {
		if added := c.AddAnnotation(source, id, key, value); !added {
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
		c.logger.Warn(
			"annotation '%s' from %s overrides the same annotation with distinct value from %s",
			c.annPrefix+key, source, sources)
	}
	return value, source, true
}

// GetStrValue ...
func (c *Mapper) GetStrValue(key string) string {
	value, _, _ := c.GetStr(key)
	return value
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

func (m *Map) String() string {
	return fmt.Sprintf("%+v", *m)
}

func (s *Source) String() string {
	return s.Type + " '" + s.Namespace + "/" + s.Name + "'"
}
