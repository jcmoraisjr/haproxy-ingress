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

package types

import (
	"fmt"
	"sort"
	"strings"
)

// AppendHostname ...
func (hm *HostsMap) AppendHostname(base, value string) {
	// always use case insensitive match
	base = strings.ToLower(base)
	isHostnameOnly := !strings.Contains(base, "/")
	if strings.HasPrefix(base, "*.") {
		// *.example.local
		key := "^" + strings.Replace(base, ".", "\\.", -1)
		key = strings.Replace(key, "*", "[^.]+", 1)
		if isHostnameOnly {
			// match eol if only the hostname is provided
			// if has /path, need to match the begining of the string, a la map_beg() converter
			key = key + "$"
		}
		hm.Regex = append(hm.Regex, &HostsMapEntry{
			Key:   key,
			Value: value,
		})
	} else {
		// sub.example.local
		hm.Match = append(hm.Match, &HostsMapEntry{
			Key:   base,
			Value: value,
		})
		// Hostnames are already in alphabetical order but Alias are not
		// Sort only hostname maps which uses ebtree search via map converter
		if isHostnameOnly {
			sort.Slice(hm.Match, func(i, j int) bool {
				return hm.Match[i].Key < hm.Match[j].Key
			})
		}
	}
}

// AppendAliasName ...
func (hm *HostsMap) AppendAliasName(base, value string) {
	if base != "" {
		hm.AppendHostname(base, value)
	}
}

// AppendAliasRegex ...
func (hm *HostsMap) AppendAliasRegex(base, value string) {
	// always use case insensitive match
	base = strings.ToLower(base)
	if base != "" {
		hm.Regex = append(hm.Regex, &HostsMapEntry{
			Key:   base,
			Value: value,
		})
	}
}

// AppendPath ...
func (hm *HostsMap) AppendPath(path, id string) {
	// always use case insensitive match
	path = strings.ToLower(path)
	hm.Match = append(hm.Match, &HostsMapEntry{
		Key:   path,
		Value: id,
	})
	sort.SliceStable(hm.Match, func(i, j int) bool {
		return hm.Match[i].Key > hm.Match[j].Key
	})
}

// AppendItem adds a generic item to the HostsMap.
func (hm *HostsMap) AppendItem(item string) {
	hm.Match = append(hm.Match, &HostsMapEntry{
		Key: item,
	})
}

// HasRegex ...
func (hm *HostsMap) HasRegex() bool {
	return len(hm.Regex) > 0
}

// HasHost ...
func (hm *HostsMap) HasHost() bool {
	return len(hm.Regex) > 0 || len(hm.Match) > 0
}

// CreateMaps ...
func CreateMaps() *HostsMaps {
	return &HostsMaps{}
}

// AddMap ...
func (hm *HostsMaps) AddMap(filename string) *HostsMap {
	matchFile := filename
	regexFile := strings.Replace(filename, ".", "_regex.", 1)
	hmap := &HostsMap{
		MatchFile: matchFile,
		RegexFile: regexFile,
	}
	hm.Items = append(hm.Items, hmap)
	return hmap
}

// HasMaxBody ...
func (fg *FrontendGroup) HasMaxBody() bool {
	return fg.MaxBodySizeMap.HasHost()
}

// String ...
func (f *Frontend) String() string {
	return fmt.Sprintf("%+v", *f)
}
