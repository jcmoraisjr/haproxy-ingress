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

package types

import (
	"container/list"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CreateMaps ...
func CreateMaps(matchOrder []MatchType) *HostsMaps {
	return &HostsMaps{
		matchOrder: matchOrder,
	}
}

// AddMap ...
func (hm *HostsMaps) AddMap(basename string) *HostsMap {
	hmap := &HostsMap{
		basename:   basename,
		matchOrder: hm.matchOrder,
		rawhosts:   map[string][]*HostsMapEntry{},
		rawfiles:   map[MatchType]*hostsMapMatchFile{},
	}
	hm.Items = append(hm.Items, hmap)
	return hmap
}

// AddHostnameMapping ...
func (hm *HostsMap) AddHostnameMapping(hostname, target string) {
	hostname, hasWildcard := convertWildcardToRegex(hostname)
	if hasWildcard {
		hm.addTarget(hostname, "", target, MatchRegex)
	} else {
		hm.addTarget(hostname, "", target, MatchExact)
	}
}

// AddHostnamePathMapping ...
func (hm *HostsMap) AddHostnamePathMapping(hostname string, hostPath *HostPath, target string) {
	hostname, hasWildcard := convertWildcardToRegex(hostname)
	path := hostPath.Path
	match := hostPath.Match
	// TODO paths of a wildcard hostname will always have less precedence
	// despite the match type because the whole hostname+path will fill a
	// MatchRegex map, which has the lesser precedence in the template.
	if hasWildcard {
		path = convertPathToRegex(hostPath)
		match = MatchRegex
	} else if hostPath.Match == MatchRegex {
		hostname = "^" + regexp.QuoteMeta(hostname) + "$"
	}
	hm.addTarget(hostname, path, target, match)
}

// AddAliasPathMapping ...
func (hm *HostsMap) AddAliasPathMapping(alias HostAliasConfig, path *HostPath, target string) {
	if alias.AliasName != "" {
		hm.AddHostnamePathMapping(alias.AliasName, path, target)
	}
	if alias.AliasRegex != "" {
		pathstr := convertPathToRegex(path)
		hm.addTarget(alias.AliasRegex, pathstr, target, MatchRegex)
	}
}

func convertWildcardToRegex(hostname string) (h string, hasWildcard bool) {
	if !strings.HasPrefix(hostname, "*.") {
		return hostname, false
	}
	return "^[^.]+" + regexp.QuoteMeta(hostname[1:]) + "$", true
}

// convertPathToRegex converts a path of any match type that
// needs to be added to a regex list, eg when a alias regex
// or a wildcard hostname is used.
//
// regex has an implicit starting `^` char due to ingress path
// validation - paths need to start with a slash. There is no
// implicit `$`, so regex behaves pretty much like `begin`.
func convertPathToRegex(hostPath *HostPath) string {
	switch hostPath.Match {
	case MatchBegin:
		return regexp.QuoteMeta(hostPath.Path)
	case MatchExact:
		return regexp.QuoteMeta(hostPath.Path) + "$"
	case MatchPrefix:
		path := regexp.QuoteMeta(hostPath.Path)
		if strings.HasSuffix(path, "/") {
			return path
		}
		return path + "(/.*)?"
	case MatchRegex:
		return hostPath.Path
	}
	panic("unsupported match type")
}

func (hm *HostsMap) addTarget(hostname, path, target string, match MatchType) {
	hostname = strings.ToLower(hostname)
	if match == MatchBegin {
		// this is the only match that uses case insensitive path
		path = strings.ToLower(path)
	}
	entry := &HostsMapEntry{
		hostname: hostname,
		path:     path,
		match:    match,
		Key:      buildMapKey(match, hostname, path),
		Value:    target,
	}
	matchFile := hm.rawfiles[match]
	if matchFile == nil {
		matchFile = &hostsMapMatchFile{match: match}
		hm.rawfiles[match] = matchFile
	}
	matchFile.entries = append(matchFile.entries, entry)
	hm.rawhosts[hostname] = append(hm.rawhosts[hostname], entry)
	hm.matchFiles = nil
}

func buildMapKey(match MatchType, hostname, path string) string {
	if match == MatchRegex && hostname != "" && path != "" {
		// we support hostname with ^/$ boundaries
		// lets change the ending of the hostname
		// in order to give the expected behavior.
		if strings.HasSuffix(hostname, "$") {
			hostname = hostname[:len(hostname)-1]
		} else {
			hostname = hostname + "[^/]*"
		}
	}
	if hostname != "" && path != "" {
		// Fixes dir match type (Prefix from the ingress pathType) if a path or
		// subpath matches a configured domain. Eg, this map:
		//
		//   domain.local/ backend1
		//   sub.domain.local/ backend2
		//
		// and this request:
		//
		//   sub.domain.local/domain.local
		//
		// backend2 would be chosen on beg and reg match types, but backend1
		// would be chosen if dir was used.
		//
		// The default hostname adds a hostname as well due to how map_dir()
		// converter behaves in HAProxy:
		//
		//   /
		//   <default>#/
		//
		// the former pattern doesn't match `/app` but it should, so the
		// hostname part is added which will make the later pattern match
		// with `<default>#/app`
		return hostname + "#" + path
	}
	return hostname + path
}

// MatchFiles ...
func (hm *HostsMap) MatchFiles() []*MatchFile {
	if len(hm.matchFiles) == 0 {
		hm.matchFiles = hm.rebuildMatchFiles()
	}
	return hm.matchFiles
}

func (hm *HostsMap) rebuildMatchFiles() (matchFiles []*MatchFile) {
	order := &list.List{}
	for _, entryList := range hm.rawhosts {
		// /sub/dir need to be processed before /sub
		sort.Slice(entryList, func(i, j int) bool {
			return entryList[i].path > entryList[j].path
		})
		for i, e1 := range entryList {
			if i < len(entryList) {
				for _, e2 := range entryList[i+1:] {
					// TODO regex is currently always the last match
					if e1.match != e2.match && e1.match != MatchRegex && e2.match != MatchRegex && strings.HasPrefix(e1.path, e2.path) {
						// here we have an overlap and distinct match files
						// separate the entry that should be processed first
						// into a match file with higher priority
						el1 := e1._elem
						if el1 == nil {
							var m1 *hostsMapMatchFile
							m1, el1 = findOrCreateMatchFile(order, e1.match, e1._upper, e2._elem)
							m1.entries = append(m1.entries, e1)
							e1._elem = el1
						}
						e2._upper = el1
					}
				}
			}
		}
	}
	orderCnt := order.Len()
	for _, match := range hm.matchOrder {
		matchFile := hm.rawfiles[match]
		if matchFile != nil {
			matchFile.shrink()
			if len(matchFile.entries) > 0 {
				order.PushBack(matchFile)
			}
		}
	}
	matchFiles = make([]*MatchFile, 0, order.Len())
	var i int
	for e := order.Front(); e != nil; e = e.Next() {
		i++
		matchFile := e.Value.(*hostsMapMatchFile)
		var suffix string
		if i <= orderCnt {
			suffix = fmt.Sprintf("__%s_%02d", matchFile.match, i)
		} else {
			suffix = fmt.Sprintf("__%s", matchFile.match)
		}
		matchFile.sort()
		matchFiles = append(matchFiles, &MatchFile{
			matchFile: matchFile,
			filename:  strings.Replace(hm.basename, ".", suffix+".", 1),
			first:     i == 1,
		})
	}
	return matchFiles
}

func findOrCreateMatchFile(order *list.List, match MatchType, starting, limit *list.Element) (matchFile *hostsMapMatchFile, element *list.Element) {
	matchFile, element = findMatchFile(order, match, starting, limit)
	if element == nil {
		matchFile = &hostsMapMatchFile{match: match}
		if limit == nil {
			element = order.PushBack(matchFile)
		} else {
			element = order.InsertBefore(matchFile, limit)
		}
	}
	return matchFile, element
}

func findMatchFile(order *list.List, match MatchType, starting, limit *list.Element) (matchFile *hostsMapMatchFile, element *list.Element) {
	if starting == nil {
		starting = order.Front()
	}
	for element = starting; element != limit; element = element.Next() {
		matchFile = element.Value.(*hostsMapMatchFile)
		if matchFile.match == match {
			return matchFile, element
		}
	}
	return nil, nil
}

// HasHost ...
func (hm *HostsMap) HasHost() bool {
	for _, matchFile := range hm.rawfiles {
		if len(matchFile.entries) > 0 {
			return true
		}
	}
	return false
}

func (mf *hostsMapMatchFile) shrink() {
	e := mf.entries
	l := len(e)
	for i := l - 1; i >= 0; i-- {
		if e[i]._elem != nil {
			l--
			e[i] = e[l]
		}
	}
	mf.entries = e[:l]
}

func (mf *hostsMapMatchFile) sort() {
	if mf.match == MatchRegex {
		// Keep regexes in order from most to least specific, based on rule length
		sort.Slice(mf.entries, func(i, j int) bool {
			k1 := mf.entries[i].Key
			k2 := mf.entries[j].Key
			if len(k1) != len(k2) {
				return len(k1) > len(k2)
			}
			return k1 < k2
		})
	} else {
		// Ascending order of hostnames and reverse order of paths within the same hostname
		sort.Slice(mf.entries, func(i, j int) bool {
			v1 := mf.entries[i]
			v2 := mf.entries[j]
			if v1.hostname == v2.hostname {
				return v1.path > v2.path
			}
			return v1.Key < v2.Key
		})
	}
}

func (mf *hostsMapMatchFile) lower() bool {
	if mf.match == MatchBegin {
		return true
	}
	return false
}

func (mf *hostsMapMatchFile) method() string {
	switch mf.match {
	case MatchExact:
		return "str"
	case MatchPrefix:
		return "dir"
	case MatchBegin:
		return "beg"
	case MatchRegex:
		return "reg"
	}
	panic(fmt.Errorf("unsupported match type: %s", mf.match))
}

// Filename ...
func (m MatchFile) Filename() string {
	return m.filename
}

// First ...
func (m MatchFile) First() bool {
	return m.first
}

// Lower ...
func (m MatchFile) Lower() bool {
	return m.matchFile.lower()
}

// Method ...
func (m MatchFile) Method() string {
	return m.matchFile.method()
}

// Values ...
func (m MatchFile) Values() []*HostsMapEntry {
	return m.matchFile.entries
}

func (he *HostsMapEntry) String() string {
	return fmt.Sprintf("%+v", *he)
}
