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
	"reflect"
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
	hm.addHostnameMappingMatch(hostname, target, MatchExact)
}

// AddHostnameMappingRegex ...
func (hm *HostsMap) AddHostnameMappingRegex(hostname, target string) {
	hm.addHostnameMappingMatch(hostname, target, MatchRegex)
}

func (hm *HostsMap) addHostnameMappingMatch(hostname, target string, match MatchType) {
	if match != MatchRegex {
		var hasWildcard bool
		if hostname, hasWildcard = convertWildcardToRegex(hostname); hasWildcard {
			match = MatchRegex
		}
	}
	hm.addTarget(hostname, "", nil, 0, target, match)
}

// AddHostnamePathMapping ...
func (hm *HostsMap) AddHostnamePathMapping(hostname string, path *Path, target string) {
	hostname, hasWildcard := convertWildcardToRegex(hostname)
	strpath := path.Path()
	match := path.Match()
	// TODO paths of a wildcard hostname will always have less precedence
	// despite the match type because the whole hostname+path will fill a
	// MatchRegex map, which has the lesser precedence in the template.
	if hasWildcard {
		strpath = convertPathToRegex(path)
		match = MatchRegex
	} else if match == MatchRegex {
		hostname = "^" + regexp.QuoteMeta(hostname) + "$"
	}
	hm.addTarget(hostname, strpath, path.Link.headers, path.order, target, match)
}

// AddAliasPathMapping ...
func (hm *HostsMap) AddAliasPathMapping(alias HostAliasConfig, path *Path, target string) {
	if alias.AliasName != "" {
		hm.AddHostnamePathMapping(alias.AliasName, path, target)
	}
	if alias.AliasRegex != "" {
		pathstr := convertPathToRegex(path)
		hm.addTarget(alias.AliasRegex, pathstr, path.Link.headers, path.order, target, MatchRegex)
	}
}

func convertWildcardToRegex(hostname string) (h string, hasWildcard bool) {
	if !strings.HasPrefix(hostname, "*.") {
		return hostname, false
	}
	return "^[^.]+" + regexp.QuoteMeta(hostname[1:]) + "$", true
}

// convertPathToRegex converts a path of any match type that
// needs to be added to a regex list, eg when an alias regex
// or a wildcard hostname is used.
//
// regex has an implicit starting `^` char due to ingress path
// validation - paths need to start with a slash. There is no
// implicit `$`, so regex behaves pretty much like `begin`.
func convertPathToRegex(path *Path) string {
	strpath := path.Path()
	switch path.Match() {
	case MatchBegin:
		return regexp.QuoteMeta(strpath)
	case MatchExact:
		return regexp.QuoteMeta(strpath) + "$"
	case MatchPrefix:
		strpath = regexp.QuoteMeta(strpath)
		if strings.HasSuffix(strpath, "/") {
			return strpath
		}
		return strpath + "(/.*)?"
	case MatchRegex:
		return strpath
	}
	panic("unsupported match type")
}

func (hm *HostsMap) addTarget(hostname, path string, headers []HTTPMatch, order int, target string, match MatchType) {
	hostname = strings.ToLower(hostname)
	if match == MatchBegin {
		// this is the only match that uses case-insensitive path
		path = strings.ToLower(path)
	}
	entry := &HostsMapEntry{
		hostname: hostname,
		path:     path,
		match:    match,
		headers:  headers,
		order:    order,
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
	listWithFilters := list.New()
	order := list.New()

	// Iterates over all the raw map entries, looking for extra map files
	// that should be created. overlaps() defines if two entries
	// should be placed on distinct maps due to overlap or extra filters.
	for _, entryList := range hm.rawhosts {
		// priorities should be processed first:
		// - /sub/dir need to be processed before /sub
		// - with-filters need to be processed before without-filters
		sort.Slice(entryList, func(i, j int) bool {
			e1 := entryList[i]
			e2 := entryList[j]
			if e1.headers.equals(e2.headers) {
				return e1.path > e2.path
			}
			return e1.hasFilter()
		})
		if len(entryList) == 1 {
			e1 := entryList[0]
			if e1.hasFilter() {
				_ = findOrCreateMatchFile(listWithFilters, e1)
			}
		}
		for i, e1 := range entryList {
			f1 := e1.hasFilter()
			for _, e2 := range entryList[i+1:] {
				f2 := e2.hasFilter()
				if !f1 && !f2 {
					// Both e1 and e2 does not have filter, so they share the same list, `order`
					findOrCreateMatchFileIfOverlaps(order, e1, e2)
				} else {
					// either e1 or e2 have filter and entries with filter should always be moved to a new match.
					// move either or both (if f[12]) if not moved yet (_elem == nil).
					if f1 && e1._elem == nil {
						_ = findOrCreateMatchFile(listWithFilters, e1)
					}
					if f2 && e2._elem == nil {
						_ = findOrCreateMatchFile(listWithFilters, e2)
					}
				}
			}
		}
	}

	// Create the default match files. All the entries without overlap or filters
	// will be placed here. Other entries were already removed and placed on new
	// map files created in the former for-loop
	for _, match := range hm.matchOrder {
		matchFile := hm.rawfiles[match]
		if matchFile != nil {
			matchFile.shrink()
			if len(matchFile.entries) > 0 {
				if matchFile.match == MatchExact {
					// exact match is always processed first - it never overlaps if checked first, and it's faster.
					// we could respect the match order configured by the sysadmin and split in more map files if
					// a begin or prefix overlaps, but this doesn't make sense - it would create an even
					// more complex group of match files which would run slower for nothing.
					order.PushFront(matchFile)
				} else {
					// ordinary match files are processed with less priority, in the order
					// defined by matchOrder, `path-type-order`, except for `exact` which
					// always have priority
					order.PushBack(matchFile)
				}
			}
		}
	}

	// Add entries with filters as high priority and create
	// the final []matchFiles in the correct order.
	order.PushFrontList(listWithFilters)
	matchFiles = make([]*MatchFile, 0, order.Len())
	var i int
	for e := order.Front(); e != nil; e = e.Next() {
		i++
		matchFile := e.Value.(*hostsMapMatchFile)
		var suffix string
		if matchFile.priority {
			suffix = fmt.Sprintf("__%s_%02d", matchFile.match, i)
		} else {
			suffix = fmt.Sprintf("__%s", matchFile.match)
		}
		matchFile.sort()
		matchFiles = append(matchFiles, &MatchFile{
			matchFile: matchFile,
			filename:  strings.Replace(hm.basename, ".", suffix+".", 1),
			first:     i == 1,
			last:      false,
		})
	}
	if len(matchFiles) > 0 {
		matchFiles[len(matchFiles)-1].last = true
	}
	return matchFiles
}

// Checks if two hostmap entries overlaps
// A hostmap entry is a path and its match type from a hostname
// An overlap happens when /app/sub and a /app belongs to the same
// hostname and has distinct match types
// Exact is removed from the check because it always has priority and never overlaps
// Regex is removed because all of its entries are processed together, giving priority to longer regexps
func overlaps(e1, e2 *HostsMapEntry) bool {
	return e1.match != e2.match &&
		e1.path != e2.path &&
		e1.match != MatchExact && e2.match != MatchExact &&
		e1.match != MatchRegex && e2.match != MatchRegex &&
		strings.HasPrefix(e1.path, e2.path)
}

func findOrCreateMatchFileIfOverlaps(order *list.List, e1, e2 *HostsMapEntry) {
	if overlaps(e1, e2) || !e1.hasSameFilter(e2) {
		el1 := e1._elem
		if el1 == nil {
			el1 = findOrCreateMatchFile(order, e1)
		}
		e2._upper = el1
	}
}

func findOrCreateMatchFile(order *list.List, e1 *HostsMapEntry) *list.Element {
	matchFile, element := findMatchFile(order, e1)
	if element == nil {
		matchFile = &hostsMapMatchFile{
			match:    e1.match,
			headers:  e1.headers,
			priority: true,
		}
		element = order.PushBack(matchFile)
	}
	matchFile.entries = append(matchFile.entries, e1)
	e1._elem = element
	return element
}

func findMatchFile(order *list.List, e1 *HostsMapEntry) (matchFile *hostsMapMatchFile, element *list.Element) {
	starting := e1._upper
	if starting == nil {
		starting = order.Front()
	}
	for element = starting; element != nil; element = element.Next() {
		matchFile = element.Value.(*hostsMapMatchFile)
		if matchFile.match == e1.match && matchFile.headers.equals(e1.headers) {
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
	switch mf.match {
	case MatchExact:
		// Ascending order of the keys
		sort.Slice(mf.entries, func(i, j int) bool {
			v1 := mf.entries[i]
			v2 := mf.entries[j]
			if v1.Key == v2.Key {
				return v1.order < v2.order
			}
			return v1.Key < v2.Key
		})
	case MatchRegex:
		// Keep regexes in order from most to least specific, based on rule length
		sort.Slice(mf.entries, func(i, j int) bool {
			k1 := mf.entries[i].Key
			k2 := mf.entries[j].Key
			if len(k1) != len(k2) {
				return len(k1) > len(k2)
			}
			if k1 == k2 {
				return mf.entries[i].order < mf.entries[j].order
			}
			return k1 < k2
		})
	default:
		// Ascending order of hostnames and reverse order of paths within the same hostname
		sort.Slice(mf.entries, func(i, j int) bool {
			v1 := mf.entries[i]
			v2 := mf.entries[j]
			if v1.hostname == v2.hostname {
				if v1.path == v2.path {
					return v1.order < v2.order
				}
				return v1.path > v2.path
			}
			return v1.Key < v2.Key
		})
	}
}

func (mf *hostsMapMatchFile) lower() bool {
	return mf.match == MatchBegin
}

func (mf *hostsMapMatchFile) method() string {
	return haMatchMethod(mf.match)
}

func haMatchMethod(match MatchType) string {
	switch match {
	case MatchExact:
		return "str"
	case MatchPrefix:
		return "dir"
	case MatchBegin:
		return "beg"
	case MatchRegex:
		return "reg"
	}
	panic(fmt.Errorf("unsupported match type: %s", match))
}

// Filename ...
func (m MatchFile) Filename() string {
	return m.filename
}

// First ...
func (m MatchFile) First() bool {
	return m.first
}

// Last ...
func (m MatchFile) Last() bool {
	return m.last
}

// Lower ...
func (m MatchFile) Lower() bool {
	return m.matchFile.lower()
}

// Method ...
func (m MatchFile) Method() string {
	return m.matchFile.method()
}

// Headers ...
func (m MatchFile) Headers() HTTPHeaderMatch {
	return m.matchFile.headers
}

// Values ...
func (m MatchFile) Values() []*HostsMapEntry {
	return m.matchFile.entries
}

func (he *HostsMapEntry) hasFilter() bool {
	return he.headers != nil
}

func (he *HostsMapEntry) hasSameFilter(other *HostsMapEntry) bool {
	return he.headers.equals(other.headers)
}

func (h HTTPHeaderMatch) equals(other HTTPHeaderMatch) bool {
	return reflect.DeepEqual(h, other)
}

func (he *HostsMapEntry) String() string {
	return fmt.Sprintf("%+v", *he)
}
