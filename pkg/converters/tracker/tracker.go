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
	"slices"
	"sort"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

// NewTracker ...
func NewTracker() convtypes.Tracker {
	return &tracker{
		tracking: trackingMap{},
	}
}

type link struct{}
type trackingMap map[convtypes.ResourceType]map[string]map[convtypes.TrackingRef]link

type tracker struct {
	tracking trackingMap
}

func TrackChanges(links convtypes.TrackingLinks, context convtypes.ResourceType, fullname string) {
	if llink := links[context]; !slices.Contains(llink, fullname) {
		links[context] = append(llink, fullname)
	}
}

func (t *tracker) TrackNames(leftContext convtypes.ResourceType, leftName string, rightContext convtypes.ResourceType, rightName string) {
	t.TrackRefs(
		convtypes.TrackingRef{Context: leftContext, UniqueName: leftName},
		convtypes.TrackingRef{Context: rightContext, UniqueName: rightName},
	)
}

func (t *tracker) TrackRefName(left []convtypes.TrackingRef, rightContext convtypes.ResourceType, rightName string) {
	for _, track := range left {
		t.TrackRefs(track, convtypes.TrackingRef{Context: rightContext, UniqueName: rightName})
	}
}

var emptyRef convtypes.TrackingRef = convtypes.TrackingRef{}

func (t *tracker) TrackRefs(left, right convtypes.TrackingRef) {
	if left == emptyRef || right == emptyRef {
		return
	}
	t.track(&left, &right)
	t.track(&right, &left)
}

func (t *tracker) track(dest, source *convtypes.TrackingRef) {
	names, found := t.tracking[dest.Context]
	if !found {
		names = map[string]map[convtypes.TrackingRef]link{}
		t.tracking[dest.Context] = names
	}
	refs, found := names[dest.UniqueName]
	if !found {
		refs = map[convtypes.TrackingRef]link{}
		names[dest.UniqueName] = refs
	}
	refs[*source] = link{}
}

// QueryLinks recursively lists all resource IDs that a list of input
// resources are linked to, and remove the input IDs from the maps
func (t *tracker) QueryLinks(input convtypes.TrackingLinks, removeMatches bool) convtypes.TrackingLinks {
	outputrefs := map[convtypes.ResourceType]map[string]link{}
	var updateOutput func(convtypes.ResourceType, []string)
	updateOutput = func(ctx convtypes.ResourceType, namelist []string) {
		if refs, found := t.tracking[ctx]; found {
			for _, name := range namelist {
				for ref := range refs[name] {
					outputlist, found := outputrefs[ref.Context]
					if !found {
						outputlist = map[string]link{}
						outputrefs[ref.Context] = outputlist
					}
					if _, found := outputlist[ref.UniqueName]; !found {
						outputlist[ref.UniqueName] = link{}
						updateOutput(ref.Context, []string{ref.UniqueName})
					}
				}
			}
		}
	}
	for ctx, namelist := range input {
		updateOutput(ctx, namelist)
	}
	output := map[convtypes.ResourceType][]string{}
	for ctx, idmap := range outputrefs {
		idlist := make([]string, 0, len(idmap))
		for id := range idmap {
			idlist = append(idlist, id)
			if removeMatches {
				t.removeRef(ctx, id)
			}
		}
		sort.Strings(idlist)
		output[ctx] = idlist
	}
	return output
}

func (t *tracker) ClearLinks() {
	t.tracking = trackingMap{}
}

func (t *tracker) removeRef(ctx convtypes.ResourceType, name string) {
	if refs, found := t.tracking[ctx]; found {
		n := refs[name]
		delete(refs, name)
		for ref := range n {
			t.removeRef(ref.Context, ref.UniqueName)
		}
	}
}
