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
	"fmt"
	"sort"
	"strings"
	"testing"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/kylelemons/godebug/diff"
)

func TestTrack(t *testing.T) {
	ing1 := convtypes.TrackingRef{Context: "ingress", UniqueName: "default/ing1"}
	ing2 := convtypes.TrackingRef{Context: "ingress", UniqueName: "default/ing2"}
	ing3 := convtypes.TrackingRef{Context: "ingress", UniqueName: "default/ing3"}
	back1 := convtypes.TrackingRef{Context: "backend", UniqueName: "default_echo1_8080"}
	back2 := convtypes.TrackingRef{Context: "backend", UniqueName: "default_echo2_8080"}
	back3 := convtypes.TrackingRef{Context: "backend", UniqueName: "default_echo3_8080"}
	back4 := convtypes.TrackingRef{Context: "backend", UniqueName: "default_echo4_8080"}
	back5 := convtypes.TrackingRef{Context: "backend", UniqueName: "default_echo5_8080"}
	back6 := convtypes.TrackingRef{Context: "backend", UniqueName: "default_echo6_8080"}

	cfgBefore1 := `
backend
  default_echo1_8080
    ingress:default/ing1
  default_echo2_8080
    ingress:default/ing1
  default_echo3_8080
    ingress:default/ing2
  default_echo4_8080
    ingress:default/ing2
  default_echo5_8080
    ingress:default/ing3
  default_echo6_8080
    ingress:default/ing3
ingress
  default/ing1
    backend:default_echo1_8080
    backend:default_echo2_8080
  default/ing2
    backend:default_echo3_8080
    backend:default_echo4_8080
  default/ing3
    backend:default_echo5_8080
    backend:default_echo6_8080
`
	cfgAfter1 := `
backend
  default_echo5_8080
    ingress:default/ing3
  default_echo6_8080
    ingress:default/ing3
ingress
  default/ing3
    backend:default_echo5_8080
    backend:default_echo6_8080
`
	cfgLinks1 := `
backend
  default_echo1_8080
  default_echo2_8080
  default_echo3_8080
  default_echo4_8080
ingress
  default/ing1
  default/ing2
`

	type refs struct {
		left  convtypes.TrackingRef
		right convtypes.TrackingRef
	}
	type refname struct {
		left         []convtypes.TrackingRef
		rightContext convtypes.ResourceType
		rightName    string
	}
	type names struct {
		leftContext  convtypes.ResourceType
		leftName     string
		rightContext convtypes.ResourceType
		rightName    string
	}

	testCases := []struct {
		trackingRefs      []refs
		trackingRefName   []refname
		trackingNames     []names
		queryContext      convtypes.ResourceType
		queryNames        []string
		preserveMatches   bool
		clearAfter        bool
		expTrackingBefore string
		expTrackingAfter  string
		expOutputLinks    string
	}{
		// 0
		{},
		// 1
		{
			queryContext: ing1.Context,
			queryNames:   []string{ing1.UniqueName},
		},
		// 2
		{
			trackingRefs: []refs{
				{ing1, convtypes.TrackingRef{}},
			},
		},
		// 3
		{
			trackingRefs: []refs{
				{ing1, ing1},
			},
			queryContext:    ing1.Context,
			queryNames:      []string{ing1.UniqueName},
			preserveMatches: true,
			expTrackingBefore: `
ingress
  default/ing1
    ingress:default/ing1
`,
			expTrackingAfter: `
ingress
  default/ing1
    ingress:default/ing1
`,
			expOutputLinks: `
ingress
  default/ing1
`,
		},
		// 4
		{
			trackingRefs: []refs{
				{ing1, ing1},
			},
			queryContext: ing1.Context,
			queryNames:   []string{ing1.UniqueName},
			clearAfter:   true,
			expTrackingBefore: `
ingress
  default/ing1
    ingress:default/ing1
`,
			expTrackingAfter: ``,
			expOutputLinks: `
ingress
  default/ing1
`,
		},
		// 5
		{
			trackingRefs: []refs{
				{ing1, ing1},
			},
			queryContext: ing1.Context,
			queryNames:   []string{ing1.UniqueName},
			expTrackingBefore: `
ingress
  default/ing1
    ingress:default/ing1
`,
			expTrackingAfter: `
ingress
`,
			expOutputLinks: `
ingress
  default/ing1
`,
		},
		// 6
		{
			trackingRefs: []refs{
				{ing1, ing1},
			},
			queryContext: ing2.Context,
			queryNames:   []string{ing2.UniqueName},
			expTrackingBefore: `
ingress
  default/ing1
    ingress:default/ing1
`,
			expTrackingAfter: `
ingress
  default/ing1
    ingress:default/ing1
`,
			expOutputLinks: ``,
		},
		// 7
		{
			trackingRefs: []refs{
				{ing1, back1},
				{back1, ing2},
				{ing2, back2},
				{back2, ing1},
			},
			queryContext: ing1.Context,
			queryNames:   []string{ing1.UniqueName},
			expTrackingBefore: `
backend
  default_echo1_8080
    ingress:default/ing1
    ingress:default/ing2
  default_echo2_8080
    ingress:default/ing1
    ingress:default/ing2
ingress
  default/ing1
    backend:default_echo1_8080
    backend:default_echo2_8080
  default/ing2
    backend:default_echo1_8080
    backend:default_echo2_8080
`,
			expTrackingAfter: `
backend
ingress
`,
			expOutputLinks: `
backend
  default_echo1_8080
  default_echo2_8080
ingress
  default/ing1
  default/ing2
`,
		},
		// 8
		{
			trackingRefs: []refs{
				{ing1, back1},
				{ing1, back2},
				{ing2, back3},
			},
			queryContext: ing1.Context,
			queryNames:   []string{ing1.UniqueName},
			expTrackingBefore: `
backend
  default_echo1_8080
    ingress:default/ing1
  default_echo2_8080
    ingress:default/ing1
  default_echo3_8080
    ingress:default/ing2
ingress
  default/ing1
    backend:default_echo1_8080
    backend:default_echo2_8080
  default/ing2
    backend:default_echo3_8080
`,
			expTrackingAfter: `
backend
  default_echo3_8080
    ingress:default/ing2
ingress
  default/ing2
    backend:default_echo3_8080
`,
			expOutputLinks: `
backend
  default_echo1_8080
  default_echo2_8080
ingress
  default/ing1
`,
		},
		// 9
		{
			trackingRefs: []refs{
				{ing1, back1},
				{ing1, back2},
				{ing2, back3},
				{ing2, back4},
				{ing3, back5},
				{ing3, back6},
			},
			queryContext:      ing1.Context,
			queryNames:        []string{ing1.UniqueName, ing2.UniqueName},
			expTrackingBefore: cfgBefore1,
			expTrackingAfter:  cfgAfter1,
			expOutputLinks:    cfgLinks1,
		},
		// 10
		{
			trackingRefs: []refs{
				{ing1, back1},
				{ing2, back3},
			},
			trackingRefName: []refname{
				{[]convtypes.TrackingRef{ing1}, back2.Context, back2.UniqueName},
				{[]convtypes.TrackingRef{ing2}, back4.Context, back4.UniqueName},
			},
			trackingNames: []names{
				{ing3.Context, ing3.UniqueName, back5.Context, back5.UniqueName},
				{ing3.Context, ing3.UniqueName, back6.Context, back6.UniqueName},
			},
			queryContext:      ing1.Context,
			queryNames:        []string{ing1.UniqueName, ing2.UniqueName},
			expTrackingBefore: cfgBefore1,
			expTrackingAfter:  cfgAfter1,
			expOutputLinks:    cfgLinks1,
		},
	}
	for i, test := range testCases {
		c := setup(t)
		for _, t := range test.trackingRefs {
			c.tracker.TrackRefs(t.left, t.right)
		}
		for _, t := range test.trackingRefName {
			c.tracker.TrackRefName(t.left, t.rightContext, t.rightName)
		}
		for _, t := range test.trackingNames {
			c.tracker.TrackNames(t.leftContext, t.leftName, t.rightContext, t.rightName)
		}
		c.compareTrackingMap(i, test.expTrackingBefore)
		links := c.tracker.QueryLinks(convtypes.TrackingLinks{
			test.queryContext: test.queryNames,
		}, !test.preserveMatches)
		if test.clearAfter {
			c.tracker.ClearLinks()
		}
		c.compareTrackingMap(i, test.expTrackingAfter)
		c.compareOutputLinks(i, links, test.expOutputLinks)
		c.teardown()
	}
}

type testConfig struct {
	t       *testing.T
	tracker *tracker
}

func setup(t *testing.T) *testConfig {
	return &testConfig{
		t:       t,
		tracker: NewTracker().(*tracker),
	}
}

func (c *testConfig) teardown() {
}

func (c *testConfig) compareTrackingMap(i int, expected string) {
	actual := trackingMap2string(c.tracker)
	c.compareText(i, actual, expected)
}

func (c *testConfig) compareOutputLinks(i int, links convtypes.TrackingLinks, expected string) {
	actual := outputlinks2string(links)
	c.compareText(i, actual, expected)
}

func (c *testConfig) compareText(i int, actual, expected string) {
	txt1 := "\n" + strings.Trim(expected, "\n")
	txt2 := "\n" + strings.Trim(actual, "\n")
	if txt1 != txt2 {
		c.t.Errorf("diff on %d:%s", i, diff.Diff(txt1, txt2))
	}
}

func trackingMap2string(tracker *tracker) string {
	tracking := tracker.tracking
	context := make([]convtypes.ResourceType, 0, len(tracking))
	for ctx := range tracking {
		context = append(context, ctx)
	}
	sort.Slice(context, func(i, j int) bool {
		return context[i] < context[j]
	})
	out := "\n"
	for _, ctx := range context {
		out += fmt.Sprintf("%s\n", ctx)
		refs := tracking[ctx]
		names := make([]string, 0, len(refs))
		for name := range refs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out += fmt.Sprintf("  %s\n", name)
			targets := refs[name]
			targetrefs := make([]convtypes.TrackingRef, 0, len(targets))
			for t := range targets {
				targetrefs = append(targetrefs, t)
			}
			sort.Slice(targetrefs, func(i, j int) bool {
				t1 := targetrefs[i]
				t2 := targetrefs[j]
				if t1.Context == t2.Context {
					return t1.UniqueName < t2.UniqueName
				}
				return t1.Context < t2.Context
			})
			for _, t := range targetrefs {
				out += fmt.Sprintf("    %s:%s\n", t.Context, t.UniqueName)
			}
		}
	}
	return out
}

func outputlinks2string(links convtypes.TrackingLinks) string {
	context := make([]convtypes.ResourceType, 0, len(links))
	for ctx := range links {
		context = append(context, ctx)
	}
	sort.Slice(context, func(i, j int) bool {
		return context[i] < context[j]
	})
	out := "\n"
	for _, ctx := range context {
		refs := links[ctx]
		sort.Strings(refs)
		out += fmt.Sprintf("%s\n", ctx)
		for _, r := range refs {
			out += fmt.Sprintf("  %s\n", r)
		}
	}
	return out
}
