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
	"reflect"
	"strconv"
	"strings"
	"testing"

	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	conv_helper "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/helper_test"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
)

func TestAffinity(t *testing.T) {
	testCase := []struct {
		annDefault map[string]string
		ann        map[string]string
		expCookie  hatypes.Cookie
		expLogging string
	}{
		// 0
		{
			ann:        map[string]string{},
			expLogging: "",
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.BackAffinity: "no",
			},
			expLogging: "ERROR unsupported affinity type on ingress 'default/ing1': no",
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.BackAffinity: "cookie",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert"},
			expLogging: "",
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.BackAffinity:          "cookie",
				ingtypes.BackSessionCookieName: "ing",
			},
			expCookie:  hatypes.Cookie{Name: "ing", Strategy: "insert"},
			expLogging: "",
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieStrategy: "err",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert"},
			expLogging: "WARN invalid affinity cookie strategy 'err' on ingress 'default/ing1', using 'insert' instead",
		},
		// 5
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieStrategy: "rewrite",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "rewrite"},
			expLogging: "",
		},
		// 6
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieStrategy: "prefix",
				ingtypes.BackSessionCookieDynamic:  "true",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "prefix", Dynamic: true},
			expLogging: "",
		},
		// 7
		{
			ann: map[string]string{
				ingtypes.BackAffinity:             "cookie",
				ingtypes.BackSessionCookieDynamic: "false",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert", Dynamic: false},
			expLogging: "",
		},
	}

	for i, test := range testCase {
		c := setup(t)
		u := c.createUpdater()
		d := c.createBackendData("default", "ing1", test.ann, test.annDefault)
		u.buildBackendAffinity(d)
		if !reflect.DeepEqual(test.expCookie, d.backend.Cookie) {
			t.Errorf("config %d differs - expected: %+v - actual: %+v", i, test.expCookie, d.backend.Cookie)
		}
		c.logger.CompareLogging(test.expLogging)
		c.teardown()
	}
}

func TestAuthHTTP(t *testing.T) {
	testCase := []struct {
		namespace    string
		ingname      string
		annDefault   map[string]string
		ann          map[string]string
		secrets      conv_helper.SecretContent
		expUserlists []*hatypes.Userlist
		expLogging   string
	}{
		// 0
		{
			ann:        map[string]string{},
			expLogging: "",
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.BackAuthType: "fail",
			},
			expLogging: "ERROR unsupported authentication type on ingress 'default/ing1': fail",
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.BackAuthType: "basic",
			},
			expLogging: "ERROR missing secret name on basic authentication on ingress 'default/ing1'",
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "mypwd",
			},
			expLogging: "ERROR error reading basic authentication on ingress 'default/ing1': secret not found: 'default/mypwd'",
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "mypwd",
			},
			secrets:    conv_helper.SecretContent{"default/mypwd": {"xx": []byte{}}},
			expLogging: "ERROR error reading basic authentication on ingress 'default/ing1': secret 'default/mypwd' does not have file/key 'auth'",
		},
		// 5
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "mypwd",
				ingtypes.BackAuthRealm:  `"a name"`,
			},
			secrets: conv_helper.SecretContent{"default/mypwd": {"auth": []byte("usr1::clear1")}},
			expUserlists: []*hatypes.Userlist{&hatypes.Userlist{Name: "default_mypwd", Users: []hatypes.User{
				{Name: "usr1", Passwd: "clear1", Encrypted: false},
			}}},
			expLogging: "WARN ignoring auth-realm with quotes on ingress 'default/ing1'",
		},
		// 6
		{
			namespace: "ns1",
			ingname:   "i1",
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "mypwd",
			},
			secrets:      conv_helper.SecretContent{"ns1/mypwd": {"auth": []byte{}}},
			expUserlists: []*hatypes.Userlist{&hatypes.Userlist{Name: "ns1_mypwd"}},
			expLogging:   "WARN userlist on ingress 'ns1/i1' for basic authentication is empty",
		},
		// 7
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "basicpwd",
			},
			secrets:      conv_helper.SecretContent{"default/basicpwd": {"auth": []byte("fail")}},
			expUserlists: []*hatypes.Userlist{&hatypes.Userlist{Name: "default_basicpwd"}},
			expLogging: `
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'fail' line 1
WARN userlist on ingress 'default/ing1' for basic authentication is empty`,
		},
		// 8
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "basicpwd",
			},
			secrets: conv_helper.SecretContent{"default/basicpwd": {"auth": []byte(`
usr1::clearpwd1
nopwd`)}},
			expUserlists: []*hatypes.Userlist{&hatypes.Userlist{Name: "default_basicpwd", Users: []hatypes.User{
				{Name: "usr1", Passwd: "clearpwd1", Encrypted: false},
			}}},
			expLogging: "WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'nopwd' line 3",
		},
		// 9
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "basicpwd",
			},
			secrets: conv_helper.SecretContent{"default/basicpwd": {"auth": []byte(`
usrnopwd1:
usrnopwd2::
:encpwd3
::clearpwd4`)}},
			expUserlists: []*hatypes.Userlist{&hatypes.Userlist{Name: "default_basicpwd"}},
			expLogging: `
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'usrnopwd1' line 2
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'usrnopwd2' line 3
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing username line 4
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing username line 5
WARN userlist on ingress 'default/ing1' for basic authentication is empty`,
		},
		// 10
		{
			ann: map[string]string{
				ingtypes.BackAuthType:   "basic",
				ingtypes.BackAuthSecret: "basicpwd",
			},
			secrets: conv_helper.SecretContent{"default/basicpwd": {"auth": []byte(`
usr1:encpwd1
usr2::clearpwd2`)}},
			expUserlists: []*hatypes.Userlist{&hatypes.Userlist{Name: "default_basicpwd", Users: []hatypes.User{
				{Name: "usr1", Passwd: "encpwd1", Encrypted: true},
				{Name: "usr2", Passwd: "clearpwd2", Encrypted: false},
			}}},
			expLogging: "",
		},
	}

	for i, test := range testCase {
		// TODO missing expHTTPRequests
		c := setup(t)
		u := c.createUpdater()
		if test.namespace == "" {
			test.namespace = "default"
		}
		if test.ingname == "" {
			test.ingname = "ing1"
		}
		c.cache.SecretContent = test.secrets
		d := c.createBackendData(test.namespace, test.ingname, test.ann, test.annDefault)
		u.buildBackendAuthHTTP(d)
		userlists := u.haproxy.Userlists()
		if len(userlists)+len(test.expUserlists) > 0 && !reflect.DeepEqual(test.expUserlists, userlists) {
			t.Errorf("userlists config %d differs - expected: %+v - actual: %+v", i, test.expUserlists, userlists)
		}
		c.logger.CompareLogging(test.expLogging)
		c.teardown()
	}
}

func TestBlueGreen(t *testing.T) {
	buildPod := func(labels string) *api.Pod {
		l := make(map[string]string)
		for _, label := range strings.Split(labels, ",") {
			kv := strings.Split(label, "=")
			l[kv[0]] = kv[1]
		}
		return &api.Pod{
			ObjectMeta: meta.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
				Labels:    l,
			},
		}
	}
	buildAnn := func(bal, mode string) map[string]string {
		ann := map[string]string{}
		ann[ingtypes.BackBlueGreenBalance] = bal
		if mode != "" {
			ann[ingtypes.BackBlueGreenMode] = mode
		}
		return ann
	}
	buildEndpoints := func(targets string) []*hatypes.Endpoint {
		ep := []*hatypes.Endpoint{}
		if targets != "" {
			for _, targetRef := range strings.Split(targets, ",") {
				targetWeight := strings.Split(targetRef, "=")
				target := targetRef
				weight := 1
				if len(targetWeight) == 2 {
					target = targetWeight[0]
					if w, err := strconv.ParseInt(targetWeight[1], 10, 0); err == nil {
						weight = int(w)
					}
				}
				ep = append(ep, &hatypes.Endpoint{
					IP:        "172.17.0.11",
					Port:      8080,
					Weight:    weight,
					TargetRef: target,
				})
			}
		}
		return ep
	}
	pods := map[string]*api.Pod{
		"pod0101-01": buildPod("app=d01,v=1"),
		"pod0101-02": buildPod("app=d01,v=1"),
		"pod0102-01": buildPod("app=d01,v=2"),
		"pod0102-02": buildPod("app=d01,v=2"),
		"pod0102-03": buildPod("app=d01,v=2"),
		"pod0102-04": buildPod("app=d01,v=2"),
		"pod0103-01": buildPod("app=d01,v=3"),
	}
	testCase := []struct {
		annDefault map[string]string
		ann        map[string]string
		endpoints  []*hatypes.Endpoint
		expWeights []int
		expLogging string
	}{
		// 0
		{
			ann:        buildAnn("", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "",
		},
		// 1
		{
			ann:        buildAnn("", "err"),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "",
		},
		// 22
		{
			ann:        buildAnn("err", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "ERROR blue/green config on ingress 'default/ing1' has an invalid weight format: err",
		},
		// 3
		{
			ann:        buildAnn("v=1=xx", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "ERROR blue/green config on ingress 'default/ing1' has an invalid weight value: strconv.ParseInt: parsing \"xx\": invalid syntax",
		},
		// 4
		{
			ann:        buildAnn("v=1=1.5", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "ERROR blue/green config on ingress 'default/ing1' has an invalid weight value: strconv.ParseInt: parsing \"1.5\": invalid syntax",
		},
		// 5
		{
			ann:        buildAnn("v=1=-1", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{0},
			expLogging: "WARN invalid weight '-1' on ingress 'default/ing1', using '0' instead",
		},
		// 6
		{
			ann:        buildAnn("v=1=260", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "WARN invalid weight '260' on ingress 'default/ing1', using '256' instead",
		},
		// 7
		{
			ann:        buildAnn("v=1=10", "err"),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "WARN unsupported blue/green mode 'err' on ingress 'default/ing1', falling back to 'deploy'",
		},
		// 8
		{
			ann:        buildAnn("v=1=10", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{1},
			expLogging: "",
		},
		// 9
		{
			ann:        buildAnn("", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{1, 1},
			expLogging: "",
		},
		// 10
		{
			ann:        buildAnn("v=1=50,v=2=50", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{1, 1},
			expLogging: "",
		},
		// 11
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{2, 1},
			expLogging: "",
		},
		// 12
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02"),
			expWeights: []int{4, 1, 1},
			expLogging: "",
		},
		// 13
		{
			ann:        buildAnn("v=1=50,v=2=25", "pod"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02"),
			expWeights: []int{50, 25, 25},
			expLogging: "",
		},
		// 14
		{
			ann:        buildAnn("v=1=50,v=2=25", ""),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02"),
			expWeights: []int{4, 1, 1},
			expLogging: "",
		},
		// 15
		{
			ann:        buildAnn("v=1=500,v=2=2", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{128, 1},
			expLogging: "WARN invalid weight '500' on ingress 'default/ing1', using '256' instead",
		},
		// 16
		{
			ann:        buildAnn("v=1=60,v=2=3", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0102-03,pod0102-04"),
			expWeights: []int{80, 1, 1, 1, 1},
			expLogging: "",
		},
		// 17
		{
			ann:        buildAnn("v=1=70,v=2=3", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0102-03,pod0102-04"),
			expWeights: []int{256, 2, 2, 2, 2},
			expLogging: "",
		},
		// 18
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints(",pod0102-01"),
			expWeights: []int{0, 1},
			expLogging: `
WARN endpoint '172.17.0.11:8080' on ingress 'default/ing1' was removed from balance: endpoint does not reference a pod
INFO-V(3) blue/green balance label 'v=1' on ingress 'default/ing1' does not reference any endpoint`,
		},
		// 19
		{
			ann:        buildAnn("v=1=50,v=non=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{1, 0},
			expLogging: "INFO-V(3) blue/green balance label 'v=non' on ingress 'default/ing1' does not reference any endpoint",
		},
		// 20
		{
			ann:        buildAnn("v=1=50,v=non=25", "pod"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{50, 0},
			expLogging: "INFO-V(3) blue/green balance label 'v=non' on ingress 'default/ing1' does not reference any endpoint",
		},
		// 21
		{
			ann:        buildAnn("v=1=50,non=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{1, 0},
			expLogging: "INFO-V(3) blue/green balance label 'non=2' on ingress 'default/ing1' does not reference any endpoint",
		},
		// 22
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-non"),
			expWeights: []int{1, 0},
			expLogging: `
WARN endpoint '172.17.0.11:8080' on ingress 'default/ing1' was removed from balance: pod not found: 'pod0102-non'
INFO-V(3) blue/green balance label 'v=2' on ingress 'default/ing1' does not reference any endpoint`,
		},
		// 23
		{
			ann:        buildAnn("v=1=50,v=2=25", "pod"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-non"),
			expWeights: []int{50, 0},
			expLogging: `
WARN endpoint '172.17.0.11:8080' on ingress 'default/ing1' was removed from balance: pod not found: 'pod0102-non'
INFO-V(3) blue/green balance label 'v=2' on ingress 'default/ing1' does not reference any endpoint`,
		},
		// 24
		{
			ann:        buildAnn("v=1=50,v=2=25,v=3=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0103-01"),
			expWeights: []int{4, 1, 1, 2},
			expLogging: "",
		},
		// 25
		{
			ann:        buildAnn("v=1=50,v=2=0,v=3=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0103-01"),
			expWeights: []int{2, 0, 0, 1},
			expLogging: "",
		},
		// 26
		{
			ann:        buildAnn("v=1=50,v=2=0,v=3=25", "deploy"),
			endpoints:  buildEndpoints(""),
			expWeights: []int{},
			expLogging: `
INFO-V(3) blue/green balance label 'v=1' on ingress 'default/ing1' does not reference any endpoint
INFO-V(3) blue/green balance label 'v=2' on ingress 'default/ing1' does not reference any endpoint
INFO-V(3) blue/green balance label 'v=3' on ingress 'default/ing1' does not reference any endpoint`,
		},
		// 27
		{
			ann:        buildAnn("v=1=0,v=2=0", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{0, 0},
			expLogging: "",
		},
		// 28
		{
			ann:        buildAnn("v=1=255,v=2=2", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0102-03,pod0102-04"),
			expWeights: []int{256, 1, 1, 1, 1},
			expLogging: "",
		},
		// 29
		{
			ann:        buildAnn("v=1=50,v=2=50", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0101-02,pod0102-01,pod0102-02=0"),
			expWeights: []int{1, 1, 2, 0},
			expLogging: "",
		},
	}
	for i, test := range testCase {
		c := setup(t)
		c.cache.PodList = pods
		d := c.createBackendData("default", "ing1", test.ann, test.annDefault)
		d.backend.Endpoints = test.endpoints
		u := c.createUpdater()
		u.buildBackendBlueGreen(d)
		weights := make([]int, len(d.backend.Endpoints))
		for j, ep := range d.backend.Endpoints {
			weights[j] = ep.Weight
		}
		if len(test.expWeights)+len(weights) > 0 && !reflect.DeepEqual(test.expWeights, weights) {
			t.Errorf("weight on %d differs - expected: %v - actual: %v", i, test.expWeights, weights)
		}
		c.logger.CompareLogging(test.expLogging)
		c.teardown()
	}
}

func TestHSTS(t *testing.T) {
	testCases := []struct {
		paths      []string
		source     *Source
		annDefault map[string]string
		ann        map[string]map[string]string
		expected   []*hatypes.BackendConfigHSTS
		logging    string
	}{
		// 0
		{
			paths: []string{"/", "/url"},
			annDefault: map[string]string{
				ingtypes.BackHSTS:       "true",
				ingtypes.BackHSTSMaxAge: "15768000",
			},
			ann: map[string]map[string]string{
				"/": {},
				"/url": {
					ingtypes.BackHSTSMaxAge:  "50",
					ingtypes.BackHSTSPreload: "true",
				},
			},
			expected: []*hatypes.BackendConfigHSTS{
				{
					Paths: hatypes.NewBackendPaths(&hatypes.BackendPath{ID: "path01", Hostpath: "/", Path: "/"}),
					Config: hatypes.HSTS{
						Enabled:    true,
						MaxAge:     15768000,
						Subdomains: false,
						Preload:    false,
					},
				},
				{
					Paths: hatypes.NewBackendPaths(&hatypes.BackendPath{ID: "path02", Hostpath: "/url", Path: "/url"}),
					Config: hatypes.HSTS{
						Enabled:    true,
						MaxAge:     50,
						Subdomains: false,
						Preload:    true,
					},
				},
			},
		},
		// 1
		{
			paths: []string{"/"},
			annDefault: map[string]string{
				ingtypes.BackHSTS:       "true",
				ingtypes.BackHSTSMaxAge: "15768000",
			},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackHSTSMaxAge:            "50",
					ingtypes.BackHSTSPreload:           "not-valid-bool",
					ingtypes.BackHSTSIncludeSubdomains: "true",
				},
			},
			expected: []*hatypes.BackendConfigHSTS{
				{
					Paths: hatypes.NewBackendPaths(&hatypes.BackendPath{ID: "path01", Hostpath: "/", Path: "/"}),
					Config: hatypes.HSTS{
						Enabled:    true,
						MaxAge:     50,
						Subdomains: true,
						Preload:    false,
					},
				},
			},
			source:  &Source{Namespace: "default", Name: "ing1", Type: "ingress"},
			logging: `WARN ignoring key 'hsts-preload' for backend 'default/ing1': strconv.ParseBool: parsing "not-valid-bool": invalid syntax`,
		},
		// 2
		{
			paths: []string{"/"},
			expected: []*hatypes.BackendConfigHSTS{
				{
					Paths:  hatypes.NewBackendPaths(&hatypes.BackendPath{ID: "path01", Hostpath: "/", Path: "/"}),
					Config: hatypes.HSTS{},
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendData("default", "ing1", map[string]string{}, test.annDefault)
		for _, path := range test.paths {
			d.backend.AddHostPath("", path)
		}
		for uri, ann := range test.ann {
			d.mapper.AddAnnotations(test.source, uri, ann)
		}
		u := c.createUpdater()
		u.buildBackendHSTS(d)
		if !reflect.DeepEqual(d.backend.HSTS, test.expected) {
			t.Errorf("hsts on %d differs - expected: %v - actual: %v", i, test.expected, d.backend.HSTS)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestOAuth(t *testing.T) {
	testCases := []struct {
		annDefault map[string]string
		ann        map[string]string
		backend    string
		oauthExp   hatypes.OAuthConfig
		logging    string
	}{
		// 0
		{
			ann:      map[string]string{},
			oauthExp: hatypes.OAuthConfig{},
		},
		// 1
		{
			ann: map[string]string{
				ingtypes.BackOAuth: "none",
			},
			logging: "WARN ignoring invalid oauth implementation 'none' on ingress 'default/app'",
		},
		// 2
		{
			ann: map[string]string{
				ingtypes.BackOAuth: "oauth2_proxy",
			},
			logging: "ERROR path '/oauth2' was not found on namespace 'default'",
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.BackOAuth: "oauth2_proxy",
			},
			backend: "default:back:/oauth2",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/oauth2",
				Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
			},
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.BackOAuth:          "oauth2_proxy",
				ingtypes.BackOAuthURIPrefix: "/auth",
			},
			backend: "default:back:/auth",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/auth",
				Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
			},
		},
		// 5
		{
			ann: map[string]string{
				ingtypes.BackOAuth:        "oauth2_proxy",
				ingtypes.BackOAuthHeaders: "X-Auth-New:attr_from_lua",
			},
			backend: "default:back:/oauth2",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/oauth2",
				Headers:     map[string]string{"X-Auth-New": "attr_from_lua"},
			},
		},
		// 6
		{
			ann: map[string]string{
				ingtypes.BackOAuth:        "oauth2_proxy",
				ingtypes.BackOAuthHeaders: "space before:attr",
			},
			backend: "default:back:/oauth2",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/oauth2",
				Headers:     map[string]string{},
			},
			logging: "WARN invalid header format 'space before:attr' on ingress 'default/app'",
		},
		// 7
		{
			ann: map[string]string{
				ingtypes.BackOAuth:        "oauth2_proxy",
				ingtypes.BackOAuthHeaders: "no-colon",
			},
			backend: "default:back:/oauth2",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/oauth2",
				Headers:     map[string]string{},
			},
			logging: "WARN invalid header format 'no-colon' on ingress 'default/app'",
		},
		// 8
		{
			ann: map[string]string{
				ingtypes.BackOAuth:        "oauth2_proxy",
				ingtypes.BackOAuthHeaders: "more:colons:unsupported",
			},
			backend: "default:back:/oauth2",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/oauth2",
				Headers:     map[string]string{},
			},
			logging: "WARN invalid header format 'more:colons:unsupported' on ingress 'default/app'",
		},
		// 9
		{
			ann: map[string]string{
				ingtypes.BackOAuth:        "oauth2_proxy",
				ingtypes.BackOAuthHeaders: ",,X-Auth-Request-Email:auth_response_email,,X-Auth-New:attr_from_lua,",
			},
			backend: "default:back:/oauth2",
			oauthExp: hatypes.OAuthConfig{
				Impl:        "oauth2_proxy",
				BackendName: "default_back_8080",
				URIPrefix:   "/oauth2",
				Headers: map[string]string{
					"X-Auth-Request-Email": "auth_response_email",
					"X-Auth-New":           "attr_from_lua",
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendData("default", "app", test.ann, test.annDefault)
		if test.backend != "" {
			b := strings.Split(test.backend, ":")
			backend := c.haproxy.AcquireBackend(b[0], b[1], "8080")
			c.haproxy.AcquireHost("app.local").AddPath(backend, b[2])
		}
		c.createUpdater().buildBackendOAuth(d)
		if !reflect.DeepEqual(test.oauthExp, d.backend.OAuth) {
			t.Errorf("oauth on %d differs - expected: %+v - actual: %+v", i, test.oauthExp, d.backend.OAuth)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestRewriteURL(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		logging  string
	}{
		// 0
		{
			input:    ``,
			expected: ``,
		},
		// 1
		{
			input:    `/"/`,
			expected: ``,
			logging:  `WARN rewrite-target does not allow white spaces or single/double quotes on backend 'default/app': /"/`,
		},
		// 2
		{
			input:    `/app`,
			expected: `/app`,
		},
	}

	for i, test := range testCases {
		c := setup(t)
		var ann map[string]string
		if test.input != "" {
			ann = map[string]string{ingtypes.BackRewriteTarget: test.input}
		}
		d := c.createBackendData("default", "app", map[string]string{}, map[string]string{})
		d.backend.AddHostPath("d1.local", "/")
		d.mapper.AddAnnotations(&Source{}, "d1.local/", ann)
		c.createUpdater().buildBackendRewriteURL(d)
		expected := []*hatypes.BackendConfigStr{
			{
				Paths:  hatypes.NewBackendPaths(d.backend.FindHostPath("d1.local/")),
				Config: test.expected,
			},
		}
		if !reflect.DeepEqual(d.backend.RewriteURL, expected) {
			t.Errorf("rewrite on %d differs - expected: %v - actual: %v", i, expected, d.backend.RewriteURL)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestWAF(t *testing.T) {
	testCase := []struct {
		waf      string
		expected string
		logging  string
	}{
		{
			waf:      "",
			expected: "",
			logging:  "",
		},
		{
			waf:      "none",
			expected: "",
			logging:  "WARN ignoring invalid WAF mode on ingress 'default/app': none",
		},
		{
			waf:      "modsecurity",
			expected: "modsecurity",
			logging:  "",
		},
	}
	for i, test := range testCase {
		c := setup(t)
		var ann map[string]string
		if test.waf != "" {
			ann = map[string]string{ingtypes.BackWAF: test.waf}
		}
		d := c.createBackendData("default", "app", ann, map[string]string{})
		c.createUpdater().buildBackendWAF(d)
		if d.backend.WAF != test.expected {
			t.Errorf("WAF on %d differs - expected: %v - actual: %v", i, test.expected, d.backend.WAF)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestWhitelistHTTP(t *testing.T) {
	testCases := []struct {
		paths    []string
		cidrlist map[string]string
		expected []*hatypes.BackendConfigWhitelist
		logging  string
	}{
		// 0
		{
			paths: []string{"/"},
			cidrlist: map[string]string{
				"/": "10.0.0.0/8,192.168.0.0/16",
			},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths:  hatypes.NewBackendPaths(&hatypes.BackendPath{Path: "/"}),
					Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
			},
		},
		// 1
		{
			paths: []string{"/", "/url", "/path"},
			cidrlist: map[string]string{
				"/":     "10.0.0.0/8,192.168.0.0/16",
				"/path": "10.0.0.0/8,192.168.0.0/16",
				"/url":  "10.0.0.0/8",
			},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths: hatypes.NewBackendPaths(
						&hatypes.BackendPath{Path: "/"},
						&hatypes.BackendPath{Path: "/path"},
					),
					Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
				{
					Paths:  hatypes.NewBackendPaths(&hatypes.BackendPath{Path: "/url"}),
					Config: []string{"10.0.0.0/8"},
				},
			},
		},
		// 2
		{
			paths: []string{"/"},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths: hatypes.NewBackendPaths(&hatypes.BackendPath{Path: "/"}),
				},
			},
		},
		// 3
		{
			paths: []string{"/"},
			cidrlist: map[string]string{
				"/": "",
			},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths: hatypes.NewBackendPaths(
						&hatypes.BackendPath{Path: "/"},
					),
					Config: nil,
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendData("default", "app", map[string]string{}, map[string]string{})
		for _, path := range test.paths {
			// TODO missing a proper test with host and /path
			d.backend.AddHostPath("", path)
		}
		for uri, cidrlist := range test.cidrlist {
			d.mapper.AddAnnotation(&Source{}, uri, ingtypes.BackWhitelistSourceRange, cidrlist)
		}
		c.createUpdater().buildBackendWhitelistHTTP(d)
		for _, cfg := range d.backend.WhitelistHTTP {
			for _, path := range cfg.Paths.Items {
				path.ID = ""
				path.Hostpath = ""
			}
		}
		if !reflect.DeepEqual(d.backend.WhitelistHTTP, test.expected) {
			t.Errorf("whitelist on %d differs- expected: %v - actual: %v", i, test.expected, d.backend.WhitelistHTTP)
		}
		c.teardown()
	}
}

func TestWhitelistTCP(t *testing.T) {
	testCase := []struct {
		cidrlist string
		expected []string
		logging  string
	}{
		// 0
		{
			cidrlist: "10.0.0.0/8,192.168.0.0/16",
			expected: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		// 1
		{
			cidrlist: "10.0.0.0/8, 192.168.0.0/16",
			expected: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		// 2
		{
			cidrlist: "10.0.0.0/8,192.168.0/16",
			expected: []string{"10.0.0.0/8"},
			logging:  `WARN skipping invalid cidr '192.168.0/16' in whitelist config on ingress 'default/app'`,
		},
		// 3
		{
			cidrlist: "10.0.0/8,192.168.0/16",
			expected: nil,
			logging: `
WARN skipping invalid cidr '10.0.0/8' in whitelist config on ingress 'default/app'
WARN skipping invalid cidr '192.168.0/16' in whitelist config on ingress 'default/app'`,
		},
	}
	for i, test := range testCase {
		c := setup(t)
		d := c.createBackendData("default", "app", map[string]string{ingtypes.BackWhitelistSourceRange: test.cidrlist}, map[string]string{})
		d.backend.ModeTCP = true
		c.createUpdater().buildBackendWhitelistTCP(d)
		if !reflect.DeepEqual(d.backend.WhitelistTCP, test.expected) {
			t.Errorf("whitelist on %d differs - expected: %v - actual: %v", i, test.expected, d.backend.WhitelistTCP)
		}
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
