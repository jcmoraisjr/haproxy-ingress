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
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert", Keywords: "indirect nocache httponly"},
			expLogging: "",
		},
		// 3
		{
			ann: map[string]string{
				ingtypes.BackAffinity:          "cookie",
				ingtypes.BackSessionCookieName: "ing",
			},
			expCookie:  hatypes.Cookie{Name: "ing", Strategy: "insert", Keywords: "indirect nocache httponly"},
			expLogging: "",
		},
		// 4
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieStrategy: "err",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert", Keywords: "indirect nocache httponly"},
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
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert", Dynamic: false, Keywords: "indirect nocache httponly"},
			expLogging: "",
		},
		// 8
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieKeywords: "nocache",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert", Dynamic: false, Keywords: "nocache"},
			expLogging: "",
		},
		// 9
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieStrategy: "prefix",
				ingtypes.BackSessionCookieKeywords: "nocache",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "prefix", Keywords: "nocache"},
			expLogging: "",
		},
		// 10 - test that warning is logged when using "preserve" in the keywords annotation instead of in "session-cookie-preserve" annotation
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieName:     "serverId",
				ingtypes.BackSessionCookieStrategy: "insert",
				ingtypes.BackSessionCookieDynamic:  "false",
				ingtypes.BackSessionCookieKeywords: "preserve nocache",
			},
			expCookie:  hatypes.Cookie{Name: "serverId", Strategy: "insert", Dynamic: false, Preserve: false, Keywords: "preserve nocache"},
			expLogging: "WARN session-cookie-keywords contains 'preserve'; consider using 'session-cookie-preserve' instead for better dynamic update cookie persistence",
		},
		// 11 - test "session-cookie-preserve" cookie annotation is applied
		{
			ann: map[string]string{
				ingtypes.BackAffinity:              "cookie",
				ingtypes.BackSessionCookieName:     "serverId",
				ingtypes.BackSessionCookieStrategy: "insert",
				ingtypes.BackSessionCookieDynamic:  "false",
				ingtypes.BackSessionCookiePreserve: "true",
				ingtypes.BackSessionCookieKeywords: "nocache",
			},
			expCookie:  hatypes.Cookie{Name: "serverId", Strategy: "insert", Dynamic: false, Preserve: true, Keywords: "nocache"},
			expLogging: "",
		},
	}

	source := &Source{
		Namespace: "default",
		Name:      "ing1",
		Type:      "ingress",
	}
	for i, test := range testCase {
		c := setup(t)
		u := c.createUpdater()
		d := c.createBackendData("default/app", source, test.ann, test.annDefault)
		u.buildBackendAffinity(d)
		c.compareObjects("affinity", i, d.backend.Cookie, test.expCookie)
		c.logger.CompareLogging(test.expLogging)
		c.teardown()
	}
}

func TestAuthHTTP(t *testing.T) {
	testCase := []struct {
		paths        []string
		source       *Source
		annDefault   map[string]string
		ann          map[string]map[string]string
		secrets      conv_helper.SecretContent
		expUserlists []*hatypes.Userlist
		expConfig    []*hatypes.BackendConfigAuth
		expLogging   string
	}{
		// 0
		{
			ann: map[string]map[string]string{},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType: "fail",
				},
			},
			expLogging: "ERROR unsupported authentication type on ingress 'default/ing1': fail",
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType: "basic",
				},
			},
			expLogging: "ERROR missing secret name on basic authentication on ingress 'default/ing1'",
		},
		// 3
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "mypwd",
				},
			},
			expLogging: "ERROR error reading basic authentication on ingress 'default/ing1': secret not found: 'default/mypwd'",
		},
		// 4
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "mypwd",
				},
			},
			secrets:    conv_helper.SecretContent{"default/mypwd": {"xx": []byte{}}},
			expLogging: "ERROR error reading basic authentication on ingress 'default/ing1': secret 'default/mypwd' does not have file/key 'auth'",
		},
		// 5
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "mypwd",
					ingtypes.BackAuthRealm:  `"a name"`,
				},
			},
			secrets: conv_helper.SecretContent{"default/mypwd": {"auth": []byte("usr1::clear1")}},
			expUserlists: []*hatypes.Userlist{{Name: "default_mypwd", Users: []hatypes.User{
				{Name: "usr1", Passwd: "clear1", Encrypted: false},
			}}},
			expLogging: "WARN ignoring auth-realm with quotes on ingress 'default/ing1'",
		},
		// 6
		{
			source: &Source{Namespace: "ns1", Name: "i1", Type: "ingress"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "mypwd",
				},
			},
			secrets:      conv_helper.SecretContent{"ns1/mypwd": {"auth": []byte{}}},
			expUserlists: []*hatypes.Userlist{{Name: "ns1_mypwd"}},
			expLogging:   "WARN userlist on ingress 'ns1/i1' for basic authentication is empty",
		},
		// 7
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "basicpwd",
				},
			},
			secrets:      conv_helper.SecretContent{"default/basicpwd": {"auth": []byte("fail")}},
			expUserlists: []*hatypes.Userlist{{Name: "default_basicpwd"}},
			expLogging: `
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'fail' line 1
WARN userlist on ingress 'default/ing1' for basic authentication is empty`,
		},
		// 8
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "basicpwd",
				},
			},
			secrets: conv_helper.SecretContent{"default/basicpwd": {"auth": []byte(`
usr1::clearpwd1
nopwd`)}},
			expUserlists: []*hatypes.Userlist{{Name: "default_basicpwd", Users: []hatypes.User{
				{Name: "usr1", Passwd: "clearpwd1", Encrypted: false},
			}}},
			expLogging: "WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'nopwd' line 3",
		},
		// 9
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "basicpwd",
				},
			},
			secrets: conv_helper.SecretContent{"default/basicpwd": {"auth": []byte(`
usrnopwd1:
usrnopwd2::
:encpwd3
::clearpwd4`)}},
			expUserlists: []*hatypes.Userlist{{Name: "default_basicpwd"}},
			expLogging: `
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'usrnopwd1' line 2
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing password of user 'usrnopwd2' line 3
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing username line 4
WARN ignoring malformed usr/passwd on secret 'default/basicpwd', declared on ingress 'default/ing1': missing username line 5
WARN userlist on ingress 'default/ing1' for basic authentication is empty`,
		},
		// 10
		{
			paths: []string{"/", "/admin"},
			ann: map[string]map[string]string{
				"/admin": {
					ingtypes.BackAuthType:   "basic",
					ingtypes.BackAuthSecret: "basicpwd",
				},
			},
			secrets: conv_helper.SecretContent{"default/basicpwd": {"auth": []byte(`
usr1:encpwd1
usr2::clearpwd2`)}},
			expUserlists: []*hatypes.Userlist{{Name: "default_basicpwd", Users: []hatypes.User{
				{Name: "usr1", Passwd: "encpwd1", Encrypted: true},
				{Name: "usr2", Passwd: "clearpwd2", Encrypted: false},
			}}},
			expConfig: []*hatypes.BackendConfigAuth{
				{
					Paths: createBackendPaths("/"),
				},
				{
					Paths:        createBackendPaths("/admin"),
					UserlistName: "default_basicpwd",
					Realm:        "localhost",
				},
			},
		},
	}

	for i, test := range testCase {
		// TODO missing expHTTPRequests
		c := setup(t)
		u := c.createUpdater()
		if test.source == nil {
			test.source = &Source{
				Namespace: "default",
				Name:      "ing1",
				Type:      "ingress",
			}
		}
		c.cache.SecretContent = test.secrets
		d := c.createBackendMappingData("default/app", test.source, test.annDefault, test.ann, test.paths)
		u.buildBackendAuthHTTP(d)
		userlists := u.haproxy.Userlists().BuildSortedItems()
		c.compareObjects("userlists", i, userlists, test.expUserlists)
		if test.expConfig != nil {
			c.compareObjects("auth http", i, d.backend.AuthHTTP, test.expConfig)
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
				weight := 100
				if len(targetWeight) == 2 {
					target = targetWeight[0]
					if w, err := strconv.ParseInt(targetWeight[1], 10, 0); err == nil {
						weight = int(w)
					}
				}
				ep = append(ep, &hatypes.Endpoint{
					Enabled:   true,
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
		"pod0103-02": buildPod("app=d01,x=3"),
		"pod0103-03": buildPod("app=d01"),
	}
	testCase := []struct {
		ann        map[string]string
		endpoints  []*hatypes.Endpoint
		expConfig  *hatypes.BlueGreenConfig
		expLabels  []string
		expWeights []int
		expLogging string
	}{
		//
		// Balance test cases
		//
		// 0
		{
			ann:        buildAnn("", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
			expLogging: "",
		},
		// 1
		{
			ann:        buildAnn("", "err"),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
			expLogging: "",
		},
		// 2
		{
			ann:        buildAnn("err", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
			expLogging: "ERROR blue/green config on ingress 'default/ing1' has an invalid weight format: err",
		},
		// 3
		{
			ann:        buildAnn("v=1=xx", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
			expLogging: "ERROR blue/green config on ingress 'default/ing1' has an invalid weight value: strconv.ParseInt: parsing \"xx\": invalid syntax",
		},
		// 4
		{
			ann:        buildAnn("v=1=1.5", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
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
			expWeights: []int{100},
			expLogging: "WARN invalid weight '260' on ingress 'default/ing1', using '256' instead",
		},
		// 7
		{
			ann:        buildAnn("v=1=10", "err"),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
			expLogging: "WARN unsupported blue/green mode 'err' on ingress 'default/ing1', falling back to 'deploy'",
		},
		// 8
		{
			ann:        buildAnn("v=1=10", ""),
			endpoints:  buildEndpoints("pod0101-01"),
			expWeights: []int{100},
			expLogging: "",
		},
		// 9
		{
			ann:        buildAnn("", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{100, 100},
			expLogging: "",
		},
		// 10
		{
			ann:        buildAnn("v=1=50,v=2=50", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{100, 100},
			expLogging: "",
		},
		// 11
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{200, 100},
			expLogging: "",
		},
		// 12
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02"),
			expWeights: []int{256, 64, 64},
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
			expWeights: []int{256, 64, 64},
			expLogging: "",
		},
		// 15
		{
			ann:        buildAnn("v=1=500,v=2=2", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{256, 2},
			expLogging: "WARN invalid weight '500' on ingress 'default/ing1', using '256' instead",
		},
		// 16
		{
			ann:        buildAnn("v=1=60,v=2=3", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0102-03,pod0102-04"),
			expWeights: []int{256, 3, 3, 3, 3},
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
			expWeights: []int{0, 100},
			expLogging: `
WARN endpoint '172.17.0.11:8080' on ingress 'default/ing1' was removed from balance: endpoint does not reference a pod
INFO-V(3) blue/green balance label 'v=1' on ingress 'default/ing1' does not reference any endpoint`,
		},
		// 19
		{
			ann:        buildAnn("v=1=50,v=non=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01"),
			expWeights: []int{100, 0},
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
			expWeights: []int{100, 0},
			expLogging: "INFO-V(3) blue/green balance label 'non=2' on ingress 'default/ing1' does not reference any endpoint",
		},
		// 22
		{
			ann:        buildAnn("v=1=50,v=2=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-non"),
			expWeights: []int{100, 0},
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
			expWeights: []int{256, 64, 64, 128},
			expLogging: "",
		},
		// 25
		{
			ann:        buildAnn("v=1=50,v=2=0,v=3=25", "deploy"),
			endpoints:  buildEndpoints("pod0101-01,pod0102-01,pod0102-02,pod0103-01"),
			expWeights: []int{200, 0, 0, 100},
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
			expWeights: []int{100, 100, 200, 0},
			expLogging: "",
		},
		//
		// Label test cases
		//
		// 30
		{
			ann:       map[string]string{ingtypes.BackBlueGreenCookie: "SetServer:v"},
			endpoints: buildEndpoints("pod0101-01,pod0101-02,pod0102-01"),
			expConfig: &hatypes.BlueGreenConfig{CookieName: "SetServer"},
			expLabels: []string{"1", "1", "2"},
		},
		// 31
		{
			ann:       map[string]string{ingtypes.BackBlueGreenHeader: "X-Server:v"},
			endpoints: buildEndpoints("pod0101-01,pod0101-02,pod0102-01"),
			expConfig: &hatypes.BlueGreenConfig{HeaderName: "X-Server"},
			expLabels: []string{"1", "1", "2"},
		},
		// 32
		{
			ann:       map[string]string{ingtypes.BackBlueGreenHeader: "X-Server:v"},
			endpoints: buildEndpoints("pod0103-01,pod0103-02,pod0103-03"),
			expConfig: &hatypes.BlueGreenConfig{HeaderName: "X-Server"},
			expLabels: []string{"3", "", ""},
		},
		// 33
		{
			ann: map[string]string{
				ingtypes.BackBlueGreenCookie: "SetServer:v",
				ingtypes.BackBlueGreenHeader: "X-Server:v",
			},
			endpoints: buildEndpoints("pod0103-01,pod0103-02,pod0103-03"),
			expConfig: &hatypes.BlueGreenConfig{
				CookieName: "SetServer",
				HeaderName: "X-Server",
			},
			expLabels: []string{"3", "", ""},
		},
		// 34
		{
			ann: map[string]string{
				ingtypes.BackBlueGreenCookie: "SetServer:v",
				ingtypes.BackBlueGreenHeader: "X-Server:x",
			},
			endpoints:  buildEndpoints("pod0103-01,pod0103-02,pod0103-03"),
			expConfig:  &hatypes.BlueGreenConfig{},
			expLabels:  []string{"", "", ""},
			expLogging: `ERROR CookieName:LabelName and HeaderName:LabelName pairs, used in the same backend on ingress 'default/ing1' and ingress 'default/ing1', should have the same label name`,
		},
		// 35
		{
			ann: map[string]string{
				ingtypes.BackBlueGreenCookie: "SetServer:x",
				ingtypes.BackBlueGreenHeader: "X-Server:x",
			},
			endpoints: buildEndpoints("pod0103-01,pod0103-02,pod0103-03"),
			expConfig: &hatypes.BlueGreenConfig{
				CookieName: "SetServer",
				HeaderName: "X-Server",
			},
			expLabels: []string{"", "3", ""},
		},
		// 36
		{
			ann: map[string]string{
				ingtypes.BackBlueGreenCookie: "SetServer",
			},
			endpoints:  buildEndpoints("pod0103-01,pod0103-02,pod0103-03"),
			expConfig:  &hatypes.BlueGreenConfig{},
			expLabels:  []string{"", "", ""},
			expLogging: `ERROR invalid CookieName:LabelName pair on ingress 'default/ing1': SetServer`,
		},
		// 37
		{
			ann: map[string]string{
				ingtypes.BackBlueGreenHeader: "_X_Server:v",
			},
			endpoints:  buildEndpoints("pod0103-01,pod0103-02,pod0103-03"),
			expConfig:  &hatypes.BlueGreenConfig{},
			expLabels:  []string{"", "", ""},
			expLogging: `ERROR invalid HeaderName:LabelName pair on ingress 'default/ing1': _X_Server:v`,
		},
	}
	source := &Source{
		Namespace: "default",
		Name:      "ing1",
		Type:      "ingress",
	}
	for i, test := range testCase {
		c := setup(t)
		c.cache.PodList = pods
		d := c.createBackendData("default/app", source, test.ann, map[string]string{ingtypes.BackInitialWeight: "100"})
		d.backend.Endpoints = test.endpoints
		u := c.createUpdater()
		u.buildBackendBlueGreenBalance(d)
		u.buildBackendBlueGreenSelector(d)
		weights := make([]int, len(d.backend.Endpoints))
		labels := make([]string, len(d.backend.Endpoints))
		for j, ep := range d.backend.Endpoints {
			weights[j] = ep.Weight
			labels[j] = ep.Label
		}
		if test.expConfig != nil || test.expLabels != nil {
			c.compareObjects("blue/green configs", i, d.backend.BlueGreen, *test.expConfig)
			c.compareObjects("blue/green labels", i, labels, test.expLabels)
		}
		if test.expWeights != nil {
			c.compareObjects("blue/green weight", i, weights, test.expWeights)
		}
		c.logger.CompareLogging(test.expLogging)
		c.teardown()
	}
}

func TestBodySize(t *testing.T) {
	testCases := []struct {
		source     Source
		annDefault map[string]string
		ann        map[string]map[string]string
		paths      []string
		expected   []*hatypes.BackendConfigInt
		logging    string
	}{
		// 0
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "10",
				},
			},
			expected: []*hatypes.BackendConfigInt{
				{
					Paths:  createBackendPaths("/"),
					Config: 10,
				},
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "10k",
				},
				"/app": {
					ingtypes.BackProxyBodySize: "10m",
				},
				"/sub": {
					ingtypes.BackProxyBodySize: "10g",
				},
			},
			expected: []*hatypes.BackendConfigInt{
				{
					Paths:  createBackendPaths("/"),
					Config: 10240,
				},
				{
					Paths:  createBackendPaths("/app"),
					Config: 10485760,
				},
				{
					Paths:  createBackendPaths("/sub"),
					Config: 10737418240,
				},
			},
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "unlimited",
				},
			},
			expected: []*hatypes.BackendConfigInt{
				{
					Paths:  createBackendPaths("/"),
					Config: 0,
				},
			},
		},
		// 3
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "10e",
				},
			},
			expected: []*hatypes.BackendConfigInt{
				{
					Paths:  createBackendPaths("/"),
					Config: 0,
				},
			},
			source:  Source{Namespace: "default", Name: "ing1", Type: "ingress"},
			logging: `WARN ignoring invalid body size on ingress 'default/ing1': 10e`,
		},
		// 4
		{
			ann: map[string]map[string]string{
				"/app": {
					ingtypes.BackProxyBodySize: "1m",
				},
			},
			expected: []*hatypes.BackendConfigInt{
				{
					Paths:  createBackendPaths("/"),
					Config: 0,
				},
				{
					Paths:  createBackendPaths("/app"),
					Config: 1048576,
				},
			},
			paths:  []string{"/"},
			source: Source{Namespace: "default", Name: "ing1", Type: "ingress"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.paths)
		c.createUpdater().buildBackendBodySize(d)
		c.compareObjects("proxy body size", i, d.backend.MaxBodySize, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

const (
	corsDefaultHeaders = "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
	corsDefaultMethods = "GET, PUT, POST, DELETE, PATCH, OPTIONS"
	corsDefaultOrigin  = "*"
	corsDefaultMaxAge  = 86400
)

func TestCors(t *testing.T) {
	testCases := []struct {
		paths    []string
		ann      map[string]map[string]string
		expected []*hatypes.BackendConfigCors
		logging  string
	}{
		// 0
		{
			paths: []string{"/"},
			expected: []*hatypes.BackendConfigCors{
				{
					Paths:  createBackendPaths("/"),
					Config: hatypes.Cors{},
				},
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackCorsEnable: "true",
				},
			},
			expected: []*hatypes.BackendConfigCors{
				{
					Paths: createBackendPaths("/"),
					Config: hatypes.Cors{
						Enabled:          true,
						AllowCredentials: false,
						AllowHeaders:     corsDefaultHeaders,
						AllowMethods:     corsDefaultMethods,
						AllowOrigin:      corsDefaultOrigin,
						ExposeHeaders:    "",
						MaxAge:           corsDefaultMaxAge,
					},
				},
			},
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackCorsEnable: "false",
				},
				"/sub": {
					ingtypes.BackCorsEnable: "true",
				},
			},
			expected: []*hatypes.BackendConfigCors{
				{
					Paths:  createBackendPaths("/"),
					Config: hatypes.Cors{},
				},
				{
					Paths: createBackendPaths("/sub"),
					Config: hatypes.Cors{
						Enabled:          true,
						AllowCredentials: false,
						AllowHeaders:     corsDefaultHeaders,
						AllowMethods:     corsDefaultMethods,
						AllowOrigin:      corsDefaultOrigin,
						ExposeHeaders:    "",
						MaxAge:           corsDefaultMaxAge,
					},
				},
			},
		},
	}
	annDefault := map[string]string{
		ingtypes.BackCorsAllowHeaders: corsDefaultHeaders,
		ingtypes.BackCorsAllowMethods: corsDefaultMethods,
		ingtypes.BackCorsAllowOrigin:  corsDefaultOrigin,
		ingtypes.BackCorsMaxAge:       strconv.Itoa(corsDefaultMaxAge),
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &Source{}, annDefault, test.ann, test.paths)
		c.createUpdater().buildBackendCors(d)
		c.compareObjects("cors", i, d.backend.Cors, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestHeaders(t *testing.T) {
	testCases := []struct {
		headers  string
		expected []*hatypes.BackendHeader
		logging  string
	}{
		// 0
		{
			headers: `invalid`,
			logging: `WARN ignored missing header name or value on ingress 'ing1/app': invalid`,
		},
		// 1
		{
			headers: `key value`,
			expected: []*hatypes.BackendHeader{
				{Name: "key", Value: "value"},
			},
		},
		// 2
		{
			headers: `name: content`,
			expected: []*hatypes.BackendHeader{
				{Name: "name", Value: "content"},
			},
		},
		// 3
		{
			headers: `k:v`,
			expected: []*hatypes.BackendHeader{
				{Name: "k", Value: "v"},
			},
		},
		// 4
		{
			headers: `host: %[service].%[namespace].svc.cluster.local`,
			expected: []*hatypes.BackendHeader{
				{Name: "host", Value: "app.default.svc.cluster.local"},
			},
		},
		// 5
		{
			headers: `
k8snamespace: %[namespace]
k8sservice: %[service]
host: %[service].%[namespace].svc.cluster.local
`,
			expected: []*hatypes.BackendHeader{
				{Name: "k8snamespace", Value: "default"},
				{Name: "k8sservice", Value: "app"},
				{Name: "host", Value: "app.default.svc.cluster.local"},
			},
		},
	}
	source := &Source{
		Namespace: "ing1",
		Name:      "app",
		Type:      "ingress",
	}
	for i, test := range testCases {
		c := setup(t)
		ann := map[string]map[string]string{
			"/": {ingtypes.BackHeaders: test.headers},
		}
		d := c.createBackendMappingData("default/app", source, map[string]string{}, ann, []string{"/"})
		c.createUpdater().buildBackendHeaders(d)
		c.compareObjects("headers", i, d.backend.Headers, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestHSTS(t *testing.T) {
	testCases := []struct {
		paths      []string
		source     Source
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
					Paths: createBackendPaths("/"),
					Config: hatypes.HSTS{
						Enabled:    true,
						MaxAge:     15768000,
						Subdomains: false,
						Preload:    false,
					},
				},
				{
					Paths: createBackendPaths("/url"),
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
					Paths: createBackendPaths("/"),
					Config: hatypes.HSTS{
						Enabled:    true,
						MaxAge:     50,
						Subdomains: true,
						Preload:    false,
					},
				},
			},
			source:  Source{Namespace: "default", Name: "ing1", Type: "ingress"},
			logging: `WARN ignoring invalid bool expression on ingress 'default/ing1' key 'hsts-preload': not-valid-bool`,
		},
		// 2
		{
			paths: []string{"/"},
			expected: []*hatypes.BackendConfigHSTS{
				{
					Paths:  createBackendPaths("/"),
					Config: hatypes.HSTS{},
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.paths)
		u := c.createUpdater()
		u.buildBackendHSTS(d)
		c.compareObjects("hsts", i, d.backend.HSTS, test.expected)
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
			logging: "WARN ignoring invalid oauth implementation 'none' on ingress 'default/ing1'",
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
			logging: "WARN invalid header format 'space before:attr' on ingress 'default/ing1'",
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
			logging: "WARN invalid header format 'no-colon' on ingress 'default/ing1'",
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
			logging: "WARN invalid header format 'more:colons:unsupported' on ingress 'default/ing1'",
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

	source := &Source{
		Namespace: "default",
		Name:      "ing1",
		Type:      "ingress",
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendData("default/app", source, test.ann, test.annDefault)
		if test.backend != "" {
			b := strings.Split(test.backend, ":")
			backend := c.haproxy.Backends().AcquireBackend(b[0], b[1], "8080")
			c.haproxy.Hosts().AcquireHost("app.local").AddPath(backend, b[2], hatypes.MatchBegin)
		}
		c.createUpdater().buildBackendOAuth(d)
		c.compareObjects("oauth", i, d.backend.OAuth, test.oauthExp)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestRewriteURL(t *testing.T) {
	testCases := []struct {
		source   Source
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
			source: Source{
				Namespace: "default",
				Name:      "app1",
				Type:      "service",
			},
			input:    `/"/`,
			expected: ``,
			logging:  `WARN rewrite-target does not allow white spaces or single/double quotes on service 'default/app1': '/"/'`,
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
		d := c.createBackendData("default/app", &test.source, map[string]string{}, map[string]string{})
		d.backend.AddBackendPath(hatypes.CreatePathLink("d1.local", "/"))
		d.mapper.AddAnnotations(&test.source, hatypes.CreatePathLink("d1.local", "/"), ann)
		c.createUpdater().buildBackendRewriteURL(d)
		expected := []*hatypes.BackendConfigStr{
			{
				Paths:  hatypes.NewBackendPaths(d.backend.Paths...),
				Config: test.expected,
			},
		}
		c.compareObjects("rewrite", i, d.backend.RewriteURL, expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestBackendServerNaming(t *testing.T) {
	testCases := []struct {
		source  Source
		naming  string
		logging string
	}{
		// 0
		{
			naming: "seq",
		},
		// 1
		{
			naming: "sequence",
		},
		// 2
		{
			source: Source{
				Namespace: "default",
				Name:      "ing1",
				Type:      "ingress",
			},
			naming:  "sequences",
			logging: "WARN ignoring invalid naming type 'sequences' on ingress 'default/ing1', using 'seq' instead",
		},
		// 3
		{
			naming: "pod",
		},
		// 4
		{
			naming: "ip",
		},
	}
	for _, test := range testCases {
		c := setup(t)
		d := c.createBackendData("default/app", &test.source, map[string]string{ingtypes.BackBackendServerNaming: test.naming}, map[string]string{})
		c.createUpdater().buildBackendServerNaming(d)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestBackendProtocol(t *testing.T) {
	testCase := []struct {
		source     Source
		useHTX     bool
		annDefault map[string]string
		ann        map[string]map[string]string
		paths      []string
		tlsSecrets map[string]string
		caSecrets  map[string]string
		expected   hatypes.ServerConfig
		logging    string
	}{
		// 0
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSecureBackends: "true",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   true,
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSecureCrtSecret: "cli",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   false,
			},
		},
		// 2
		{
			source: Source{Namespace: "default", Name: "app1", Type: "service"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSecureBackends:  "true",
					ingtypes.BackSecureCrtSecret: "cli",
				},
			},
			tlsSecrets: map[string]string{
				"default/cli": "/var/haproxy/ssl/cli.pem",
			},
			expected: hatypes.ServerConfig{
				Protocol:    "h1",
				Secure:      true,
				CrtFilename: "/var/haproxy/ssl/cli.pem",
				CrtHash:     "f916dd295030e070f4d4aca4508571bc82f549af",
			},
		},
		// 3
		{
			source: Source{Namespace: "default", Name: "app1", Type: "service"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSecureBackends:       "true",
					ingtypes.BackSecureCrtSecret:      "cli",
					ingtypes.BackSecureVerifyCASecret: "ca",
				},
			},
			tlsSecrets: map[string]string{
				"default/cli": "/var/haproxy/ssl/cli.pem",
			},
			caSecrets: map[string]string{
				"default/ca": "/var/haproxy/ssl/ca.pem",
			},
			expected: hatypes.ServerConfig{
				Protocol:    "h1",
				Secure:      true,
				CAFilename:  "/var/haproxy/ssl/ca.pem",
				CAHash:      "3be93154b1cddfd0e1279f4d76022221676d08c7",
				CrtFilename: "/var/haproxy/ssl/cli.pem",
				CrtHash:     "f916dd295030e070f4d4aca4508571bc82f549af",
			},
		},
		// 4
		{
			source: Source{Namespace: "default", Name: "app1", Type: "service"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSecureBackends:       "true",
					ingtypes.BackSecureCrtSecret:      "cli",
					ingtypes.BackSecureVerifyCASecret: "ca",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   true,
			},
			logging: `
WARN skipping client certificate on service 'default/app1': secret not found: 'default/cli'
WARN skipping CA on service 'default/app1': secret not found: 'default/ca'`,
		},
		// 5
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   false,
			},
		},
		// 6
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1-ssl",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   true,
			},
		},
		// 7
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1-ssl",
					ingtypes.BackSecureBackends:  "false",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   true,
			},
		},
		// 8
		{
			useHTX: true,
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "GRPC",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h2",
				Secure:   false,
			},
		},
		// 9
		{
			useHTX: true,
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h2-ssl",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h2",
				Secure:   true,
			},
		},
		// 10
		{
			source: Source{Namespace: "default", Name: "app1", Type: "service"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "invalid-ssl",
				},
			},
			expected: hatypes.ServerConfig{},
			logging:  `WARN ignoring invalid backend protocol on service 'default/app1': invalid-ssl`,
		},
		// 11
		{
			source: Source{Namespace: "default", Name: "app1", Type: "service"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h2",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
			},
			logging: `WARN ignoring h2 protocol on service 'default/app1' due to HTX disabled, changing to h1`,
		},
	}
	for i, test := range testCase {
		c := setup(t)
		d := c.createBackendMappingData("defualt/app", &test.source, test.annDefault, test.ann, test.paths)
		c.haproxy.Global().UseHTX = test.useHTX
		c.cache.SecretTLSPath = test.tlsSecrets
		c.cache.SecretCAPath = test.caSecrets
		c.createUpdater().buildBackendProtocol(d)
		c.compareObjects("secure", i, d.backend.Server, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestSSLRedirect(t *testing.T) {
	testCases := []struct {
		annDefault map[string]string
		ann        map[string]map[string]string
		addPaths   []string
		expected   []*hatypes.BackendConfigBool
		source     Source
		logging    string
	}{
		// 0
		{
			addPaths: []string{"/"},
			expected: []*hatypes.BackendConfigBool{
				{
					Paths:  createBackendPaths("/"),
					Config: false,
				},
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSSLRedirect: "true",
				},
			},
			expected: []*hatypes.BackendConfigBool{
				{
					Paths:  createBackendPaths("/"),
					Config: true,
				},
			},
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSSLRedirect: "invalid",
				},
			},
			expected: []*hatypes.BackendConfigBool{
				{
					Paths:  createBackendPaths("/"),
					Config: false,
				},
			},
			source:  Source{Namespace: "default", Name: "ing1", Type: "ingress"},
			logging: `WARN ignoring invalid bool expression on ingress 'default/ing1' key 'ssl-redirect': invalid`,
		},
		// 3
		{
			addPaths: []string{"/other"},
			annDefault: map[string]string{
				ingtypes.BackSSLRedirect: "false",
			},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSSLRedirect: "true",
				},
				"/url": {
					ingtypes.BackSSLRedirect: "false",
				},
				"/path": {
					ingtypes.BackSSLRedirect: "no-bool",
				},
			},
			expected: []*hatypes.BackendConfigBool{
				{
					Paths:  createBackendPaths("/"),
					Config: true,
				},
				{
					Paths:  createBackendPaths("/other", "/path", "/url"),
					Config: false,
				},
			},
			source:  Source{Namespace: "system1", Name: "app", Type: "service"},
			logging: `WARN ignoring invalid bool expression on service 'system1/app' key 'ssl-redirect': no-bool`,
		},
		// 4
		{
			annDefault: map[string]string{
				ingtypes.GlobalNoTLSRedirectLocations: "/.hidden,/app",
			},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSSLRedirect: "false",
				},
				"/.hidden/api": {
					ingtypes.BackSSLRedirect: "true",
				},
				"/api": {
					ingtypes.BackSSLRedirect: "true",
				},
				"/app": {
					ingtypes.BackSSLRedirect: "true",
				},
			},
			expected: []*hatypes.BackendConfigBool{
				{
					Paths:  createBackendPaths("/", "/.hidden/api", "/app"),
					Config: false,
				},
				{
					Paths:  createBackendPaths("/api"),
					Config: true,
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.addPaths)
		c.createUpdater().buildBackendSSLRedirect(d)
		c.compareObjects("sslredirect", i, d.backend.SSLRedirect, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestTimeout(t *testing.T) {
	testCase := []struct {
		annDefault map[string]string
		ann        map[string]map[string]string
		paths      []string
		source     Source
		expected   hatypes.BackendTimeoutConfig
		logging    string
	}{
		// 0
		{
			ann: map[string]map[string]string{
				"/": {
					"timeout-server": "10s",
				},
			},
			expected: hatypes.BackendTimeoutConfig{
				Server: "10s",
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					"timeout-server": "10zz",
				},
			},
			source:   Source{Namespace: "default", Name: "ing1", Type: "ingress"},
			expected: hatypes.BackendTimeoutConfig{},
			logging:  `WARN ignoring invalid time format on ingress 'default/ing1': 10zz`,
		},
		// 2
		{
			annDefault: map[string]string{
				"timeout-server": "10s",
			},
			// use only if declared as svc/ing annotation, otherwise defaults to HAProxy's defaults section
			expected: hatypes.BackendTimeoutConfig{},
		},
	}
	for i, test := range testCase {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.paths)
		c.createUpdater().buildBackendTimeout(d)
		c.compareObjects("backend timeout", i, d.backend.Timeout, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestWAF(t *testing.T) {
	testCase := []struct {
		waf          string
		wafmode      string
		expected     string
		expectedmode string
		logging      string
	}{
		// 0
		{
			waf:          "",
			wafmode:      "",
			expected:     "",
			expectedmode: "",
			logging:      "",
		},
		// 1
		{
			waf:          "none",
			wafmode:      "deny",
			expected:     "",
			expectedmode: "",
			logging:      "WARN ignoring invalid WAF module on ingress 'default/ing1': none",
		},
		// 2
		{
			waf:          "modsecurity",
			wafmode:      "XXXXXX",
			expected:     "modsecurity",
			expectedmode: "deny",
			logging:      "WARN ignoring invalid WAF mode 'XXXXXX' on ingress 'default/ing1', using 'deny' instead",
		},
		// 3
		{
			waf:          "modsecurity",
			wafmode:      "detect",
			expected:     "modsecurity",
			expectedmode: "detect",
			logging:      "",
		},
		// 4
		{
			waf:          "modsecurity",
			wafmode:      "deny",
			expected:     "modsecurity",
			expectedmode: "deny",
			logging:      "",
		},
		// 5
		{
			waf:          "modsecurity",
			wafmode:      "",
			expected:     "modsecurity",
			expectedmode: "deny",
			logging:      "",
		},
	}
	source := &Source{
		Namespace: "default",
		Name:      "ing1",
		Type:      "ingress",
	}
	for i, test := range testCase {
		c := setup(t)
		var ann map[string]map[string]string
		var expected []*hatypes.BackendConfigWAF
		ann = map[string]map[string]string{
			"/": {},
		}
		if test.waf != "" {
			ann["/"][ingtypes.BackWAF] = test.waf
		}
		if test.wafmode != "" {
			ann["/"][ingtypes.BackWAFMode] = test.wafmode
		}
		expected = []*hatypes.BackendConfigWAF{
			{
				Paths: createBackendPaths("/"),
				Config: hatypes.WAF{
					Module: test.expected,
					Mode:   test.expectedmode,
				},
			},
		}
		d := c.createBackendMappingData("default/app", source, map[string]string{ingtypes.BackWAFMode: "deny"}, ann, []string{})
		c.createUpdater().buildBackendWAF(d)
		c.compareObjects("WAF", i, d.backend.WAF, expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestWhitelistHTTP(t *testing.T) {
	testCases := []struct {
		paths    []string
		cidrlist map[string]map[string]string
		expected []*hatypes.BackendConfigWhitelist
		logging  string
	}{
		// 0
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,192.168.0.0/16",
				},
			},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths:  createBackendPaths("/"),
					Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
			},
		},
		// 1
		{
			paths: []string{"/", "/url", "/path"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,192.168.0.0/16",
				},
				"/path": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,192.168.0.0/16",
				},
				"/url": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,192.168.0.101",
				},
			},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths:  createBackendPaths("/", "/path"),
					Config: []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
				{
					Paths:  createBackendPaths("/url"),
					Config: []string{"10.0.0.0/8", "192.168.0.101"},
				},
			},
		},
		// 2
		{
			paths: []string{"/"},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths: createBackendPaths("/"),
				},
			},
		},
		// 3
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "",
				},
			},
			expected: []*hatypes.BackendConfigWhitelist{
				{
					Paths:  createBackendPaths("/"),
					Config: nil,
				},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &Source{}, map[string]string{}, test.cidrlist, test.paths)
		c.createUpdater().buildBackendWhitelistHTTP(d)
		c.compareObjects("whitelist http", i, d.backend.WhitelistHTTP, test.expected)
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
			logging:  `WARN skipping invalid IP or cidr on ingress 'default/ing1': 192.168.0/16`,
		},
		// 3
		{
			cidrlist: "10.0.0/8,192.168.0/16,192.168.1.101",
			expected: []string{"192.168.1.101"},
			logging: `
WARN skipping invalid IP or cidr on ingress 'default/ing1': 10.0.0/8
WARN skipping invalid IP or cidr on ingress 'default/ing1': 192.168.0/16`,
		},
	}

	source := &Source{
		Namespace: "default",
		Name:      "ing1",
		Type:      "ingress",
	}
	for i, test := range testCase {
		c := setup(t)
		ann := map[string]string{ingtypes.BackWhitelistSourceRange: test.cidrlist}
		d := c.createBackendData("default/app", source, ann, map[string]string{})
		d.backend.ModeTCP = true
		c.createUpdater().buildBackendWhitelistTCP(d)
		c.compareObjects("whitelist tcp", i, d.backend.WhitelistTCP, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func createBackendPaths(paths ...string) hatypes.BackendPaths {
	backendPaths := make([]*hatypes.BackendPath, 0, len(paths))
	for _, path := range paths {
		backendPaths = append(backendPaths, &hatypes.BackendPath{
			// ignoring ID which isn't the focus of the test
			// removing on createBackendMappingData() as well
			ID:   "",
			Link: hatypes.CreatePathLink(testingHostname, path),
		})
	}
	return hatypes.NewBackendPaths(backendPaths...)
}
