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
			expLogging: "WARN session-cookie-keywords on ingress 'default/ing1' contains 'preserve'; consider using 'session-cookie-preserve' instead for better dynamic update cookie persistence",
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
		// 12 - test that there is a fallback to using the "name" cookie value strategy
		{
			ann: map[string]string{
				ingtypes.BackAffinity:             "cookie",
				ingtypes.BackSessionCookieDynamic: "false",
				ingtypes.BackSessionCookieValue:   "err",
			},
			expCookie:  hatypes.Cookie{Name: "INGRESSCOOKIE", Strategy: "insert", Dynamic: false, Keywords: "indirect nocache httponly"},
			expLogging: "WARN invalid session-cookie-value-strategy 'err' on ingress 'default/ing1', using 'server-name' instead",
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
		expConfig    map[string]hatypes.AuthHTTP
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
			expConfig: map[string]hatypes.AuthHTTP{
				"/": {},
				"/admin": {
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
			actual := map[string]hatypes.AuthHTTP{}
			for _, path := range d.backend.Paths {
				actual[path.Path()] = path.AuthHTTP
			}
			c.compareObjects("auth http", i, actual, test.expConfig)
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
		expected   map[string]int64
		logging    string
	}{
		// 0
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "10",
				},
			},
			expected: map[string]int64{
				"/": 10,
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
			expected: map[string]int64{
				"/":    10240,
				"/app": 10485760,
				"/sub": 10737418240,
			},
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "unlimited",
				},
			},
			expected: map[string]int64{
				"/": 0,
			},
		},
		// 3
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackProxyBodySize: "10e",
				},
			},
			expected: map[string]int64{
				"/": 0,
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
			expected: map[string]int64{
				"/":    0,
				"/app": 1048576,
			},
			paths:  []string{"/"},
			source: Source{Namespace: "default", Name: "ing1", Type: "ingress"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.paths)
		c.createUpdater().buildBackendBodySize(d)
		actual := map[string]int64{}
		for _, path := range d.backend.Paths {
			actual[path.Path()] = path.MaxBodySize
		}
		c.compareObjects("proxy body size", i, actual, test.expected)
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
		expected map[string]hatypes.Cors
		logging  string
	}{
		// 0
		{
			paths: []string{"/"},
			expected: map[string]hatypes.Cors{
				"/": {},
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackCorsEnable: "true",
				},
			},
			expected: map[string]hatypes.Cors{
				"/": {
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
			expected: map[string]hatypes.Cors{
				"/": {},
				"/sub": {
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
		actual := map[string]hatypes.Cors{}
		for _, path := range d.backend.Paths {
			actual[path.Path()] = path.Cors
		}
		c.compareObjects("cors", i, actual, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestCustomConfig(t *testing.T) {
	testCases := []struct {
		disabled []string
		config   string
		expected []string
		logging  string
	}{
		// 0
		{
			config:   "  server srv001 127.0.0.1:8080",
			expected: []string{"  server srv001 127.0.0.1:8080"},
		},
		// 1
		{
			disabled: []string{"server"},
			config:   "  server srv001 127.0.0.1:8080",
			logging:  `WARN skipping configuration snippet on Ingress 'default/app': keyword 'server' not allowed`,
		},
		// 2
		{
			disabled: []string{"*"},
			config:   "  server srv001 127.0.0.1:8080",
			logging:  `WARN skipping configuration snippet on Ingress 'default/app': custom configuration is disabled`,
		},
		// 3
		{
			disabled: []string{"http-response"},
			config: `
  http-request set-header x-id 1 if { path / }
`,
			expected: []string{"", "  http-request set-header x-id 1 if { path / }"},
		},
		// 4
		{
			disabled: []string{"http-response"},
			config: `
  acl rootpath path /
  http-request set-header x-id 1 if rootpath
`,
			expected: []string{"", "  acl rootpath path /", "  http-request set-header x-id 1 if rootpath"},
		},
		// 5
		{
			disabled: []string{"http-response", "acl"},
			config: `
  acl rootpath path /
  http-request set-header x-id 1 if rootpath
`,
			logging: `WARN skipping configuration snippet on Ingress 'default/app': keyword 'acl' not allowed`,
		},
		// 6
		{
			disabled: []string{"http"},
			config:   "  http-request set-header x-id 1 if { path / }",
			expected: []string{"  http-request set-header x-id 1 if { path / }"},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		source := &Source{
			Type:      "Ingress",
			Namespace: "default",
			Name:      "app",
		}
		ann := map[string]map[string]string{
			"/": {ingtypes.BackConfigBackend: test.config},
		}
		d := c.createBackendMappingData("default/app", source, map[string]string{}, ann, []string{"/"})
		updater := c.createUpdater()
		updater.options.DisableKeywords = test.disabled
		updater.buildBackendCustomConfig(d)
		c.compareObjects("custom config", i, d.backend.CustomConfig, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestFirstToken(t *testing.T) {
	testCases := []struct {
		line     string
		expected string
	}{
		// 0
		{
			line:     "",
			expected: "",
		},
		// 1
		{
			line:     "server",
			expected: "server",
		},
		// 2
		{
			line:     "server svc",
			expected: "server",
		},
		// 3
		{
			line:     "\tserver\tsvc",
			expected: "server",
		},
		// 4
		{
			line:     " \tserver \tsvc",
			expected: "server",
		},
		// 5
		{
			line:     "  server  svc",
			expected: "server",
		},
	}
	for i, test := range testCases {
		c := setup(t)
		c.compareObjects("token", i, firstToken(test.line), test.expected)
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
		expected   map[string]hatypes.HSTS
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
			expected: map[string]hatypes.HSTS{
				"/": {
					Enabled:    true,
					MaxAge:     15768000,
					Subdomains: false,
					Preload:    false,
				},
				"/url": {
					Enabled:    true,
					MaxAge:     50,
					Subdomains: false,
					Preload:    true,
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
			expected: map[string]hatypes.HSTS{
				"/": {
					Enabled:    true,
					MaxAge:     50,
					Subdomains: true,
					Preload:    false,
				},
			},
			source:  Source{Namespace: "default", Name: "ing1", Type: "ingress"},
			logging: `WARN ignoring invalid bool expression on ingress 'default/ing1' key 'hsts-preload': not-valid-bool`,
		},
		// 2
		{
			paths: []string{"/"},
			expected: map[string]hatypes.HSTS{
				"/": {},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.paths)
		u := c.createUpdater()
		u.buildBackendHSTS(d)
		actual := map[string]hatypes.HSTS{}
		for _, path := range d.backend.Paths {
			actual[path.Path()] = path.HSTS
		}
		c.compareObjects("hsts", i, actual, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestOAuth(t *testing.T) {
	testCases := []struct {
		annDefault map[string]string
		ann        map[string]map[string]string
		external   bool
		haslua     bool
		backend    string
		oauthExp   map[string]hatypes.OAuthConfig
		logging    string
	}{
		// 0
		{
			ann:      map[string]map[string]string{},
			oauthExp: map[string]hatypes.OAuthConfig{},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth: "none",
				},
			},
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {AlwaysDeny: true},
			},
			logging: "WARN ignoring invalid oauth implementation 'none' on ingress 'default/ing1'",
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
			},
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {AlwaysDeny: true},
			},
			logging: "ERROR path '/oauth2' was not found on namespace 'default'",
		},
		// 3
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
				},
			},
		},
		// 4
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth:          "oauth2_proxy",
					ingtypes.BackOAuthURIPrefix: "/auth",
				},
			},
			backend: "default:back:/auth",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/auth",
					Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
				},
			},
		},
		// 5
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth:        "oauth2_proxy",
					ingtypes.BackOAuthHeaders: "X-Auth-New:attr_from_lua",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{"X-Auth-New": "attr_from_lua"},
				},
			},
		},
		// 6
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth:        "oauth2_proxy",
					ingtypes.BackOAuthHeaders: "space before:attr",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{},
				},
			},
			logging: "WARN invalid header format 'space before:attr' on ingress 'default/ing1'",
		},
		// 7
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth:        "oauth2_proxy",
					ingtypes.BackOAuthHeaders: "no-colon",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{},
				},
			},
			logging: "WARN invalid header format 'no-colon' on ingress 'default/ing1'",
		},
		// 8
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth:        "oauth2_proxy",
					ingtypes.BackOAuthHeaders: "more:colons:unsupported",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{},
				},
			},
			logging: "WARN invalid header format 'more:colons:unsupported' on ingress 'default/ing1'",
		},
		// 9
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth:        "oauth2_proxy",
					ingtypes.BackOAuthHeaders: ",,X-Auth-Request-Email:auth_response_email,,X-Auth-New:attr_from_lua,",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers: map[string]string{
						"X-Auth-Request-Email": "auth_response_email",
						"X-Auth-New":           "attr_from_lua",
					},
				},
			},
		},
		// 10
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
				"/app": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
			},
			external: true,
			backend:  "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/":    {AlwaysDeny: true},
				"/app": {AlwaysDeny: true},
			},
			logging: `
WARN oauth2_proxy on ingress 'default/ing1' needs Lua socket, install Lua libraries and enable 'external-has-lua' global config
WARN oauth2_proxy on ingress 'default/ing1' needs Lua socket, install Lua libraries and enable 'external-has-lua' global config
`,
		},
		// 11
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
				"/app": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
			},
			external: true,
			haslua:   true,
			backend:  "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
				},
				"/app": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
				},
			},
		},
		// 12
		{
			ann: map[string]map[string]string{
				"/": {},
				"/app": {
					ingtypes.BackOAuth: "oauth2_proxy",
				},
			},
			backend: "default:back:/oauth2",
			oauthExp: map[string]hatypes.OAuthConfig{
				"/": {},
				"/app": {
					Impl:        "oauth2_proxy",
					BackendName: "default_back_8080",
					URIPrefix:   "/oauth2",
					Headers:     map[string]string{"X-Auth-Request-Email": "auth_response_email"},
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
		d := c.createBackendMappingData("default/app", source, test.annDefault, test.ann, []string{})
		if test.external {
			c.haproxy.Global().External.MasterSocket = "/tmp/master.sock"
		}
		c.haproxy.Global().External.HasLua = test.haslua
		if test.backend != "" {
			b := strings.Split(test.backend, ":")
			backend := c.haproxy.Backends().AcquireBackend(b[0], b[1], "8080")
			c.haproxy.Hosts().AcquireHost("app.local").AddPath(backend, b[2], hatypes.MatchBegin)
		}
		c.createUpdater().buildBackendOAuth(d)
		actual := map[string]hatypes.OAuthConfig{}
		for _, path := range d.backend.Paths {
			actual[path.Path()] = path.OAuth
		}
		c.compareObjects("oauth", i, actual, test.oauthExp)
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
		actual := d.backend.Paths[0].RewriteURL
		c.compareObjects("rewrite", i, actual, test.expected)
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
		// 12
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1-ssl",
					ingtypes.BackSecureSNI:       "sni",
				},
			},
			expected: hatypes.ServerConfig{
				Secure:   true,
				Protocol: "h1",
				SNI:      "ssl_fc_sni",
			},
		},
		// 13
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1-ssl",
					ingtypes.BackSecureSNI:       "host",
				},
			},
			expected: hatypes.ServerConfig{
				Secure:   true,
				Protocol: "h1",
				SNI:      "var(req.host)",
			},
		},
		// 14
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1-ssl",
					ingtypes.BackSecureSNI:       "domain.tld",
				},
			},
			expected: hatypes.ServerConfig{
				Secure:   true,
				Protocol: "h1",
				SNI:      "str(domain.tld)",
			},
		},
		// 15
		{
			source: Source{Namespace: "default", Name: "app", Type: "ingress"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol: "h1-ssl",
					ingtypes.BackSecureSNI:       "invalid/domain",
				},
			},
			expected: hatypes.ServerConfig{
				Secure:   true,
				Protocol: "h1",
			},
			logging: `WARN skipping invalid domain (SNI) on ingress 'default/app': invalid/domain`,
		},
		// 16
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol:      "h1-ssl",
					ingtypes.BackSecureVerifyHostname: "domain.tld",
				},
			},
			expected: hatypes.ServerConfig{
				Secure:     true,
				Protocol:   "h1",
				VerifyHost: "domain.tld",
			},
		},
		// 17
		{
			source: Source{Namespace: "default", Name: "app", Type: "ingress"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol:      "h1-ssl",
					ingtypes.BackSecureVerifyHostname: "invalid/domain",
				},
			},
			expected: hatypes.ServerConfig{
				Secure:   true,
				Protocol: "h1",
			},
			logging: `WARN skipping invalid domain (verify-hostname) on ingress 'default/app': invalid/domain`,
		},
		// 18
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol:      "h1-ssl",
					ingtypes.BackSecureVerifyHostname: "valid-domain.tld",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol:   "h1",
				Secure:     true,
				VerifyHost: "valid-domain.tld",
			},
		},
		// 19
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol:      "h1-ssl",
					ingtypes.BackSecureVerifyHostname: "sub.valid-domain.tld",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol:   "h1",
				Secure:     true,
				VerifyHost: "sub.valid-domain.tld",
			},
		},
		// 20
		{
			source: Source{Namespace: "default", Name: "app", Type: "ingress"},
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackBackendProtocol:      "h1-ssl",
					ingtypes.BackSecureVerifyHostname: "invalid-domain",
				},
			},
			expected: hatypes.ServerConfig{
				Protocol: "h1",
				Secure:   true,
			},
			logging: `WARN skipping invalid domain (verify-hostname) on ingress 'default/app': invalid-domain`,
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
		expected   map[bool][]string
		source     Source
		logging    string
	}{
		// 0
		{
			addPaths: []string{"/"},
			expected: map[bool][]string{
				false: {"/"},
			},
		},
		// 1
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSSLRedirect: "true",
				},
			},
			expected: map[bool][]string{
				true: {"/"},
			},
		},
		// 2
		{
			ann: map[string]map[string]string{
				"/": {
					ingtypes.BackSSLRedirect: "invalid",
				},
			},
			expected: map[bool][]string{
				false: {"/"},
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
			expected: map[bool][]string{
				false: {"/other", "/path", "/url"},
				true:  {"/"},
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
			expected: map[bool][]string{
				false: {"/", "/.hidden/api", "/app"},
				true:  {"/api"},
			},
		},
	}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", &test.source, test.annDefault, test.ann, test.addPaths)
		c.createUpdater().buildBackendSSLRedirect(d)
		actual := map[bool][]string{}
		for _, path := range d.backend.Paths {
			actual[path.SSLRedirect] = append(actual[path.SSLRedirect], path.Path())
		}
		if len(actual[false]) == 0 {
			delete(actual, false)
		}
		if len(actual[true]) == 0 {
			delete(actual, true)
		}
		c.compareObjects("sslredirect", i, actual, test.expected)
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
		waf      string
		wafmode  string
		expected hatypes.WAF
		logging  string
	}{
		// 0
		{},
		// 1
		{
			waf:      "none",
			wafmode:  "deny",
			expected: hatypes.WAF{},
			logging:  "WARN ignoring invalid WAF module on ingress 'default/ing1': none",
		},
		// 2
		{
			waf:     "modsecurity",
			wafmode: "XXXXXX",
			expected: hatypes.WAF{
				Module: "modsecurity",
				Mode:   "deny",
			},
			logging: "WARN ignoring invalid WAF mode 'XXXXXX' on ingress 'default/ing1', using 'deny' instead",
		},
		// 3
		{
			waf:     "modsecurity",
			wafmode: "detect",
			expected: hatypes.WAF{
				Module: "modsecurity",
				Mode:   "detect",
			},
			logging: "",
		},
		// 4
		{
			waf:     "modsecurity",
			wafmode: "deny",
			expected: hatypes.WAF{
				Module: "modsecurity",
				Mode:   "deny",
			},
			logging: "",
		},
		// 5
		{
			waf:     "modsecurity",
			wafmode: "",
			expected: hatypes.WAF{
				Module: "modsecurity",
				Mode:   "deny",
			},
			logging: "",
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
		ann = map[string]map[string]string{
			"/": {},
		}
		if test.waf != "" {
			ann["/"][ingtypes.BackWAF] = test.waf
		}
		if test.wafmode != "" {
			ann["/"][ingtypes.BackWAFMode] = test.wafmode
		}
		d := c.createBackendMappingData("default/app", source, map[string]string{ingtypes.BackWAFMode: "deny"}, ann, []string{})
		c.createUpdater().buildBackendWAF(d)
		actual := d.backend.Paths[0].WAF
		c.compareObjects("WAF", i, actual, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}

func TestWhitelistHTTP(t *testing.T) {
	testCases := []struct {
		paths       []string
		cidrlist    map[string]map[string]string
		expected    map[string][]string
		expAllowExc map[string][]string
		expDenyRule map[string][]string
		expDenyExc  map[string][]string
		logging     string
	}{
		// 0
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,192.168.0.0/16",
				},
			},
			expected: map[string][]string{
				"/": {"10.0.0.0/8", "192.168.0.0/16"},
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
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/48,192.168.0.0/48",
				},
				"/url": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,192.168.0.101",
				},
			},
			expected: map[string][]string{
				"/":    {"10.0.0.0/8", "192.168.0.0/16"},
				"/url": {"10.0.0.0/8", "192.168.0.101"},
			},
			logging: `
WARN skipping invalid IP or cidr on ingress 'default/ing1': 10.0.0.0/48
WARN skipping invalid IP or cidr on ingress 'default/ing1': 192.168.0.0/48`,
		},
		// 2
		{
			paths:    []string{"/"},
			expected: map[string][]string{},
		},
		// 3
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "",
				},
			},
			expected: map[string][]string{},
		},
		// 4
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,fa00::1:1,fa00::/64",
				},
			},
			expected: map[string][]string{
				"/": {"10.0.0.0/8", "fa00::1:1", "fa00::/64"},
			},
		},
		// 5
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/8,fa00::/129",
				},
			},
			expected: map[string][]string{
				"/": {"10.0.0.0/8"},
			},
			logging: `
WARN skipping invalid IP or cidr on ingress 'default/ing1': fa00::/129`,
		},
		// 6
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackWhitelistSourceRange: "10.0.0.0/48,192.168.0.0/24",
				},
			},
			expected: map[string][]string{
				"/": {"192.168.0.0/24"},
			},
			logging: `
WARN skipping invalid IP or cidr on ingress 'default/ing1': 10.0.0.0/48`,
		},
		// 7
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackAllowlistSourceRange: "10.0.0.0/8,192.168.0.0/24",
					ingtypes.BackWhitelistSourceRange: "10.1.0.0/16",
				},
			},
			expected: map[string][]string{
				"/": {"10.0.0.0/8", "192.168.0.0/24"},
			},
			logging: `
WARN both allowlist and whitelist were used on ingress 'default/ing1', ignoring whitelist content: 10.1.0.0/16`,
		},
		// 8
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackAllowlistSourceRange: "10.0.0.0/8,192.168.0.0/24,!10.100.0.0/16",
				},
			},
			expected: map[string][]string{
				"/": {"10.0.0.0/8", "192.168.0.0/24"},
			},
			expAllowExc: map[string][]string{
				"/": {"10.100.0.0/16"},
			},
		},
		// 9
		{
			paths: []string{"/"},
			cidrlist: map[string]map[string]string{
				"/": {
					ingtypes.BackDenylistSourceRange: "192.168.0.0/24,!192.168.95.0/24",
				},
			},
			expDenyRule: map[string][]string{
				"/": {"192.168.0.0/24"},
			},
			expDenyExc: map[string][]string{
				"/": {"192.168.95.0/24"},
			},
		},
	}
	source := &Source{Namespace: "default", Name: "ing1", Type: "ingress"}
	for i, test := range testCases {
		c := setup(t)
		d := c.createBackendMappingData("default/app", source, map[string]string{}, test.cidrlist, test.paths)
		c.createUpdater().buildBackendWhitelistHTTP(d)
		actual := map[string][]string{}
		actualAllowExc := map[string][]string{}
		actualDenyRule := map[string][]string{}
		actualDenyExc := map[string][]string{}
		for _, path := range d.backend.Paths {
			if len(path.AllowedIPHTTP.Rule) > 0 {
				actual[path.Path()] = path.AllowedIPHTTP.Rule
			}
			if len(path.AllowedIPHTTP.Exception) > 0 {
				actualAllowExc[path.Path()] = path.AllowedIPHTTP.Exception
			}
			if len(path.DeniedIPHTTP.Rule) > 0 {
				actualDenyRule[path.Path()] = path.DeniedIPHTTP.Rule
			}
			if len(path.DeniedIPHTTP.Exception) > 0 {
				actualDenyExc[path.Path()] = path.DeniedIPHTTP.Exception
			}
		}
		if test.expected == nil {
			test.expected = map[string][]string{}
		}
		if test.expAllowExc == nil {
			test.expAllowExc = map[string][]string{}
		}
		if test.expDenyRule == nil {
			test.expDenyRule = map[string][]string{}
		}
		if test.expDenyExc == nil {
			test.expDenyExc = map[string][]string{}
		}
		c.compareObjects("whitelist http", i, actual, test.expected)
		c.compareObjects("whitelist http", i, actualAllowExc, test.expAllowExc)
		c.compareObjects("whitelist http", i, actualDenyRule, test.expDenyRule)
		c.compareObjects("whitelist http", i, actualDenyExc, test.expDenyExc)
		c.logger.CompareLogging(test.logging)
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
		c.compareObjects("whitelist tcp", i, d.backend.AllowedIPTCP.Rule, test.expected)
		c.logger.CompareLogging(test.logging)
		c.teardown()
	}
}
