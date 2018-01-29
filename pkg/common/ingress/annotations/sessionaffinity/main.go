/*
Copyright 2016 The Kubernetes Authors.

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

package sessionaffinity

import (
	"regexp"

	"github.com/golang/glog"

	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
)

const (
	annotationAffinityType = "ingress.kubernetes.io/affinity"
	// If a cookie with this name exists,
	// its value is used as an index into the list of available backends.
	annotationAffinityCookieName = "ingress.kubernetes.io/session-cookie-name"
	defaultAffinityCookieName    = "INGRESSCOOKIE"
	// The cookie strategy to use: insert, prefix, or rewrite
	annotationAffinityCookieStrategy = "ingress.kubernetes.io/session-cookie-strategy"
	defaultAffinityCookieStrategy    = "insert"
	// This is the algorithm used by nginx to generate a value for the session cookie, if
	// one isn't supplied and affinity is set to "cookie".
	annotationAffinityCookieHash = "ingress.kubernetes.io/session-cookie-hash"
	defaultAffinityCookieHash    = "md5"
)

var (
	affinityCookieHashRegex = regexp.MustCompile(`^(index|md5|sha1)$`)
	affinityCookieStrategyRegex = regexp.MustCompile(`^(insert|prefix|rewrite)`)
)

// AffinityConfig describes the per ingress session affinity config
type AffinityConfig struct {
	// The type of affinity that will be used
	AffinityType string `json:"type"`
	CookieConfig
}

// CookieConfig describes the Config of cookie type affinity
type CookieConfig struct {
	// The name of the cookie that will be used in case of cookie affinity type.
	Name string `json:"name"`
	// The cookie strategy that will be used in case of cookie affinity type.
	Strategy string `json:"strategy"`
	// The hash that will be used to encode the cookie in case of cookie affinity type
	Hash string `json:"hash"`
}

// CookieAffinityParse gets the annotation values related to Cookie Affinity
// It also sets default values when no value or incorrect value is found
func CookieAffinityParse(ing *extensions.Ingress) *CookieConfig {

	sn, err := parser.GetStringAnnotation(annotationAffinityCookieName, ing)

	if err != nil || sn == "" {
		glog.V(3).Infof("Ingress %v: No value found in annotation %v. Using the default %v", ing.Name, annotationAffinityCookieName, defaultAffinityCookieName)
		sn = defaultAffinityCookieName
	}

	ss, err := parser.GetStringAnnotation(annotationAffinityCookieStrategy, ing)

	if err != nil || !affinityCookieStrategyRegex.MatchString(ss) {
		glog.V(3).Infof("Invalid or no annotation value found in Ingress %v: %v. Setting it to default %v", ing.Name, annotationAffinityCookieStrategy, defaultAffinityCookieStrategy)
		ss = defaultAffinityCookieStrategy
	}

	sh, err := parser.GetStringAnnotation(annotationAffinityCookieHash, ing)

	if err != nil || !affinityCookieHashRegex.MatchString(sh) {
		glog.V(3).Infof("Invalid or no annotation value found in Ingress %v: %v. Setting it to default %v", ing.Name, annotationAffinityCookieHash, defaultAffinityCookieHash)
		sh = defaultAffinityCookieHash
	}

	return &CookieConfig{
		Name: sn,
		Strategy: ss,
		Hash: sh,
	}
}

// NewParser creates a new Affinity annotation parser
func NewParser() parser.IngressAnnotation {
	return affinity{}
}

type affinity struct {
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to configure the affinity directives
func (a affinity) Parse(ing *extensions.Ingress) (interface{}, error) {
	cookieAffinityConfig := &CookieConfig{}
	// Check the type of affinity that will be used
	at, err := parser.GetStringAnnotation(annotationAffinityType, ing)
	if err != nil {
		at = ""
	}

	switch at {
	case "cookie":
		cookieAffinityConfig = CookieAffinityParse(ing)

	default:
		glog.V(3).Infof("No default affinity was found for Ingress %v", ing.Name)

	}
	return &AffinityConfig{
		AffinityType: at,
		CookieConfig: *cookieAffinityConfig,
	}, nil

}
