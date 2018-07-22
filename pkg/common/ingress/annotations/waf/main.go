/*
Copyright 2018 The Kubernetes Authors.

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

package waf

import (
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	extensions "k8s.io/api/extensions/v1beta1"
	"regexp"
)

const (
	wafAnn = "ingress.kubernetes.io/waf"
)

var (
	wafAnnRegex = regexp.MustCompile(`^(modsecurity)$`)
)

type waf struct{}

// Config is the web application firewall configuration
type Config struct {
	Mode string
}

// NewParser creates a new waf annotation parser
func NewParser() parser.IngressAnnotation {
	return waf{}
}

// Parse parses waf annotation
func (w waf) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, err := parser.GetStringAnnotation(wafAnn, ing)
	if err != nil {
		return Config{}, nil
	}
	if !wafAnnRegex.MatchString(s) {
		glog.Warningf("ignoring invalid WAF option: %v", s)
		return Config{}, nil
	}
	return Config{
		Mode: s,
	}, nil
}

// Equal tests for equality between two waf Config types
func (c1 *Config) Equal(c2 *Config) bool {
	if c1.Mode != c2.Mode {
		return false
	}
	return true
}
