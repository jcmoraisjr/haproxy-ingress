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

package proxybackend

import (
	"github.com/golang/glog"
	extensions "k8s.io/api/extensions/v1beta1"
	"regexp"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
)

const (
	proxyProtocolAnn = "ingress.kubernetes.io/proxy-protocol"
)

var (
	// "" (empty) is also a valid content
	proxyProtocolRegex = regexp.MustCompile(`^(|no|v1|v2|v2-ssl|v2-ssl-cn)$`)
)

// Config is the proxybackend configuration instance
type Config struct {
	ProxyProtocol string `json:"proxyProtocol"`
}

// Equal tests for equality between two Config types
func (c1 *Config) Equal(c2 *Config) bool {
	if c1.ProxyProtocol != c2.ProxyProtocol {
		return false
	}
	return true
}

type proxy struct{}

// NewParser creates a new proxybackend configuration annotation parser
func NewParser() parser.IngressAnnotation {
	return proxy{}
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to configure the backend
func (p proxy) Parse(ing *extensions.Ingress) (interface{}, error) {
	pp, err := parser.GetStringAnnotation(proxyProtocolAnn, ing)
	if err != nil {
		pp = ""
	}
	// "no", "" (empty) or any other non "v1|v2|v2-ssl|..." value is
	// ignored by the template, falling back to not using proxy protocol
	if !proxyProtocolRegex.MatchString(pp) {
		glog.Warningf("ignoring invalid proxy protocol option '%v' on %v/%v", pp, ing.Namespace, ing.Name)
		pp = ""
	}

	return &Config{
		ProxyProtocol: pp,
	}, nil
}
