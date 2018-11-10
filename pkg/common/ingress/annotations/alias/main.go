/*
Copyright 2017 The Kubernetes Authors.

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

package alias

import (
	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
)

const (
	aliasAnn      = "ingress.kubernetes.io/server-alias"
	aliasRegexAnn = "ingress.kubernetes.io/server-alias-regex"
)

type alias struct {
}

// Config has the server alias configuration
type Config struct {
	Host  string
	Regex string
}

// NewParser creates a new Alias annotation parser
func NewParser() parser.IngressAnnotation {
	return alias{}
}

// Parse parses the annotations contained in the ingress rule
// used to add an alias to the provided hosts
func (a alias) Parse(ing *extensions.Ingress) (interface{}, error) {
	host, _ := parser.GetStringAnnotation(aliasAnn, ing)
	regex, _ := parser.GetStringAnnotation(aliasRegexAnn, ing)
	return &Config{
		Host:  host,
		Regex: regex,
	}, nil
}

// Equal tests equality between two Config objects
func (c1 *Config) Equal(c2 *Config) bool {
	if c1 == nil || c2 == nil {
		return c1 == c2
	}
	if c1.Host != c2.Host {
		return false
	}
	if c1.Regex != c2.Regex {
		return false
	}
	return true
}
