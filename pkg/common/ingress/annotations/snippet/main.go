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

package snippet

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	extensions "k8s.io/api/extensions/v1beta1"
	"strings"
)

const (
	configFrontendAnn = "ingress.kubernetes.io/config-frontend"
	configBackendAnn  = "ingress.kubernetes.io/config-backend"
)

type snippet struct {
}

// Config has the snippet configurations. This struct is used in both
// frontend (locations) and backend structs.
type Config struct {
	Frontend []string
	Backend  []string
}

// NewParser creates a new CORS annotation parser
func NewParser() parser.IngressAnnotation {
	return snippet{}
}

// Parse parses the annotations contained in the ingress rule
// used to indicate if the frontend and/or the backend contains
// a fragment of configuration to be included
func (a snippet) Parse(ing *extensions.Ingress) (interface{}, error) {
	f, _ := parser.GetStringAnnotation(configFrontendAnn, ing)
	b, _ := parser.GetStringAnnotation(configBackendAnn, ing)
	config := Config{
		Frontend: linebreakToSlice(f),
		Backend:  linebreakToSlice(b),
	}
	return config, nil
}

func linebreakToSlice(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// Equal tests equality between two Config structs
func (c1 *Config) Equal(c2 *Config) bool {
	if len(c1.Frontend) != len(c2.Frontend) || len(c1.Backend) != len(c2.Backend) {
		return false
	}
	for i := range c1.Frontend {
		if c1.Frontend[i] != c2.Frontend[i] {
			return false
		}
	}
	for i := range c1.Backend {
		if c1.Backend[i] != c2.Backend[i] {
			return false
		}
	}
	return true
}
