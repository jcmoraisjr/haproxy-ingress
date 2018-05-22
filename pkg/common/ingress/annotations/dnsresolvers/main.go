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

package dnsresolvers

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	extensions "k8s.io/api/extensions/v1beta1"
)

const (
	DNSResolversAnn = "ingress.kubernetes.io/dns-resolvers"
	UseResolverAnn = "haproxy.kubernetes.io/use-resolver"
)

type dnsresolvers struct {
	resolvers resolver.DefaultBackend
}

// NewParser creates a new balance-algorithm annotation parser
func NewParser(resolvers resolver.DefaultBackend) parser.IngressAnnotation {
	return dnsresolvers{resolvers}
}

// Parse parses dns-resolvers annotation
func (b dnsresolvers) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, err := parser.GetStringAnnotation(DNSResolversAnn, ing)
	if err != nil {
		return b.resolvers.GetDefaultBackend().DNSResolvers, nil
	}
	return s, nil
}
