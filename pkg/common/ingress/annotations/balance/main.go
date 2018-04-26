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

package balance

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	extensions "k8s.io/api/extensions/v1beta1"
)

const (
	balanceAnn = "ingress.kubernetes.io/balance-algorithm"
)

type balance struct {
	resolver resolver.DefaultBackend
}

// NewParser creates a new balance-algorithm annotation parser
func NewParser(resolver resolver.DefaultBackend) parser.IngressAnnotation {
	return balance{resolver}
}

// Parse parses balance-algorithm annotation
func (b balance) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, err := parser.GetStringAnnotation(balanceAnn, ing)
	if err != nil {
		return b.resolver.GetDefaultBackend().BalanceAlgorithm, nil
	}
	return s, nil
}
