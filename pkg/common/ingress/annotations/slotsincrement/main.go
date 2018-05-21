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

package slotsincrement

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	extensions "k8s.io/api/extensions/v1beta1"
)

const (
	slotsIncrementAnn = "ingress.kubernetes.io/slots-increment"
)

type slotsInc struct {
	resolver resolver.DefaultBackend
}

// NewParser creates a new slots-increment annotation parser
func NewParser(resolver resolver.DefaultBackend) parser.IngressAnnotation {
	return slotsInc{resolver}
}

// Parse parses slots-increment annotation
func (s slotsInc) Parse(ing *extensions.Ingress) (interface{}, error) {
	increment, _ := parser.GetIntAnnotation(slotsIncrementAnn, ing)
	if increment <= 0 {
		increment = s.resolver.GetDefaultBackend().BackendServerSlotsIncrement
	}
	return increment, nil
}
