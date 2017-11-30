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

package hsts

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	extensions "k8s.io/api/extensions/v1beta1"
)

const (
	annHSTS           = "ingress.kubernetes.io/hsts"
	annHSTSSubdomains = "ingress.kubernetes.io/hsts-include-subdomains"
	annHSTSMaxAge     = "ingress.kubernetes.io/hsts-max-age"
	annHSTSPreload    = "ingress.kubernetes.io/hsts-preload"
)

// Config contains per ingress resource configurations
// for HTTP Strict Transport Security
type Config struct {
	Enable     bool
	Subdomains bool
	MaxAge     string
	Preload    bool
}

// Equal tests for equality between two HSTS types
func (hsts1 *Config) Equal(hsts2 *Config) bool {
	if hsts1 == hsts2 {
		return true
	}
	if hsts1 == nil || hsts2 == nil {
		return false
	}
	if hsts1.Enable != hsts2.Enable {
		return false
	}
	if hsts1.Subdomains != hsts2.Subdomains {
		return false
	}
	if hsts1.MaxAge != hsts2.MaxAge {
		return false
	}
	if hsts1.Preload != hsts2.Preload {
		return false
	}
	return true
}

type hsts struct {
	cfg resolver.DefaultBackend
}

// NewParser creates a new HSTS annotation parser
func NewParser(cfg resolver.DefaultBackend) parser.IngressAnnotation {
	return &hsts{
		cfg: cfg,
	}
}

// Parse parses the annotations contained in the ingress
// rule used to configure HSTS per server and location
func (hsts *hsts) Parse(ing *extensions.Ingress) (interface{}, error) {
	defaultBackend := hsts.cfg.GetDefaultBackend()

	enable, err := parser.GetBoolAnnotation(annHSTS, ing)
	if err != nil {
		enable = defaultBackend.HSTS
	}

	subdomains, err := parser.GetBoolAnnotation(annHSTSSubdomains, ing)
	if err != nil {
		subdomains = defaultBackend.HSTSIncludeSubdomains
	}

	maxAge, err := parser.GetStringAnnotation(annHSTSMaxAge, ing)
	if err != nil {
		maxAge = defaultBackend.HSTSMaxAge
	}

	preload, err := parser.GetBoolAnnotation(annHSTSPreload, ing)
	if err != nil {
		preload = defaultBackend.HSTSPreload
	}

	return &Config{
		Enable:     enable,
		Subdomains: subdomains,
		MaxAge:     maxAge,
		Preload:    preload,
	}, nil
}
