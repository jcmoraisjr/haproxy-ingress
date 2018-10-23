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

package sslpassthrough

import (
	"github.com/golang/glog"
	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	ing_errors "github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/errors"
)

const (
	passthroughAnn = "ingress.kubernetes.io/ssl-passthrough"
	httpPortAnn    = "ingress.kubernetes.io/ssl-passthrough-http-port"
)

type sslpt struct {
}

type Config struct {
	HasSSLPassthrough bool
	HTTPPort          int
}

// NewParser creates a new SSL passthrough annotation parser
func NewParser() parser.IngressAnnotation {
	return sslpt{}
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to indicate if is required to configure
func (a sslpt) Parse(ing *extensions.Ingress) (interface{}, error) {
	if ing.GetAnnotations() == nil {
		return &Config{}, ing_errors.ErrMissingAnnotations
	}

	pass, _ := parser.GetBoolAnnotation(passthroughAnn, ing)
	port, _ := parser.GetIntAnnotation(httpPortAnn, ing)

	if !pass && port != 0 {
		glog.Warningf("non ssl-passthrough with http-port on '%v/%v', ignoring", ing.Namespace, ing.Name)
		port = 0
	}
	if port < 0 {
		glog.Warningf("invalid port number '%v' on '%v/%v', ignoring", port, ing.Namespace, ing.Name)
		port = 0
	}

	return &Config{
		HasSSLPassthrough: pass,
		HTTPPort:          port,
	}, nil
}

// Equal tests equality between two Config structs
func (c1 *Config) Equal(c2 *Config) bool {
	if c1.HasSSLPassthrough != c2.HasSSLPassthrough {
		return false
	}
	if c1.HTTPPort != c2.HTTPPort {
		return false
	}
	return true
}
