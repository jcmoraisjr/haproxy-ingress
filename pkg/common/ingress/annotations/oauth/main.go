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

package oauth

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	extensions "k8s.io/api/extensions/v1beta1"
	"regexp"
	"strings"
)

const (
	oauthAnn          = "ingress.kubernetes.io/oauth"
	oauthURIPrefixAnn = "ingress.kubernetes.io/oauth-uri-prefix"
	oauthHeadersAnn   = "ingress.kubernetes.io/oauth-headers"
)

var (
	headerRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// Config has oauth configurations
type Config struct {
	OAuthImpl   string            `json:"oauthImpl"`
	URIPrefix   string            `json:"uriAuth"`
	BackendName string            `json:"backendName"`
	Headers     map[string]string `json:"headers"`
}

type oauth struct {
}

// NewParser creates a new oauth annotation parser
func NewParser() parser.IngressAnnotation {
	return oauth{}
}

// Parse parses oauth annotations and create a Config struct
func (a oauth) Parse(ing *extensions.Ingress) (interface{}, error) {
	var uriPrefix string
	var headers []string
	oauthImpl, _ := parser.GetStringAnnotation(oauthAnn, ing)
	if oauthImpl == "" {
		return &Config{}, nil
	}
	switch oauthImpl {
	case "oauth2_proxy":
		uriPrefix = "/oauth2"
		headers = []string{"X-Auth-Request-Email:auth_response_email"}
	default:
		glog.Warningf("ignoring invalid oauth implementation '%v' on %v/%v", oauthImpl, ing.Namespace, ing.Name)
		return &Config{}, nil
	}
	if uriPrefixTmp, err := parser.GetStringAnnotation(oauthURIPrefixAnn, ing); err == nil {
		uriPrefix = uriPrefixTmp
	}
	if headersTmp, err := parser.GetStringAnnotation(oauthHeadersAnn, ing); err == nil {
		headers = strings.Split(headersTmp, ",")
	}
	uriPrefix = strings.TrimRight(uriPrefix, "/")
	backend := findBackend(uriPrefix, ing)
	if backend == nil {
		return &Config{}, fmt.Errorf("path '%v' was not found on %v/%v", uriPrefix, ing.Namespace, ing.Name)
	}
	// TODO this is a controller construction
	backendName := fmt.Sprintf("%s-%s-%s", ing.Namespace, backend.ServiceName, backend.ServicePort.String())
	headersMap := make(map[string]string, len(headers))
	for _, header := range headers {
		if len(header) == 0 {
			continue
		}
		h := strings.Split(header, ":")
		if len(h) != 2 {
			glog.Warningf("invalid header format '%v' on %v/%v", header, ing.Namespace, ing.Name)
			continue
		}
		headersMap[h[0]] = h[1]
	}
	return &Config{
		OAuthImpl:   oauthImpl,
		URIPrefix:   uriPrefix,
		BackendName: backendName,
		Headers:     headersMap,
	}, nil
}

func findBackend(p string, ing *extensions.Ingress) *extensions.IngressBackend {
	for _, rule := range ing.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			if p == strings.TrimRight(path.Path, "/") {
				return &path.Backend
			}
		}
	}
	return nil
}

// Equal tests equality between two Config objects
func (c1 *Config) Equal(c2 *Config) bool {
	if c1 == c2 {
		return true
	}
	if c1 == nil || c2 == nil {
		return false
	}
	if c1.OAuthImpl != c2.OAuthImpl {
		return false
	}
	if c1.URIPrefix != c2.URIPrefix {
		return false
	}
	if len(c1.Headers) != len(c2.Headers) {
		return false
	}
	for hkey, hval := range c1.Headers {
		if c2.Headers[hkey] != hval {
			return false
		}
	}

	return true
}
