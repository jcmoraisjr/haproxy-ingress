/*
Copyright 2019 The HAProxy Ingress Controller Authors.

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

package utils

import (
	"fmt"
	"regexp"
	"strings"
)

var parseURLRegex = regexp.MustCompile(`^([a-z]+)://([-a-z0-9]+/)?([^][/: ]+)(:[-a-z0-9]+)?([^"' ]*)$`)

// ParseURL ...
func ParseURL(url string) (urlProto, urlHost, urlPort, urlPath string, err error) {
	urlParse := parseURLRegex.FindStringSubmatch(url)
	if len(urlParse) < 6 {
		err = fmt.Errorf("invalid URL syntax: %s", url)
		return
	}
	urlProto = urlParse[1]
	namespace := urlParse[2]
	urlHost = urlParse[3]
	urlPort = strings.TrimLeft(urlParse[4], ":")
	urlPath = urlParse[5]
	if namespace != "" {
		if urlPort == "" && urlPath == "" {
			// the `proto://name/name` case, we want `name/path` instead of `namespace/name`
			// this will probably never happen because, if proto == http/s, the first name
			// should be an IP or a valid hostname, which doesn't match the namespace submatch;
			// if proto == svc, port number is mandatory and would move the second name to the
			// urlPath submatch
			urlPath = "/" + urlHost
			urlHost = strings.TrimSuffix(namespace, "/")
		} else {
			// this is really a namespace, so concatenate
			urlHost = namespace + urlHost
		}
	}
	return
}
