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

var parseURLRegex = regexp.MustCompile(`^([a-z]+)://([-a-z0-9]+/)?([^][/: ]+)(:[-a-z0-9]+)?(/[^"' ]*)?$`)

// ParseURL ...
func ParseURL(url string) (urlProto, urlHost, urlPort, urlPath string, err error) {
	urlParse := parseURLRegex.FindStringSubmatch(url)
	if len(urlParse) < 6 {
		err = fmt.Errorf("invalid URL syntax: %s", url)
		return
	}
	urlProto = urlParse[1]
	namespace := urlParse[2]
	name := urlParse[3]
	urlPort = strings.TrimLeft(urlParse[4], ":")
	urlPath = urlParse[5]
	if namespace != "" {
		// <proto>://<namespace/><name>[:<urlPort>][<urlPath>]`
		if urlPort != "" {
			// port is mandatory on svc proto
			// a matching namespace and a declared port
			// ensures that we have a namespaced service name
			urlHost = namespace + name
		} else {
			// otherwise namespace is the host and name is the start of the path
			urlHost = strings.TrimSuffix(namespace, "/")
			urlPath = "/" + name + urlPath
		}
	} else {
		// <proto>://<name>[:<urlPort>][<urlPath>]`
		urlHost = name
	}
	return
}
