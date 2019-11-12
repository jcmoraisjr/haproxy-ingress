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

package types

import (
	"fmt"
)

func (dns *DNSConfig) String() string {
	return fmt.Sprintf("%+v", *dns)
}

func (dns *DNSResolver) String() string {
	return fmt.Sprintf("%+v", *dns)
}

func (dns *DNSNameserver) String() string {
	return fmt.Sprintf("%+v", *dns)
}

func (u *Userlist) String() string {
	return fmt.Sprintf("%+v", *u)
}

// ShareHTTPPort ...
func (b GlobalBindConfig) ShareHTTPPort() bool {
	return b.HasFrontingProxy() && b.HTTPBindIP == b.ToHTTPBindIP && b.HTTPPort == b.ToHTTPPort
}

// HasFrontingProxy ...
func (b GlobalBindConfig) HasFrontingProxy() bool {
	return b.ToHTTPPort > 0
}
