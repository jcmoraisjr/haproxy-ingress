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

package helper_test

// BindUtilsMock ...
type BindUtilsMock struct {
	CertDirs []*CertDir
}

// CertDir ...
type CertDir struct {
	Dir   string
	Certs []string
}

// CreateX509CertsDir ...
func (b *BindUtilsMock) CreateX509CertsDir(bindName string, certs []string) (string, error) {
	dir := "/var/haproxy/certs/" + bindName
	b.CertDirs = append(b.CertDirs, &CertDir{
		Dir:   dir,
		Certs: certs,
	})
	return dir, nil
}
