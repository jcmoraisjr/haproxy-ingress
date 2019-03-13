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
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// File ...
type File struct {
	Filename string
	SHA1Hash string
}

// ConverterOptions ...
type ConverterOptions struct {
	Logger           types.Logger
	Cache            Cache
	DefaultBackend   string
	DefaultSSLFile   File
	AnnotationPrefix string
}
