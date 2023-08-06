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

// ConverterOptions ...
type ConverterOptions struct {
	Logger           types.Logger
	Cache            Cache
	Tracker          Tracker
	DynamicConfig    *DynamicConfig
	LocalFSPrefix    string
	IsExternal       bool
	MasterSocket     string
	AdminSocket      string
	AcmeSocket       string
	DefaultConfig    func() map[string]string
	DefaultBackend   string
	DefaultCrtSecret string
	FakeCrtFile      CrtFile
	FakeCAFile       CrtFile
	AnnotationPrefix []string
	DisableKeywords  []string
	AcmeTrackTLSAnn  bool
	TrackInstances   bool
	HasGatewayA2     bool
	HasGatewayB1     bool
	EnableEPSlices   bool
}

// DynamicConfig ...
type DynamicConfig struct {
	CrossNamespaceSecretCertificate bool
	CrossNamespaceSecretCA          bool
	CrossNamespaceSecretPasswd      bool
	CrossNamespaceServices          bool
	// config from the command-line for backward compatibility
	StaticCrossNamespaceSecrets bool
}
