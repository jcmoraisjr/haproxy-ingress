/*
Copyright 2026 The HAProxy Ingress Controller Authors.

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

package ingress

import (
	"maps"
	"reflect"
	"strings"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/annotations"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// ConfigGlobal ...
type ConfigGlobal interface {
	NeedFullSync() bool
	Sync(full bool) error
}

// TODO: decouple global and ingress converters, and move global to its own package.
// Currently the configuration is already decoupled, but the global scope in the
// updater still shares some types and methods with the ingress counterpart.

// NewGlobalConverter ...
func NewGlobalConverter(options *convtypes.ConverterOptions, haproxy haproxy.Config, changed *convtypes.ChangedObjects) ConfigGlobal {
	logger := options.Logger
	cache := options.Cache
	defaultCrt := options.FakeCrtFile
	updater := annotations.NewUpdater(haproxy, options)
	mapper := newGlobalMapBuilder(options, changed).NewMapper()
	if options.DefaultCrtSecret != "" {
		var err error
		defaultCrt, err = cache.GetTLSSecretPath("", options.DefaultCrtSecret, nil)
		if err != nil {
			defaultCrt = options.FakeCrtFile
			logger.Warn("using auto generated fake certificate due to an error reading default TLS certificate: %v", err)
		}
	}
	c := &converterGlobal{
		logger:     logger,
		options:    options,
		haproxy:    haproxy,
		changed:    changed,
		cache:      cache,
		updater:    updater,
		mapper:     mapper,
		defaultCrt: defaultCrt,
	}
	return c
}

func newGlobalMapBuilder(options *convtypes.ConverterOptions, changed *convtypes.ChangedObjects) *annotations.MapBuilder {
	defaults := createDefaults()
	if options.DefaultsOverride != nil {
		maps.Copy(defaults, options.DefaultsOverride)
	}
	customConfig := changed.GlobalConfigMapDataNew
	if customConfig == nil {
		customConfig = changed.GlobalConfigMapDataCur
	}
	maps.Copy(defaults, customConfig)
	return annotations.NewMapBuilder(options.Logger, defaults)
}

type converterGlobal struct {
	logger     types.Logger
	options    *convtypes.ConverterOptions
	haproxy    haproxy.Config
	changed    *convtypes.ChangedObjects
	cache      convtypes.Cache
	updater    annotations.Updater
	mapper     *annotations.Mapper
	defaultCrt convtypes.CrtFile
}

func (c *converterGlobal) NeedFullSync() bool {
	crtHash := c.haproxy.Global().SSL.DefaultCrt.Hash
	needFullSync := crtHash != c.defaultCrt.SHA1Hash

	if !needFullSync {
		// global changes need a full sync because part of these keys
		// are default values for ingress annotations
		cmCurr, cmNew := c.changed.GlobalConfigMapDataCur, c.changed.GlobalConfigMapDataNew
		needFullSync = cmNew != nil && !reflect.DeepEqual(cmCurr, cmNew)
	}

	if needFullSync && crtHash == c.options.FakeCrtFile.SHA1Hash {
		c.logger.Info("using auto generated fake certificate")
	}

	return needFullSync
}

func (c *converterGlobal) Sync(full bool) error {
	if full {
		return c.syncFull()
	}
	return c.syncPartial()
}

func (c *converterGlobal) syncFull() error {
	c.updater.UpdateGlobalConfig(c.mapper)
	c.haproxy.Global().SSL.DefaultCrt = hatypes.CertificateConfig{
		Filename:   c.defaultCrt.Filename,
		Hash:       c.defaultCrt.SHA1Hash,
		CommonName: c.defaultCrt.Certificate.Subject.CommonName,
		NotAfter:   c.defaultCrt.Certificate.NotAfter,
	}
	return nil
}

func (c *converterGlobal) syncPartial() error {
	if c.mapper.Get(ingtypes.GlobalPeersPort).Int() != 0 {
		// looking for controller pod changes, used by peers.
		// missing a better tracking and global update approach.
		ctrlNamespace := c.cache.GetControllerPod().Namespace + "/"
		changedPods := c.changed.Links[convtypes.ResourcePod]
		for _, pod := range changedPods {
			if strings.HasPrefix(pod, ctrlNamespace) {
				c.logger.Info("updating peers due to changes in controller pods")
				c.updater.UpdatePeers(c.mapper)
				break
			}
		}
	}
	return nil
}
