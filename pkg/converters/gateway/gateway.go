/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package gateway

import (
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// Config ...
type Config interface {
	NeedFullSync() bool
	Sync(full bool)
}

// NewGatewayConverter ...
func NewGatewayConverter(options *convtypes.ConverterOptions, haproxy haproxy.Config, changed *convtypes.ChangedObjects, annotationReader convtypes.AnnotationReader) Config {
	return &converter{
		options: options,
		haproxy: haproxy,
		changed: changed,
		logger:  options.Logger,
		cache:   options.Cache,
		tracker: options.Tracker,
		ann:     annotationReader,
	}
}

type converter struct {
	options *convtypes.ConverterOptions
	haproxy haproxy.Config
	changed *convtypes.ChangedObjects
	logger  types.Logger
	cache   convtypes.Cache
	tracker convtypes.Tracker
	ann     convtypes.AnnotationReader
}

func (c *converter) NeedFullSync() bool {
	links := c.tracker.QueryLinks(convtypes.TrackingLinks{
		convtypes.ResourceSecret:    c.changed.Links[convtypes.ResourceSecret],
		convtypes.ResourceService:   c.changed.Links[convtypes.ResourceService],
		convtypes.ResourceEndpoints: c.changed.Links[convtypes.ResourceEndpoints],
	}, false)
	_, changed := links[convtypes.ResourceGateway]
	return changed
}

func (c *converter) Sync(full bool) {
	if !full {
		return
	}
	// TODO implement
}
