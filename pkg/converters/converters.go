/*
Copyright 2021 The HAProxy Ingress Controller Authors.

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

package converters

import (
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/configmap"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/gateway"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// Config ...
type Config interface {
	Sync()
}

// NewConverter ...
func NewConverter(timer *utils.Timer, haproxy haproxy.Config, changed *convtypes.ChangedObjects, options *convtypes.ConverterOptions) Config {
	return &converters{
		timer:   timer,
		haproxy: haproxy,
		changed: changed,
		options: options,
	}
}

type converters struct {
	timer   *utils.Timer
	haproxy haproxy.Config
	changed *convtypes.ChangedObjects
	options *convtypes.ConverterOptions
}

func (c *converters) Sync() {
	changed := c.changed
	if changed == nil {
		changed = c.options.Cache.SwapChangedObjects()
	}
	ingressConverter := ingress.NewIngressConverter(c.options, c.haproxy, changed)
	gatewayConverter := gateway.NewGatewayConverter(c.options, c.haproxy, changed, ingressConverter)

	needFullSync := changed.NeedFullSync ||
		gatewayConverter.NeedFullSync() ||
		ingressConverter.NeedFullSync()
	if needFullSync {
		c.options.Tracker.ClearLinks()
		c.haproxy.Clear()
	}
	l := len(changed.Objects)
	if l > 100 {
		c.options.Logger.InfoV(2, "applying %d change notifications", l)
	} else if l > 1 {
		c.options.Logger.InfoV(2, "applying %d change notifications: %v", l, changed.Objects)
	} else if l == 1 {
		c.options.Logger.InfoV(2, "applying 1 change notification: %v", changed.Objects)
	}

	//
	// gateway converter
	//
	if c.options.HasGatewayV1 {
		gatewayConverter.Sync(needFullSync, &gatewayv1.Gateway{})
	}
	if c.options.HasGatewayB1 {
		gatewayConverter.Sync(needFullSync, &gatewayv1beta1.Gateway{})
	}
	if c.options.HasGatewayA2 {
		gatewayConverter.Sync(needFullSync, &gatewayv1alpha2.Gateway{})
	}
	if c.options.HasGatewayA2 || c.options.HasGatewayB1 || c.options.HasGatewayV1 {
		c.timer.Tick("parse_gateway")
	}

	//
	// ingress converter
	//
	ingressConverter.Sync(needFullSync)
	c.timer.Tick("parse_ingress")

	//
	// configmap converters
	//
	if changed.TCPConfigMapDataCur != nil || changed.TCPConfigMapDataNew != nil {
		// We always need to run configmap based tcp sync, when configured, because
		// we don't have any tracking in place asking us to do it on, e.g., endpoint
		// or secret updates. Although cur is always assigned if configmap based tcp
		// is configured, only new is assigned in the very first run. OTOH, new is
		// only assigned when the configmap is changed. So we need to check both.
		tcpSvcConverter := configmap.NewTCPServicesConverter(c.options, c.haproxy, changed)
		tcpSvcConverter.Sync()
		c.timer.Tick("parse_tcp_svc")
	}

}
