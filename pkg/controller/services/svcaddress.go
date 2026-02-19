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

package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"

	"github.com/go-logr/logr"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func initSvcAddress(ctx context.Context, config *config.Config, client client.Client, cache *c) *svcAddress {
	return &svcAddress{
		log:   logr.FromContextOrDiscard(ctx).WithName("address"),
		cfg:   config,
		cli:   client,
		cache: cache,
	}
}

type svcAddress struct {
	log   logr.Logger
	cfg   *config.Config
	cli   client.Client
	run   bool
	cache *c
	curr  []networking.IngressLoadBalancerIngress
}

func (s *svcAddress) Start(ctx context.Context) error {
	s.run = true
	<-ctx.Done()
	s.run = false
	s.shutdown()
	return nil
}

func (s *svcAddress) checkChanged(ctx context.Context, timer *utils.Timer, changed *convtypes.ChangedObjects) error {
	if !s.run {
		if s.cfg.UpdateStatus {
			s.log.Info("skipping check for address status changes, I am not the leader")
		}
		return nil
	}
	defer timer.Tick("address-status-update")

	lb, err := s.readCurrentLB(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s.curr, lb) {
		s.log.Info("list of load balancers changed, checking all address status", "old", s.curr, "new", lb)
		if err := s.updateAllResources(lb); err != nil {
			return fmt.Errorf("error updating resources: %w", err)
		}
		s.log.Info("all address status are updated")
		s.curr = lb
		return nil
	}

	var errs []error
	for _, fullname := range changed.Links[convtypes.ResourceIngress] {
		namespace, name, _ := cache.SplitMetaNamespaceKey(fullname)
		if err := s.updateIngressStatus(namespace, name, lb); err != nil {
			errs = append(errs, err)
		}
	}
	for _, fullname := range changed.Links[convtypes.ResourceGateway] {
		namespace, name, _ := cache.SplitMetaNamespaceKey(fullname)
		if err := s.updateGatewayStatus(namespace, name, gwAddress(lb)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error syncing address status: %w", shrinkErrors(errs))
	}
	return nil
}

func (s *svcAddress) updateAllResources(lb []networking.IngressLoadBalancerIngress) error {
	ingList, err := s.cache.GetIngressList()
	if err != nil {
		return err
	}
	gwList, err := s.cache.GetGatewayList()
	if err != nil {
		return err
	}
	s.log.Info("checking address status", "ingress-count", len(ingList), "gateway-count", len(gwList))
	var errs []error
	for _, ing := range ingList {
		if err := s.updateIngressStatus(ing.Namespace, ing.Name, lb); err != nil {
			errs = append(errs, err)
		}
	}
	for _, gw := range gwList {
		if err := s.updateGatewayStatus(gw.Namespace, gw.Name, gwAddress(lb)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error syncing address status: %w", shrinkErrors(errs))
	}
	return nil
}

func (s *svcAddress) updateIngressStatus(namespace, name string, lb []networking.IngressLoadBalancerIngress) error {
	ing := &networking.Ingress{}
	ing.Namespace = namespace
	ing.Name = name
	return s.updateStatus(ing, func() bool {
		if reflect.DeepEqual(ing.Status.LoadBalancer.Ingress, lb) {
			return false
		}
		ing.Status.LoadBalancer.Ingress = lb
		return true
	})
}

func (s *svcAddress) updateGatewayStatus(namespace, name string, lb []gatewayv1.GatewayStatusAddress) error {
	gw := &gatewayv1.Gateway{}
	gw.Namespace = namespace
	gw.Name = name
	return s.updateStatus(gw, func() bool {
		if reflect.DeepEqual(gw.Status.Addresses, lb) {
			return false
		}
		gw.Status.Addresses = lb
		return true
	})
}

func (s *svcAddress) updateStatus(namedObj client.Object, apply func() bool) error {
	var changed bool
	err := s.cache.UpdateStatus(namedObj, func() bool {
		if !apply() {
			return false
		}
		changed = true
		return true
	}, convtypes.CacheOptions{SkipLeaderCheck: true})
	if err == nil && changed {
		s.log.WithValues("kind", reflect.TypeOf(namedObj), "namespace", namedObj.GetNamespace(), "name", namedObj.GetName()).V(1).Info("address status updated")
	}
	return err
}

func gwAddress(lb []networking.IngressLoadBalancerIngress) (address []gatewayv1.GatewayStatusAddress) {
	for _, addr := range lb {
		if addr.Hostname != "" {
			address = append(address, gatewayv1.GatewayStatusAddress{
				Type:  ptr.To(gatewayv1.HostnameAddressType),
				Value: addr.Hostname,
			})
		}
		if addr.IP != "" {
			address = append(address, gatewayv1.GatewayStatusAddress{
				Type:  ptr.To(gatewayv1.IPAddressType),
				Value: addr.IP,
			})
		}
	}
	return address
}

func shrinkErrors(errs []error) error {
	if len(errs) > 6 {
		errs = errs[:6]
		errs[5] = fmt.Errorf("<...>")
	}
	return errors.Join(errs...)
}

func (s *svcAddress) shutdown() {
	if !s.cfg.UpdateStatusOnShutdown {
		s.log.Info("skipping status update due to --update-status-on-shutdown=false")
		return
	}
	if podList, err := s.cache.GetControllerPodList(); len(podList) > 1 {
		s.log.Info(fmt.Sprintf("running %d controller replicas, leaving the status update to the next leader", len(podList)))
		return
	} else if err != nil {
		s.log.Error(err, "failed to check if there are more controller replicas running; status will not be updated")
		return
	}
	s.log.Info("no other controller running, removing address from status")
	if err := s.updateAllResources(nil); err != nil {
		s.log.Error(err, "error updating resources")
	}
}

func (s *svcAddress) readCurrentLB(ctx context.Context) (lb []networking.IngressLoadBalancerIngress, err error) {
	if s.cfg.PublishService != "" {
		// read Hostnames and IPs from the configured service
		svc := api.Service{}
		ns, n, _ := cache.SplitMetaNamespaceKey(s.cfg.PublishService)
		if err := s.cli.Get(ctx, types.NamespacedName{Namespace: ns, Name: n}, &svc); err != nil {
			return nil, fmt.Errorf("failed to read load balancer service: %w", err)
		}
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			lb = append(lb, networking.IngressLoadBalancerIngress{IP: ing.IP, Hostname: ing.Hostname})
		}
		for _, ip := range svc.Spec.ExternalIPs {
			lb = append(lb, networking.IngressLoadBalancerIngress{IP: ip})
		}
	} else if len(s.cfg.PublishAddressHostnames)+len(s.cfg.PublishAddressIPs) > 0 {
		// read Hostnames and IPs from the static option
		for _, addr := range s.cfg.PublishAddressHostnames {
			lb = append(lb, networking.IngressLoadBalancerIngress{Hostname: addr})
		}
		for _, addr := range s.cfg.PublishAddressIPs {
			lb = append(lb, networking.IngressLoadBalancerIngress{IP: addr})
		}
	} else if iplist := s.getNodeIPs(ctx); len(iplist) > 0 {
		// read IPs from the nodes where the controllers are running
		// if the controller has permission to do so.
		for _, ip := range iplist {
			lb = append(lb, networking.IngressLoadBalancerIngress{IP: ip})
		}
	} else {
		// fall back to an empty list and log an error if everything else failed
		s.log.Error(fmt.Errorf("cannot configure address status due to a failure reading the published hostnames/IPs"), ""+
			"error configuring address status, either fix the configuration or the permission failures, "+
			"configure --publish-service or --publish-address command-line options, "+
			"or disable status update with --update-status=false")
	}
	sort.Slice(lb, func(i, j int) bool {
		if lb[i].Hostname == lb[j].Hostname {
			return lb[i].IP < lb[j].IP
		}
		return lb[i].Hostname < lb[j].Hostname
	})
	return lb, nil
}

// getNodeIPs reads external node IPs, or internal if
// config.UseNodeInternalIP == true, from every controller pod.
// On dual-stack nodes, all addresses of the matching type are collected,
// allowing both IPv4 and IPv6 addresses to be reported in the status.
func (s *svcAddress) getNodeIPs(ctx context.Context) []string {
	podList, err := s.cache.GetControllerPodList()
	if err != nil {
		s.log.Error(err, "failed reading the list of controller's pods")
		return nil
	}
	targetType := api.NodeExternalIP
	if s.cfg.UseNodeInternalIP {
		targetType = api.NodeInternalIP
	}
	// read node IPs where the controller replicas are running
	var iplist []string
	for _, ctr := range podList {
		node := api.Node{}
		if err := s.cli.Get(ctx, types.NamespacedName{Name: ctr.Spec.NodeName}, &node); err != nil {
			s.log.Error(err, "failed reading node info")
			return nil
		}
		for _, addr := range node.Status.Addresses {
			if addr.Address == "" || addr.Type != targetType {
				continue
			}
			if !slices.Contains(iplist, addr.Address) {
				iplist = append(iplist, addr.Address)
			}
		}
	}
	return iplist
}
