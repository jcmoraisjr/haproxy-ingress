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
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func initSvcStatusIng(ctx context.Context, config *config.Config, client client.Client, cache *c, status svcStatusUpdateFnc) *svcStatusIng {
	return &svcStatusIng{
		log:    logr.FromContextOrDiscard(ctx).WithName("status").WithName("ingress"),
		cfg:    config,
		cli:    client,
		cache:  cache,
		status: status,
		period: time.Minute,
	}
}

type svcStatusIng struct {
	log    logr.Logger
	cfg    *config.Config
	cli    client.Client
	run    bool
	cache  *c
	status svcStatusUpdateFnc
	period time.Duration
	curr   []networking.IngressLoadBalancerIngress
}

func (s *svcStatusIng) Start(ctx context.Context) error {
	s.run = true
	<-ctx.Done()
	s.run = false

	// we need a new context, the one provided by the controller is canceled already.
	// this context's timeout is 90% of the manager's shutdown timeout
	timeout := *s.cfg.ShutdownTimeout * 9 / 10
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	s.shutdown(shutdownCtx)
	cancel()
	return nil
}

// changed.Objects ([]string) has currently the following syntax:
// <add|update|del>/<resourceType>:[<namespace>/]<name>
// Need to move to a structured type.
const addIngPrefix = "add/" + string(convtypes.ResourceIngress) + ":"

func (s *svcStatusIng) changed(ctx context.Context, timer *utils.Timer, changed *convtypes.ChangedObjects) error {
	if !s.run {
		if s.cfg.UpdateStatus {
			s.log.Info("skipping check for ingress status changes, I am not the leader")
		}
		return nil
	}
	defer timer.Tick("enqueue-status-update")

	// check if lb address(es) changed, updating s.curr and resyncing all ingress if so.
	if err := s.syncCurrentLB(ctx); err != nil {
		return err
	}

	var errs []error
	for _, obj := range changed.Objects {
		if strings.HasPrefix(obj, addIngPrefix) {
			fullname := obj[len(addIngPrefix):]
			ns, n, _ := cache.SplitMetaNamespaceKey(fullname)
			ing := networking.Ingress{}
			err := s.cli.Get(ctx, types.NamespacedName{Namespace: ns, Name: n}, &ing)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			ing.Status.LoadBalancer.Ingress = s.curr
			s.status(&ing)
		}
	}
	if len(errs) > 0 {
		if len(errs) > 6 {
			errs = errs[:6]
			errs[5] = fmt.Errorf("<...>")
		}
		return fmt.Errorf("error syncing ingress status: %w", errors.Join(errs...))
	}
	return nil
}

func (s *svcStatusIng) update(_ context.Context, lb []networking.IngressLoadBalancerIngress) error {
	ingList, err := s.cache.GetIngressList()
	if err != nil {
		return err
	}
	for _, ing := range ingList {
		ing.Status.LoadBalancer.Ingress = lb
		s.status(ing)
	}
	return nil
}

func (s *svcStatusIng) shutdown(ctx context.Context) {
	if !s.cfg.UpdateStatusOnShutdown {
		s.log.Info("skipping status update due to --update-status-on-shutdown=false")
		return
	}
	if podList, err := s.getControllerPodList(ctx); len(podList) > 1 {
		s.log.Info(fmt.Sprintf("running %d controller replicas, leaving the status update to the next leader", len(podList)))
		return
	} else if err != nil {
		s.log.Error(err, "failed to check if there are more controller replicas running; status will not be updated")
		return
	}
	s.log.Info("no other controller running, removing address from ingress status")
	if err := s.update(ctx, nil); err != nil {
		s.log.Error(err, "error listing ingress resources for status update")
	}
}

func (s *svcStatusIng) syncCurrentLB(ctx context.Context) error {
	var lb []networking.IngressLoadBalancerIngress
	if s.cfg.PublishService != "" {
		// read Hostnames and IPs from the configured service
		svc := api.Service{}
		ns, n, _ := cache.SplitMetaNamespaceKey(s.cfg.PublishService)
		if err := s.cli.Get(ctx, types.NamespacedName{Namespace: ns, Name: n}, &svc); err != nil {
			return fmt.Errorf("failed to read load balancer service: %w", err)
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
		s.log.Error(fmt.Errorf("cannot configure ingress status due to a failure reading the published hostnames/IPs"), ""+
			"error configuring ingress status, either fix the configuration or the permission failures, "+
			"configure --publish-service or --publish-address command-line options, "+
			"or disable status update with --update-status=false")
	}
	sort.Slice(lb, func(i, j int) bool {
		if lb[i].Hostname == lb[j].Hostname {
			return lb[i].IP < lb[j].IP
		}
		return lb[i].Hostname < lb[j].Hostname
	})
	if !reflect.DeepEqual(s.curr, lb) {
		s.log.Info("list of load balancers changed, updating all ingress status", "old", s.curr, "new", lb)
		if err := s.update(ctx, lb); err != nil {
			return fmt.Errorf("error updating ingress resources: %w", err)
		}
		s.curr = lb
	}
	return nil
}

// getNodeIPs reads external node IP, or internal if
// config.UseNodeInternalIP == true, from every controller pod.
func (s *svcStatusIng) getNodeIPs(ctx context.Context) []string {
	podList, err := s.getControllerPodList(ctx)
	if err != nil {
		s.log.Error(err, "failed reading the list of controller's pods")
		return nil
	}
	// read node IPs where the controller replicas are running
	var iplist []string
	for _, ctr := range podList {
		node := api.Node{}
		if err := s.cli.Get(ctx, types.NamespacedName{Name: ctr.Spec.NodeName}, &node); err != nil {
			s.log.Error(err, "failed reading node info")
			return nil
		}
		ipnode := func() string {
			for _, addr := range node.Status.Addresses {
				if addr.Address == "" {
					continue
				}
				if s.cfg.UseNodeInternalIP && addr.Type == api.NodeInternalIP {
					return addr.Address
				}
				if !s.cfg.UseNodeInternalIP && addr.Type == api.NodeExternalIP {
					return addr.Address
				}
			}
			return ""
		}()
		exists := func() bool {
			for _, ip := range iplist {
				if ip == ipnode {
					return true
				}
			}
			return false
		}()
		if !exists {
			iplist = append(iplist, ipnode)
		}
	}
	return iplist
}

func (s *svcStatusIng) getControllerPodList(ctx context.Context) ([]api.Pod, error) {
	pod := api.Pod{}
	if err := s.cli.Get(ctx, s.cfg.ControllerPod, &pod); err != nil {
		return nil, err
	}

	// remove labels that uniquely identify a pod
	podLabels := pod.GetLabels()
	delete(podLabels, "controller-revision-hash")
	delete(podLabels, "pod-template-generation")
	delete(podLabels, "pod-template-hash")
	delete(podLabels, "apps.kubernetes.io/pod-index")
	delete(podLabels, "statefulset.kubernetes.io/pod-name")

	// read all controller's pod
	podList := api.PodList{}
	if err := s.cli.List(ctx, &podList, &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(podLabels),
		Namespace:     s.cfg.ControllerPod.Namespace,
	}); err != nil {
		return nil, err
	}
	return podList.Items, nil
}
