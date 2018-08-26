/*
Copyright 2018 The Kubernetes Authors.

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

package controller

import (
	"github.com/golang/glog"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/bluegreen"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/store"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/utils"
)

func weightBalance(upstreams *map[string]*ingress.Backend, podLister store.PodLister) {
	// calc deployment weight based on blue/green config or draining state
	for _, upstream := range *upstreams {
		svc := upstream.Service
		podNamespace := svc.Namespace
		deployWeight := upstream.BlueGreen.DeployWeight
		hasBlueGreenDeploy := false
		for epID := range upstream.Endpoints {
			ep := &upstream.Endpoints[epID]
			if ep.Draining {
				// draining state always set Weight to 0, independent of a blue/green config
				ep.Weight = 0
				continue
			}
			if len(deployWeight) == 0 {
				// no blue/green config, using default Weight config as 1 and skipping to the next
				ep.Weight = 1
				continue
			}
			if ep.Target == nil {
				glog.Warningf("ignoring blue/green config due to empty object reference on endpoint %v/%v", podNamespace, upstream.Name)
				ep.Weight = 1
				continue
			}
			podName := ep.Target.Name
			var weightRef *bluegreen.DeployWeight
			if pod, err := podLister.GetPod(podNamespace, podName); err == nil {
				for wID := range deployWeight {
					weightConfig := &deployWeight[wID]
					if label, found := pod.Labels[weightConfig.LabelName]; found {
						if label == weightConfig.LabelValue {
							if weightRef == nil {
								weightRef = weightConfig
								weightRef.PodCount++
								hasBlueGreenDeploy = true
							} else if !weightRef.Equal(weightConfig) {
								glog.Warningf("deployment weight %v to service %v/%v is duplicated and was ignored", weightConfig.PodWeight, podNamespace, svc.Name)
							}
						}
					} else {
						glog.Warningf("pod %v/%v does not have label %v used on blue/green deployment", podNamespace, podName, weightConfig.LabelName)
					}
				}
			} else {
				glog.Warningf("could not calc weight of pod %v/%v: %v", podNamespace, podName, err)
			}
			ep.WeightRef = weightRef
			if weightRef != nil {
				ep.Weight = weightRef.PodWeight
			} else {
				// weight wasn't assigned, set as zero to remove all the traffic
				// without removing from the balancer
				ep.Weight = 0
			}
		}
		if !hasBlueGreenDeploy || upstream.BlueGreen.Mode == "pod" {
			// if not hasBlueGreenDeploy, nothing more to do
			// if Mode == "pod", weight is already correct
			continue
		}
		// At this moment ep.Weight refers to every single pod instead of the blue and green groups.
		// Now recalc based on the number of pods on each group.
		lcmPodCount := 0
		for _, weightConfig := range deployWeight {
			if weightConfig.PodCount == 0 {
				continue
			}
			podCount := weightConfig.PodCount
			if lcmPodCount > 0 {
				lcmPodCount = utils.LCM(lcmPodCount, podCount)
			} else {
				lcmPodCount = podCount
			}
		}
		if lcmPodCount == 0 {
			// all PodCount are zero, this config won't be used
			continue
		}
		gcdGroupWeight := 0
		maxWeight := 0
		for _, weightConfig := range deployWeight {
			if weightConfig.PodCount == 0 || weightConfig.PodWeight == 0 {
				continue
			}
			groupWeight := weightConfig.PodWeight * lcmPodCount / weightConfig.PodCount
			if gcdGroupWeight > 0 {
				gcdGroupWeight = utils.GCD(gcdGroupWeight, groupWeight)
			} else {
				gcdGroupWeight = groupWeight
			}
			if groupWeight > maxWeight {
				maxWeight = groupWeight
			}
		}
		if gcdGroupWeight == 0 {
			// all PodWeight are zero, no need to rebalance
			continue
		}
		// HAProxy weight must be between 0..256.
		// weightFactor has how many times the max weight is greater than 256.
		weightFactor := float32(maxWeight) / float32(gcdGroupWeight) / float32(256)
		// LCM of denominators and GCD of the results are known. Updating ep.Weight
		for epID := range upstream.Endpoints {
			ep := &upstream.Endpoints[epID]
			if ep.WeightRef != nil {
				wRef := ep.WeightRef
				w := wRef.PodWeight * lcmPodCount / wRef.PodCount / gcdGroupWeight
				if weightFactor > 1 {
					propWeight := int(float32(w) / weightFactor)
					if propWeight == 0 && wRef.PodWeight > 0 {
						propWeight = 1
					}
					ep.Weight = propWeight
				} else {
					ep.Weight = w
				}
			}
		}
	}
}
