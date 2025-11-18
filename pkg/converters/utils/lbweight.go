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

package utils

// WeightCluster ...
type WeightCluster struct {
	Weight int
	Length int
}

// RebalanceWeight ...
func RebalanceWeight(clusters []*WeightCluster, initialWeight int) {
	lcmCount := 0
	for _, cl := range clusters {
		if cl.Length == 0 {
			continue
		}
		if lcmCount > 0 {
			lcmCount = lcm(lcmCount, cl.Length)
		} else {
			lcmCount = cl.Length
		}
	}
	if lcmCount == 0 {
		// all lengths are zero, no need to rebalance
		return
	}
	gcdClusterWeight := 0
	minWeight := -1
	maxWeight := 0
	for _, cl := range clusters {
		if cl.Length == 0 || cl.Weight == 0 {
			continue
		}
		clusterWeight := cl.Weight * lcmCount / cl.Length
		if gcdClusterWeight > 0 {
			gcdClusterWeight = gcd(gcdClusterWeight, clusterWeight)
		} else {
			gcdClusterWeight = clusterWeight
		}
		if clusterWeight < minWeight || minWeight < 0 {
			minWeight = clusterWeight
		}
		if clusterWeight > maxWeight {
			maxWeight = clusterWeight
		}
	}
	if gcdClusterWeight == 0 {
		// all weights are zero, no need to rebalance
		return
	}
	// Agent works better if weight is `initial-weight` or
	// at least the higher value weightFactor will let it to be
	// weightFactorMin has how many times minWeight is less than `initial-weight`.
	weightFactorMin := float32(initialWeight*gcdClusterWeight) / float32(minWeight)
	// HAProxy weight must be between 0..256.
	// weightFactor has how many times the max weight will be greater than 256.
	weightFactor := weightFactorMin * float32(maxWeight) / float32(256*gcdClusterWeight)
	// LCM of denominators and GCD of the results are known. Updating ep.Weight
	for _, cl := range clusters {
		weight := weightFactorMin * float32(cl.Weight*lcmCount) / float32(cl.Length*gcdClusterWeight)
		if weightFactor > 1 {
			propWeight := int(weight / weightFactor)
			if propWeight == 0 && cl.Weight > 0 {
				propWeight = 1
			}
			cl.Weight = propWeight
		} else {
			cl.Weight = int(weight)
		}
	}
}

// gcd calculates the Greatest Common Divisor between a and b
func gcd(a, b int) int {
	for b != 0 {
		r := a % b
		a, b = b, r
	}
	return a
}

// lcm calculates the Least Common Multiple between a and b
func lcm(a, b int) int {
	return a * (b / gcd(a, b))
}
