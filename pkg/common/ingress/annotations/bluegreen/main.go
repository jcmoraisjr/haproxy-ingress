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

package bluegreen

import (
	"fmt"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	extensions "k8s.io/api/extensions/v1beta1"
	"strconv"
	"strings"
)

const (
	blueGreenAnn = "ingress.kubernetes.io/blue-green-deploy"
)

// DeployWeight has one label name/value pair and it's weight
type DeployWeight struct {
	LabelName  string
	LabelValue string
	Weight     int
}

// Config is the blue/green deployment configuration
type Config struct {
	DeployWeight []DeployWeight
}

type bgdeploy struct {
}

// NewParser creates a new blue/green annotation parser
func NewParser() parser.IngressAnnotation {
	return bgdeploy{}
}

// Parse parses blue/green annotation and create a Config struct
func (bg bgdeploy) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, err := parser.GetStringAnnotation(blueGreenAnn, ing)
	if err != nil {
		return nil, err
	}
	weights := strings.Split(s, ",")
	var dw []DeployWeight
	for _, weight := range weights {
		dwSlice := strings.Split(weight, "=")
		if len(dwSlice) != 3 {
			return nil, fmt.Errorf("invalid weight format on blue/green config: %v", weight)
		}
		w, err := strconv.ParseInt(dwSlice[2], 10, 0)
		if err != nil {
			return nil, fmt.Errorf("error reading blue/green config: %v", err)
		}
		if w < 0 {
			w = 0
		}
		dwItem := DeployWeight{
			LabelName:  dwSlice[0],
			LabelValue: dwSlice[1],
			Weight:     int(w),
		}
		dw = append(dw, dwItem)
	}
	return &Config{
		DeployWeight: dw,
	}, nil
}

// Equal tests equality between two Config objects
func (b1 *Config) Equal(b2 *Config) bool {
	if len(b1.DeployWeight) != len(b2.DeployWeight) {
		return false
	}
	for _, dw1 := range b1.DeployWeight {
		found := false
		for _, dw2 := range b2.DeployWeight {
			if (&dw1).Equal(&dw2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Equal tests equality between two DeployWeight objects
func (dw1 *DeployWeight) Equal(dw2 *DeployWeight) bool {
	if dw1.LabelName != dw2.LabelName {
		return false
	}
	if dw1.LabelValue != dw2.LabelValue {
		return false
	}
	if dw1.Weight != dw2.Weight {
		return false
	}
	return true
}
