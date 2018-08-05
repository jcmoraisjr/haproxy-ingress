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
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	extensions "k8s.io/api/extensions/v1beta1"
	"regexp"
	"strconv"
	"strings"
)

const (
	blueGreenBalanceAnn = "ingress.kubernetes.io/blue-green-balance"
	blueGreenDeployAnn  = "ingress.kubernetes.io/blue-green-deploy"
	blueGreenModeAnn    = "ingress.kubernetes.io/blue-green-mode"
)

var (
	modeAnnRegex = regexp.MustCompile(`^(pod|deploy)$`)
)

// DeployWeight has one label name/value pair and it's weight
type DeployWeight struct {
	LabelName   string
	LabelValue  string
	PodWeight   int
	PodCount    int
	GroupWeight int
}

// Config is the blue/green deployment configuration
type Config struct {
	DeployWeight []DeployWeight
	Mode         string
}

type bgdeploy struct {
}

// NewParser creates a new blue/green annotation parser
func NewParser() parser.IngressAnnotation {
	return bgdeploy{}
}

// Parse parses blue/green annotation and create a Config struct
func (bg bgdeploy) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, err := parser.GetStringAnnotation(blueGreenBalanceAnn, ing)
	if err != nil {
		s, _ = parser.GetStringAnnotation(blueGreenDeployAnn, ing)
		if s == "" {
			return nil, err
		}
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
			glog.Warningf("invalid weight '%v' on '%v/%v', using '0'", w, ing.Namespace, ing.Name)
			w = 0
		}
		if w > 256 {
			glog.Warningf("invalid weight '%v' on '%v/%v', using '256'", w, ing.Namespace, ing.Name)
			w = 256
		}
		dwItem := DeployWeight{
			LabelName:   dwSlice[0],
			LabelValue:  dwSlice[1],
			PodWeight:   int(w),
			PodCount:    0, // updated in the controller
			GroupWeight: 0, // updated in the controller
		}
		dw = append(dw, dwItem)
	}
	mode, _ := parser.GetStringAnnotation(blueGreenModeAnn, ing)
	if !modeAnnRegex.MatchString(mode) {
		if mode != "" {
			glog.Warningf("unsupported blue/green mode '%v' on '%v/%v', falling back to 'pod'", mode, ing.Namespace, ing.Name)
		}
		mode = "pod"
	}
	return &Config{
		DeployWeight: dw,
		Mode:         mode,
	}, nil
}

// Equal tests equality between two Config objects
func (b1 *Config) Equal(b2 *Config) bool {
	if b1.Mode != b2.Mode {
		return false
	}
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
	if dw1.PodWeight != dw2.PodWeight {
		return false
	}
	return true
}
