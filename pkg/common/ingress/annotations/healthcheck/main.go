/*
Copyright 2016 The Kubernetes Authors.

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

package healthcheck

import (
	"strconv"

	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/errors"
)

const (
	healthCheckURI       = "ingress.kubernetes.io/health-check-uri"
	healthCheckAddr      = "ingress.kubernetes.io/health-check-addr"
	healthCheckPort      = "ingress.kubernetes.io/health-check-port"
	healthCheckInterval  = "ingress.kubernetes.io/health-check-interval"
	healthCheckRiseCount = "ingress.kubernetes.io/health-check-rise-count"
	healthCheckFallCount = "ingress.kubernetes.io/health-check-fall-count"
)

// Config contains the health check configuration for a backend
type Config struct {
	URI       string `json:"uri"`
	Addr      string `json:"addr"`
	Port      string `json:"port"`
	Interval  string `json:"interval"`
	RiseCount string `json:"rise-count"`
	FallCount string `json:"fall-count"`
}

// Equal tests equality between two Config objects
func (b1 *Config) Equal(b2 *Config) bool {
	if b1.URI != b2.URI {
		return false
	}
	if b1.Addr != b2.Addr {
		return false
	}
	if b1.Port != b2.Port {
		return false
	}
	if b1.Interval != b2.Interval {
		return false
	}
	if b1.RiseCount != b2.RiseCount {
		return false
	}
	if b1.FallCount != b2.FallCount {
		return false
	}
	return true
}

// NewParser creates a new health check annotation parser
func NewParser() parser.IngressAnnotation {
	return healthCheck{}
}

type healthCheck struct {
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to configure health check parameters
func (a healthCheck) Parse(ing *extensions.Ingress) (interface{}, error) {
	uri, _ := parser.GetStringAnnotation(healthCheckURI, ing)

	addr, err := parser.GetStringAnnotation(healthCheckAddr, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, healthCheckAddr)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, healthCheckAddr)
		}
	}

	var port string
	portInt, err := parser.GetIntAnnotation(healthCheckPort, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, healthCheckPort)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, healthCheckPort)
		}
	} else {
		port = strconv.Itoa(portInt)
	}

	var inter string
	interInt, err := parser.GetIntAnnotation(healthCheckInterval, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, healthCheckInterval)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, healthCheckInterval)
		}
	} else {
		inter = strconv.Itoa(interInt)
	}

	var rise string
	riseInt, err := parser.GetIntAnnotation(healthCheckRiseCount, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, healthCheckRiseCount)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, healthCheckRiseCount)
		}
	} else {
		rise = strconv.Itoa(riseInt)
	}

	var fall string
	fallInt, err := parser.GetIntAnnotation(healthCheckFallCount, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, healthCheckFallCount)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, healthCheckFallCount)
		}
	} else {
		fall = strconv.Itoa(fallInt)
	}

	return &Config{uri, addr, port, inter, rise, fall}, nil
}
