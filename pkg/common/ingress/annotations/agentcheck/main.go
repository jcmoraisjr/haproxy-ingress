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

package agentcheck

import (
	"strconv"

	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/errors"
)

const (
	agentCheckAddr     = "ingress.kubernetes.io/agent-check-addr"
	agentCheckPort     = "ingress.kubernetes.io/agent-check-port"
	agentCheckInterval = "ingress.kubernetes.io/agent-check-interval"
	agentCheckSend     = "ingress.kubernetes.io/agent-check-send"
)

// Config contains the agent check configuration for a backend
type Config struct {
	Addr     string `json:"addr"`
	Port     string `json:"port"`
	Interval string `json:"interval"`
	Send     string `json:"send"`
}

// Equal tests equality between two Config objects
func (b1 *Config) Equal(b2 *Config) bool {
	if b1.Addr != b2.Addr {
		return false
	}
	if b1.Port != b2.Port {
		return false
	}
	if b1.Interval != b2.Interval {
		return false
	}
	if b1.Send != b2.Send {
		return false
	}
	return true
}

// NewParser creates a new agent check annotation parser
func NewParser() parser.IngressAnnotation {
	return agentCheck{}
}

type agentCheck struct {
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to configure agent check parameters
func (a agentCheck) Parse(ing *extensions.Ingress) (interface{}, error) {
	addr, err := parser.GetStringAnnotation(agentCheckAddr, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, agentCheckAddr)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, agentCheckAddr)
		}
	}

	var port string
	portInt, err := parser.GetIntAnnotation(agentCheckPort, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, agentCheckPort)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, agentCheckPort)
		}
	} else {
		port = strconv.Itoa(portInt)
	}

	inter, err := parser.GetStringAnnotation(agentCheckInterval, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, agentCheckInterval)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, agentCheckInterval)
		}
	}

	send, err := parser.GetStringAnnotation(agentCheckSend, ing)
	if err != nil {
		if err == errors.ErrMissingAnnotations {
			glog.V(3).Infof("Ingress %v: No value found in annotation %v.", ing.Name, agentCheckSend)
		} else {
			glog.Warningf("Invalid annotation value found in Ingress %v: %v. Ignoring.", ing.Name, agentCheckSend)
		}
	}

	return &Config{addr, port, inter, send}, nil
}
