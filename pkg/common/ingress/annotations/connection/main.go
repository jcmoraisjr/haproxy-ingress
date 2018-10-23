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

package connection

import (
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	extensions "k8s.io/api/extensions/v1beta1"
	"regexp"
)

const (
	maxconnServerAnn  = "ingress.kubernetes.io/maxconn-server"
	maxqueueServerAnn = "ingress.kubernetes.io/maxqueue-server"
	timeoutQueueAnn   = "ingress.kubernetes.io/timeout-queue"
)

var (
	timeoutQueueRegex = regexp.MustCompile(`^([0-9]+(us|ms|[smhd])?)$`)
)

// Config is the connection configuration
type Config struct {
	MaxConnServer  int
	MaxQueueServer int
	TimeoutQueue   string
}

type conn struct {
}

// NewParser creates a new connection annotation parser
func NewParser() parser.IngressAnnotation {
	return conn{}
}

// Parse parses connection limits and timeouts annotations and creates a Config struct
func (c conn) Parse(ing *extensions.Ingress) (interface{}, error) {
	maxconn, err := parser.GetIntAnnotation(maxconnServerAnn, ing)
	if err != nil {
		maxconn = 0
	}
	maxqueue, err := parser.GetIntAnnotation(maxqueueServerAnn, ing)
	if err != nil {
		maxqueue = 0
	}
	timeoutqueue, err := parser.GetStringAnnotation(timeoutQueueAnn, ing)
	if err != nil {
		timeoutqueue = ""
	}
	if timeoutqueue != "" && !timeoutQueueRegex.MatchString(timeoutqueue) {
		glog.Warningf("ignoring invalid timeout queue %v on %v/%v", timeoutqueue, ing.Namespace, ing.Name)
		timeoutqueue = ""
	}
	return &Config{
		MaxConnServer:  maxconn,
		MaxQueueServer: maxqueue,
		TimeoutQueue:   timeoutqueue,
	}, nil
}

// Equal tests equality between two Config objects
func (c1 *Config) Equal(c2 *Config) bool {
	if c1.MaxConnServer != c2.MaxConnServer {
		return false
	}
	if c1.MaxQueueServer != c2.MaxQueueServer {
		return false
	}
	if c1.TimeoutQueue != c2.TimeoutQueue {
		return false
	}
	return true
}
