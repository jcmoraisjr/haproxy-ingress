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
	"testing"

	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func buildIngress() *extensions.Ingress {
	defaultBackend := extensions.IngressBackend{
		ServiceName: "default-backend",
		ServicePort: intstr.FromInt(80),
	}

	return &extensions.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
		},
		Spec: extensions.IngressSpec{
			Backend: &extensions.IngressBackend{
				ServiceName: "default-backend",
				ServicePort: intstr.FromInt(80),
			},
			Rules: []extensions.IngressRule{
				{
					Host: "foo.bar.com",
					IngressRuleValue: extensions.IngressRuleValue{
						HTTP: &extensions.HTTPIngressRuleValue{
							Paths: []extensions.HTTPIngressPath{
								{
									Path:    "/foo",
									Backend: defaultBackend,
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestIngressAgentCheck(t *testing.T) {
	ing := buildIngress()

	data := map[string]string{}
	data[agentCheckAddr] = "1.2.3.4"
	data[agentCheckPort] = "8080"
	data[agentCheckInterval] = "7"
	data[agentCheckSend] = "hello\n"
	ing.SetAnnotations(data)

	hc, _ := NewParser().Parse(ing)
	agentCheck, ok := hc.(*Config)
	if !ok {
		t.Errorf("expected a Config type")
	}

	if agentCheck.Addr != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4 as Addr but returned %v", agentCheck.Addr)
	}
	if agentCheck.Port != "8080" {
		t.Errorf("expected 8080 as port but returned %v", agentCheck.Port)
	}
	if agentCheck.Interval != "7" {
		t.Errorf("expected 7 as Interval but returned %v", agentCheck.Interval)
	}
	if agentCheck.Send != "hello\n" {
		t.Errorf("expected hello\\n as Send but returned %v", agentCheck.Send)
	}
}
