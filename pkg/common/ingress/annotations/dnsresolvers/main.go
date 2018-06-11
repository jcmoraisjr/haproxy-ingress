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

package dnsresolvers

import (
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/parser"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/resolver"
	extensions "k8s.io/api/extensions/v1beta1"
	"reflect"
	"strings"
)

const (
	DNSResolversAnn = "ingress.kubernetes.io/dns-resolvers"
	UseResolverAnn  = "ingress.kubernetes.io/use-resolver"
	ClusterDnsDomain  = "ingress.kubernetes.io/cluster-dns-domain"
)

type dnsresolvers struct {
	//resolvers resolver.DefaultBackend
}

// Resolver information
type DNSResolver struct {
	Name                string
	Nameservers         map[string]string
	TimeoutRetry        int
	HoldObsolete        int
	HoldValid           int
	AcceptedPayloadSize int
}

// Config has the dns resolvers configurations.
type Config struct {
	DNSResolvers map[string]DNSResolver
	UseResolver  string
	ClusterDnsDomain string
}

// NewParser creates a new dns-resolvers annotation parser
func NewParser(resolvers resolver.DefaultBackend) parser.IngressAnnotation {
	return dnsresolvers{}
}

// Parse parses dns-resolvers annotation
func (b dnsresolvers) Parse(ing *extensions.Ingress) (interface{}, error) {
	s, err := parser.GetStringAnnotation(DNSResolversAnn, ing)
	resolvers := ParseDNSResolvers(s)
	useResolver, _ := parser.GetStringAnnotation(UseResolverAnn, ing)
	clusterDnsDomain, err := parser.GetStringAnnotation(ClusterDnsDomain, ing)
	if err != nil {
		clusterDnsDomain = "cluster.local"
	}
	cfg := &Config{
		DNSResolvers: resolvers,
		UseResolver: useResolver,
		ClusterDnsDomain: clusterDnsDomain,
	}
	return cfg, nil
}

// Equal tests equality between two Config structs
func (c1 *Config) Equal(c2 *Config) bool {
	if len(c1.DNSResolvers) != len(c2.DNSResolvers) {
		return false
	}
	for name, resolver1 := range c1.DNSResolvers {
		if resolver2, ok := c2.DNSResolvers[name]; ok {
			if !reflect.DeepEqual(resolver1, resolver2) {
				return false
			}
		} else {
			return false
		}
	}
	if c1.UseResolver != c2.UseResolver {
		return false
	}
	if c1.ClusterDnsDomain != c2.ClusterDnsDomain {
		return false
	}
	return true
}

func ParseDNSResolvers(dnsresolvers string) (map[string]DNSResolver) {
	result := map[string]DNSResolver{}
	if dnsresolvers == "" {
		return result
	}

	resolvers := strings.Split(dnsresolvers, "\n")
	for _, resolver := range resolvers {
		resolverData := strings.Split(resolver, "=")
		if len(resolverData) != 2 {
			if len(resolver) != 0 {
				glog.Infof("misconfigured DNS resolver: %s", resolver)
			}
			continue
		}
		nameservers := map[string]string{}
		nameserversData := strings.Split(resolverData[1], ",")
		for _, nameserver := range nameserversData {
			nameserverData := strings.Split(nameserver, ":")
			if len(nameserverData) == 1 {
				nameservers[nameserverData[0]] = "53"
			} else {
				nameservers[nameserverData[0]] = nameserverData[1]
			}
		}
		result[resolverData[0]] = DNSResolver{
			Name:                resolverData[0],
			Nameservers:         nameservers,
			TimeoutRetry:        1,
			HoldObsolete:        0,
			HoldValid:           1,
			AcceptedPayloadSize: 8192,
		}
	}
	return result
}
