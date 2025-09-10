/*
Copyright 2019 The HAProxy Ingress Controller Authors.

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

package types

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Storages ...
func (acme *AcmeData) Storages() *AcmeStorages {
	if acme.storages == nil {
		acme.storages = &AcmeStorages{
			items:    map[string]*AcmeCerts{},
			itemsAdd: map[string]*AcmeCerts{},
			itemsDel: map[string]*AcmeCerts{},
		}
	}
	return acme.storages
}

// Acquire ...
func (c *AcmeStorages) Acquire(name string) *AcmeCerts {
	storage, found := c.items[name]
	if !found {
		storage = &AcmeCerts{
			certs: map[string]struct{}{},
		}
		c.items[name] = storage
		c.itemsAdd[name] = storage
	}
	return storage
}

// Updated ...
func (c *AcmeStorages) Updated() bool {
	c.shrink()
	return len(c.itemsAdd) > 0 || len(c.itemsDel) > 0
}

// BuildAcmeStorages ...
func (c *AcmeStorages) BuildAcmeStorages() []string {
	return buildAcmeStorages(c.items)
}

// BuildAcmeStoragesAdd ...
func (c *AcmeStorages) BuildAcmeStoragesAdd() []string {
	c.shrink()
	return buildAcmeStorages(c.itemsAdd)
}

// BuildAcmeStoragesDel ...
func (c *AcmeStorages) BuildAcmeStoragesDel() []string {
	c.shrink()
	return buildAcmeStorages(c.itemsDel)
}

func buildAcmeStorages(items map[string]*AcmeCerts) []string {
	storages := make([]string, len(items))
	i := 0
	for name := range items {
		item := items[name]
		certs := make([]string, len(item.certs))
		j := 0
		for cert := range item.certs {
			certs[j] = cert
			j++
		}
		sort.Strings(certs)
		storages[i] = name + "," + item.preferredChain + "," + strings.Join(certs, ",")
		i++
	}
	return storages
}

func (c *AcmeStorages) shrink() {
	for item, del := range c.itemsDel {
		if add, found := c.itemsAdd[item]; found && reflect.DeepEqual(add, del) {
			delete(c.itemsAdd, item)
			delete(c.itemsDel, item)
		}
	}
}

// RemoveAll ...
func (c *AcmeStorages) RemoveAll(names []string) {
	for _, name := range names {
		if item, found := c.items[name]; found {
			c.itemsDel[name] = item
			delete(c.items, name)
		}
	}
}

// Commit ...
func (c *AcmeStorages) Commit() {
	c.itemsAdd = map[string]*AcmeCerts{}
	c.itemsDel = map[string]*AcmeCerts{}
}

// AddDomains ...
func (c *AcmeCerts) AddDomains(domains []string) {
	for _, domain := range domains {
		c.certs[domain] = struct{}{}
	}
}

// AssignPreferredChain ...
func (c *AcmeCerts) AssignPreferredChain(preferredChain string) error {
	if c.preferredChain != "" && c.preferredChain != preferredChain {
		return fmt.Errorf("preferred chain already assigned to '%s'", c.preferredChain)
	}
	c.preferredChain = preferredChain
	return nil
}

func (dns *DNSConfig) String() string {
	return fmt.Sprintf("%+v", *dns)
}

func (dns *DNSResolver) String() string {
	return fmt.Sprintf("%+v", *dns)
}

func (dns *DNSNameserver) String() string {
	return fmt.Sprintf("%+v", *dns)
}
