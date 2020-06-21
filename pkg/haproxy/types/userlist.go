/*
Copyright 2020 The HAProxy Ingress Controller Authors.

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
)

// CreateUserlists ...
func CreateUserlists() *Userlists {
	return &Userlists{
		items:    map[string]*Userlist{},
		itemsAdd: map[string]*Userlist{},
		itemsDel: map[string]*Userlist{},
	}
}

// Replace ...
func (u *Userlists) Replace(name string, users []User) *Userlist {
	userlist := &Userlist{
		Name:  name,
		Users: users,
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})
	u.items[name] = userlist
	u.itemsAdd[name] = userlist
	return userlist
}

// Find ...
func (u *Userlists) Find(name string) *Userlist {
	return u.items[name]
}

// BuildSortedItems ...
func (u *Userlists) BuildSortedItems() []*Userlist {
	items := make([]*Userlist, len(u.items))
	var i int
	for _, item := range u.items {
		items[i] = item
		i++
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Name < items[j].Name
	})
	if len(items) == 0 {
		return nil
	}
	return items
}

// Changed ...
func (u *Userlists) Changed() bool {
	return !reflect.DeepEqual(u.itemsAdd, u.itemsDel)
}

// Commit ...
func (u *Userlists) Commit() {
	u.itemsAdd = map[string]*Userlist{}
	u.itemsDel = map[string]*Userlist{}
}

func (u *Userlist) String() string {
	return fmt.Sprintf("%+v", *u)
}
