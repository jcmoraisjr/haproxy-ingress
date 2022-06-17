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

package template

import (
	"fmt"
	"reflect"
	"strings"
	gotemplate "text/template"

	"github.com/Masterminds/sprig"
	"github.com/imdario/mergo"
	"k8s.io/klog/v2"
)

func createFuncMap() gotemplate.FuncMap {
	fnc := gotemplate.FuncMap{
		"map": func(v ...interface{}) map[string]interface{} {
			d := make(map[string]interface{}, len(v))
			for i := range v {
				d[fmt.Sprintf("p%d", i+1)] = v[i]
			}
			return d
		},
		"iif": func(iif bool, t, f interface{}) interface{} {
			if iif {
				return t
			}
			return f
		},
		"short": func(size int, ilist interface{}) []interface{} {
			list := reflect.ValueOf(ilist)
			listlen := list.Len()
			if size < 1 {
				return []interface{}{list.Interface()}
			}
			out := make([]interface{}, (listlen+size-1)/size)
			for i := range out {
				last := size*i + size
				if last >= listlen {
					last = listlen
				}
				out[i] = list.Slice(size*i, last).Interface()
			}
			return out
		},
		"haquote": func(s string) string {
			// put in single quotes
			// escape single quotes inside as ' "'" ' (without the spaces)
			return "'" + strings.ReplaceAll(s, `'`, `'"'"'`) + "'"
		},
	}
	if err := mergo.Merge(&fnc, sprig.TxtFuncMap()); err != nil {
		klog.Fatalf("Cannot merge funcMap and sprig.FuncMap(): %v", err)
	}
	return fnc
}

var funcMap = createFuncMap()
