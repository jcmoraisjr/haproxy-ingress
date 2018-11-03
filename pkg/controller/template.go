/*
Copyright 2017 The Kubernetes Authors.

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

package controller

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig"
	"github.com/golang/glog"
	"github.com/imdario/mergo"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"regexp"
	"strconv"
	"strings"
	gotemplate "text/template"
)

type template struct {
	tmpl      *gotemplate.Template
	rawConfig *bytes.Buffer
}

var funcMap = gotemplate.FuncMap{
	"iif": func(q bool, o1, o2 string) string {
		if q {
			return o1
		}
		return o2
	},
	"isShared": func(singleServer *types.HAProxyServer) bool {
		return singleServer == nil
	},
	"isCACert": func(singleServer *types.HAProxyServer) bool {
		return singleServer != nil && singleServer.IsCACert
	},
	"isDefault": func(singleServer *types.HAProxyServer) bool {
		return singleServer != nil && singleServer.IsDefaultServer
	},
	"getServers": func(servers []*types.HAProxyServer, singleServer *types.HAProxyServer) []*types.HAProxyServer {
		if singleServer != nil {
			return []*types.HAProxyServer{singleServer}
		}
		return servers
	},
	"map": func(v ...interface{}) map[string]interface{} {
		d := make(map[string]interface{}, len(v))
		for i := range v {
			d[fmt.Sprintf("p%v", i+1)] = v[i]
		}
		return d
	},
	"hostnameRegex": func(hostname string) string {
		rtn := regexp.MustCompile(`\.`).ReplaceAllLiteralString(hostname, "\\.")
		rtn = regexp.MustCompile(`\*`).ReplaceAllLiteralString(rtn, "([^\\.]+)")
		return "^" + rtn + "(:[0-9]+)?$"
	},
	"aliasRegex": func(hostname string) string {
		rtn := regexp.MustCompile(`\.`).ReplaceAllLiteralString(hostname, "\\.")
		return "^" + rtn + "(:[0-9]+)?$"
	},
	"sizeSuffix": func(size string) string {
		value, err := utils.SizeSuffixToInt64(size)
		if err != nil {
			glog.Errorf("Error converting %v: %v", size, err)
			return size
		}
		return strconv.FormatInt(value, 10)
	},
	"split": func(str, sep string) []string {
		return strings.Split(str, sep)
	},
	"hasSuffix": func(s, suffix string) bool {
		return strings.HasSuffix(s, suffix)
	},
}

func newTemplate(name string, file string, startingBufferSize int) *template {
	if err := mergo.Merge(&funcMap, sprig.TxtFuncMap()); err != nil {
		glog.Fatalf("Cannot merge funcMap and sprig.FuncMap(): %v", err)
	}

	tmpl, err := gotemplate.New(name).Funcs(funcMap).ParseFiles(file)
	if err != nil {
		glog.Fatalf("Cannot read template file: %v", err)
	}
	return &template{
		tmpl:      tmpl,
		rawConfig: bytes.NewBuffer(make([]byte, 0, startingBufferSize)),
	}
}

func (t *template) execute(cfg *types.ControllerConfig) ([]byte, error) {
	t.rawConfig.Reset()
	if err := t.tmpl.Execute(t.rawConfig, cfg); err != nil {
		return nil, err
	}
	return t.rawConfig.Bytes(), nil
}
