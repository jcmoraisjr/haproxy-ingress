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
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
	"github.com/spf13/pflag"
	"io/ioutil"
	api "k8s.io/client-go/pkg/api/v1"
	"k8s.io/ingress/core/pkg/ingress"
	"k8s.io/ingress/core/pkg/ingress/controller"
	"k8s.io/ingress/core/pkg/ingress/defaults"
	"net/http"
	"os"
	"os/exec"
)

// HAProxyController has internal data of a HAProxyController instance
type HAProxyController struct {
	controller     *controller.GenericController
	configMap      *api.ConfigMap
	storeLister    *ingress.StoreLister
	command        string
	reloadStrategy string
	configFile     string
	template       *template
}

// NewHAProxyController constructor
func NewHAProxyController() *HAProxyController {
	return &HAProxyController{}
}

// Info provides controller name and repository infos
func (haproxy *HAProxyController) Info() *ingress.BackendInfo {
	return &ingress.BackendInfo{
		Name:       "HAProxy",
		Release:    version.RELEASE,
		Build:      version.COMMIT,
		Repository: version.REPO,
	}
}

// Start starts the controller
func (haproxy *HAProxyController) Start() {
	haproxy.controller = controller.NewIngressController(haproxy)
	haproxy.controller.Start()
}

// Stop shutdown the controller process
func (haproxy *HAProxyController) Stop() error {
	err := haproxy.controller.Stop()
	return err
}

// Name provides the complete name of the controller
func (haproxy *HAProxyController) Name() string {
	return "HAProxy Ingress Controller"
}

// DefaultIngressClass returns the ingress class name
func (haproxy *HAProxyController) DefaultIngressClass() string {
	return "haproxy"
}

// Check health check implementation
func (haproxy *HAProxyController) Check(_ *http.Request) error {
	return nil
}

// SetListers give access to the store listers
func (haproxy *HAProxyController) SetListers(lister ingress.StoreLister) {
	haproxy.storeLister = &lister
}

// ConfigureFlags allow to configure more flags before the parsing of
// command line arguments
func (haproxy *HAProxyController) ConfigureFlags(flags *pflag.FlagSet) {
}

// OverrideFlags allows controller to override command line parameter flags
func (haproxy *HAProxyController) OverrideFlags(flags *pflag.FlagSet) {
	// TODO Fix Ingress core and configure this flag properly
	// reloadStrategy := flags.String("reload-strategy", "native",
	// 	`Name of the reload strategy. Options are: native (default) or multibinder`)
	r := os.Getenv("HA_RELOAD_STRATEGY")
	reloadStrategy := &r
	if *reloadStrategy == "native" {
		haproxy.configFile = "/etc/haproxy/haproxy.cfg"
		haproxy.template = newTemplate("haproxy.tmpl", "/etc/haproxy/template/haproxy.tmpl")
	} else if *reloadStrategy == "multibinder" {
		haproxy.configFile = "/etc/haproxy/haproxy.cfg.erb"
		haproxy.template = newTemplate("haproxy.cfg.erb.tmpl", "/etc/haproxy/haproxy.cfg.erb.tmpl")
	} else {
		glog.Fatalf("Unsupported reload strategy: %v", *reloadStrategy)
	}
	haproxy.command = "/haproxy-reload.sh"
	haproxy.reloadStrategy = *reloadStrategy
}

// SetConfig receives the ConfigMap the user has configured
func (haproxy *HAProxyController) SetConfig(configMap *api.ConfigMap) {
	haproxy.configMap = configMap
}

// BackendDefaults defines default values to the ingress core
func (haproxy *HAProxyController) BackendDefaults() defaults.Backend {
	return newHAProxyConfig(haproxy).Backend
}

// OnUpdate regenerate the configuration file of the backend
func (haproxy *HAProxyController) OnUpdate(cfg ingress.Configuration) ([]byte, error) {
	data, err := haproxy.template.execute(newControllerConfig(&cfg, haproxy))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Reload reload the backend if the configuration file has changed
func (haproxy *HAProxyController) Reload(data []byte) ([]byte, bool, error) {
	if !haproxy.configChanged(data) {
		return nil, false, nil
	}
	// TODO missing HAProxy validation before overwrite and try to reload
	err := ioutil.WriteFile(haproxy.configFile, data, 0644)
	if err != nil {
		return nil, false, err
	}
	out, err := haproxy.reloadHaproxy()
	if len(out) > 0 {
		glog.Infof("HAProxy output:\n%v", string(out))
	}
	return out, true, err
}

func (haproxy *HAProxyController) configChanged(data []byte) bool {
	if _, err := os.Stat(haproxy.configFile); os.IsNotExist(err) {
		return true
	}
	cfg, err := ioutil.ReadFile(haproxy.configFile)
	if err != nil {
		glog.Warningf("error reading haproxy config: %v")
		return false
	}
	return !bytes.Equal(cfg, data)
}

func (haproxy *HAProxyController) reloadHaproxy() ([]byte, error) {
	out, err := exec.Command(haproxy.command, haproxy.reloadStrategy, haproxy.configFile).CombinedOutput()
	return out, err
}
