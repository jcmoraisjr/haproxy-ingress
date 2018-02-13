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
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
	"github.com/spf13/pflag"
	"io/ioutil"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"sort"
	"strconv"
)

// HAProxyController has internal data of a HAProxyController instance
type HAProxyController struct {
	controller     *controller.GenericController
	configMap      *api.ConfigMap
	storeLister    *ingress.StoreLister
	command        string
	reloadStrategy *string
	configDir     string
	configFilePrefix     string
	configFileSuffix     string
	maxOldConfigFiles     int
	template       *template
	currentConfig  *types.ControllerConfig
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
func (haproxy *HAProxyController) SetListers(lister *ingress.StoreLister) {
	haproxy.storeLister = lister
}

// UpdateIngressStatus custom callback used to update the status in an Ingress rule
// If the function returns nil the standard functions will be executed.
func (haproxy *HAProxyController) UpdateIngressStatus(*extensions.Ingress) []api.LoadBalancerIngress {
	return nil
}

// ConfigureFlags allow to configure more flags before the parsing of
// command line arguments
func (haproxy *HAProxyController) ConfigureFlags(flags *pflag.FlagSet) {
	haproxy.reloadStrategy = flags.String("reload-strategy", "native",
		`Name of the reload strategy. Options are: native (default), reusesocket or multibinder`)
	ingressClass := flags.Lookup("ingress-class")
	if ingressClass != nil {
		ingressClass.Value.Set("haproxy")
		ingressClass.DefValue = "haproxy"
	}
}

// OverrideFlags allows controller to override command line parameter flags
func (haproxy *HAProxyController) OverrideFlags(flags *pflag.FlagSet) {
	haproxy.configDir = "/etc/haproxy"
	haproxy.configFilePrefix = "haproxy"
	haproxy.configFileSuffix = ".cfg"
	haproxy.template = newTemplate("haproxy.tmpl", "/etc/haproxy/template/haproxy.tmpl")

	if !(*haproxy.reloadStrategy == "native" || *haproxy.reloadStrategy == "reusesocket" || *haproxy.reloadStrategy == "multibinder") {
		glog.Fatalf("Unsupported reload strategy: %v", *haproxy.reloadStrategy)
	}
	
	if *haproxy.reloadStrategy == "multibinder" {
		haproxy.template = newTemplate("haproxy.cfg.erb.tmpl", "/etc/haproxy/haproxy.cfg.erb.tmpl")
	}
	haproxy.command = "/haproxy-reload.sh"

	haproxy.maxOldConfigFiles = 1000
	envVar := os.Getenv("MAX_OLD_CONFIG_FILES")
	if maxOldConfigFiles, err := strconv.Atoi(envVar); err == nil {
		haproxy.maxOldConfigFiles = maxOldConfigFiles
	}
}

// SetConfig receives the ConfigMap the user has configured
func (haproxy *HAProxyController) SetConfig(configMap *api.ConfigMap) {
	haproxy.configMap = configMap
}

// BackendDefaults defines default values to the ingress core
func (haproxy *HAProxyController) BackendDefaults() defaults.Backend {
	return newHAProxyConfig(haproxy).Backend
}

// DefaultEndpoint returns the Endpoint to use as default when the
// referenced service does not exists
func (haproxy *HAProxyController) DefaultEndpoint() ingress.Endpoint {
	return ingress.Endpoint{
		Address: "127.0.0.1",
		Port:    "8181",
		Target:  &api.ObjectReference{},
	}
}

// OnUpdate regenerate the configuration file of the backend
func (haproxy *HAProxyController) OnUpdate(cfg ingress.Configuration) error {
	updatedConfig := newControllerConfig(&cfg, haproxy)

	reloadRequired := reconfigureBackends(haproxy.currentConfig, updatedConfig)
	haproxy.currentConfig = updatedConfig

	data, err := haproxy.template.execute(updatedConfig)
	if err != nil {
		return err
	}

	configFile, err := haproxy.rewriteConfigFiles(data)
	if err != nil {
		return err
	}

	if !reloadRequired {
		glog.Infoln("HAProxy updated through socket, reload not required")
		return nil
	}

	reloadCmd := haproxy.reloadHaproxy(configFile)
	out, err := reloadCmd.CombinedOutput()
	if len(out) > 0 {
		glog.Infof("HAProxy[pid=%v] output:\n%v", reloadCmd.Process.Pid, string(out))
	}
	return err
}

// RewriteConfigFiles safely replaces configuration files with new contents after validation
func (haproxy *HAProxyController) rewriteConfigFiles(data []byte) (string, error) {
	// Include timestamp in config file name to aid troubleshooting. When using a single, ever-changing config file it
	// was difficult to know what config was loaded by any given haproxy process
	timestamp := time.Now().Format("-060102-150405.0000")
	if *haproxy.reloadStrategy == "multibinder" {
		// multibinder currently limited to fixed config file path
		timestamp = ""
	}
	configFile := haproxy.configDir + "/" + haproxy.configFilePrefix + timestamp + haproxy.configFileSuffix

	if *haproxy.reloadStrategy == "multibinder" {
		erbFile := configFile + ".erb"
		// Write to ERB template file
		if err := ioutil.WriteFile(erbFile, data, 644); err != nil {
			glog.Warningln("Error writing rendered template to file")
			return "", err
		}

		// Generate configFile contents by processing ERB template (also validates haproxy config)
		if err := multibinderERBOnly(erbFile); err != nil {
			return "", err
		}
	} else {
		// Write directly to configFile
		if err := ioutil.WriteFile(configFile, data, 644); err != nil {
			glog.Warningln("Error writing rendered template to file")
			return "", err
		}

		// Validate haproxy config
		if err := checkValidity(configFile); err != nil {
			return "", err
		}
	}

	haproxy.removeOldConfigFiles(haproxy.configFileSuffix)
	return configFile, nil
}

func (haproxy *HAProxyController) removeOldConfigFiles(suffix string) error {
	files, err := ioutil.ReadDir(haproxy.configDir)
	if err != nil {
		return err
	}

	// Sort with most recently modified first
	sort.Slice(files, func(i,j int) bool{
		return files[i].ModTime().After(files[j].ModTime())
	})

	matchesFound := 0
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), haproxy.configFilePrefix) && strings.HasSuffix(f.Name(), suffix) {
			matchesFound = matchesFound + 1
			if matchesFound > haproxy.maxOldConfigFiles {
				filePath := haproxy.configDir + "/" + f.Name()
				glog.Infof("Removing old config file (%v). maxOldConfigFiles=%v", filePath, haproxy.maxOldConfigFiles)
				os.Remove(filePath)
			}
		}
	}
	return nil
}

// multibinderERBOnly generates a config file from ERB template by invoking multibinder-haproxy-erb
func multibinderERBOnly(configFile string) error {
	out, err := exec.Command("multibinder-haproxy-erb", "/usr/local/sbin/haproxy", "-f", configFile, "-c", "-q").CombinedOutput()
	if err != nil {
		glog.Warningf("Error validating config file:\n%v", string(out))
		return err
	}
	return nil
}

// checkValidity runs a HAProxy configuration validity check on a file
func checkValidity(configFile string) error {
	out, err := exec.Command("haproxy", "-c", "-f", configFile).CombinedOutput()
	if err != nil {
		glog.Warningf("Error validating config file:\n%v", string(out))
		return err
	}
	return nil
}

func (haproxy *HAProxyController) reloadHaproxy(configFile string) (*exec.Cmd) {
	return exec.Command(haproxy.command, *haproxy.reloadStrategy, configFile)
}
