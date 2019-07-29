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
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/annotations/class"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/defaults"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/dynconfig"
	ingressconverter "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress"
	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
)

// HAProxyController has internal data of a HAProxyController instance
type HAProxyController struct {
	instance          haproxy.Instance
	controller        *controller.GenericController
	cfg               *controller.Configuration
	configMap         *api.ConfigMap
	storeLister       *ingress.StoreLister
	converterOptions  *ingtypes.ConverterOptions
	command           string
	reloadStrategy    *string
	configDir         string
	configFilePrefix  string
	configFileSuffix  string
	maxOldConfigFiles *int
	haproxyTemplate   *template
	modsecConfigFile  string
	modsecTemplate    *template
	currentConfig     *types.ControllerConfig
}

// NewHAProxyController constructor
func NewHAProxyController() *HAProxyController {
	return &HAProxyController{}
}

// Info provides controller name and repository infos
func (hc *HAProxyController) Info() *ingress.BackendInfo {
	return &ingress.BackendInfo{
		Name:       "HAProxy",
		Release:    version.RELEASE,
		Build:      version.COMMIT,
		Repository: version.REPO,
	}
}

// Start starts the controller
func (hc *HAProxyController) Start() {
	hc.controller = controller.NewIngressController(hc)
	hc.controller.StartControllers()
	hc.configController()
	hc.controller.Start()
}

func (hc *HAProxyController) configController() {
	if *hc.reloadStrategy == "multibinder" {
		glog.Warningf("multibinder is deprecated, using reusesocket strategy instead. update your deployment configuration")
	}
	hc.cfg = hc.controller.GetConfig()

	if hc.cfg.V07 {
		return
	}

	// starting v0.8 only config
	logger := &logger{depth: 1}
	instanceOptions := haproxy.InstanceOptions{
		HAProxyCmd:        "haproxy",
		ReloadCmd:         "/haproxy-reload.sh",
		HAProxyConfigFile: "/etc/haproxy/haproxy.cfg",
		ReloadStrategy:    *hc.reloadStrategy,
		MaxOldConfigFiles: *hc.maxOldConfigFiles,
	}
	hc.instance = haproxy.CreateInstance(logger, hc, instanceOptions)
	if err := hc.instance.ParseTemplates(); err != nil {
		glog.Fatalf("error creating HAProxy instance: %v", err)
	}
	cache := newCache(hc.storeLister, hc.controller)
	hc.converterOptions = &ingtypes.ConverterOptions{
		Logger:           logger,
		Cache:            cache,
		AnnotationPrefix: "ingress.kubernetes.io",
		DefaultBackend:   hc.cfg.DefaultService,
		DefaultSSLFile:   hc.createDefaultSSLFile(cache),
	}
}

func (hc *HAProxyController) createDefaultSSLFile(cache *cache) (tlsFile ingtypes.File) {
	if hc.cfg.DefaultSSLCertificate != "" {
		tlsFile, err := cache.GetTLSSecretPath(hc.cfg.DefaultSSLCertificate)
		if err == nil {
			return tlsFile
		}
		glog.Warningf("using auto generated fake certificate due to an error reading default TLS certificate: %v", err)
	} else {
		glog.Info("using auto generated fake certificate")
	}
	path, hash := hc.controller.CreateDefaultSSLCertificate()
	tlsFile = ingtypes.File{
		Filename: path,
		SHA1Hash: hash,
	}
	return tlsFile
}

// CreateX509CertsDir hard link files from certs to a single directory.
func (hc *HAProxyController) CreateX509CertsDir(bindName string, certs []string) (string, error) {
	x509dir := "/var/haproxy/certs/" + bindName
	if err := os.RemoveAll(x509dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(x509dir, 0700); err != nil {
		return "", err
	}
	for _, cert := range certs {
		srcFile, err := os.Stat(cert)
		if err != nil {
			return "", err
		}
		dstFile := x509dir + "/" + srcFile.Name()
		if err := os.Link(cert, dstFile); err != nil {
			return "", err
		}
	}
	return x509dir, nil
}

// Stop shutdown the controller process
func (hc *HAProxyController) Stop() error {
	terminationGracePeriod := time.Duration(hc.cfg.TerminationGracePeriod) * time.Second
	glog.Infof("Waiting %v before stopping components", terminationGracePeriod)
	time.Sleep(terminationGracePeriod)
	err := hc.controller.Stop()
	return err
}

// Name provides the complete name of the controller
func (hc *HAProxyController) Name() string {
	return "HAProxy Ingress Controller"
}

// DefaultIngressClass returns the ingress class name
func (hc *HAProxyController) DefaultIngressClass() string {
	return "haproxy"
}

// Check health check implementation
func (hc *HAProxyController) Check(_ *http.Request) error {
	return nil
}

// SetListers give access to the store listers
func (hc *HAProxyController) SetListers(lister *ingress.StoreLister) {
	hc.storeLister = lister
}

// UpdateIngressStatus custom callback used to update the status in an Ingress rule
// If the function returns nil the standard functions will be executed.
func (hc *HAProxyController) UpdateIngressStatus(*extensions.Ingress) []api.LoadBalancerIngress {
	return nil
}

// ConfigureFlags allow to configure more flags before the parsing of
// command line arguments
func (hc *HAProxyController) ConfigureFlags(flags *pflag.FlagSet) {
	hc.reloadStrategy = flags.String("reload-strategy", "native",
		`Name of the reload strategy. Options are: native (default) or reusesocket`)
	hc.maxOldConfigFiles = flags.Int("max-old-config-files", 0,
		`Maximum old haproxy timestamped config files to allow before being cleaned up. A value <= 0 indicates a single non-timestamped config file will be used`)
	ingressClass := flags.Lookup("ingress-class")
	if ingressClass != nil {
		ingressClass.Value.Set("haproxy")
		ingressClass.DefValue = "haproxy"
	}
}

// OverrideFlags allows controller to override command line parameter flags
func (hc *HAProxyController) OverrideFlags(flags *pflag.FlagSet) {
	hc.configDir = "/etc/haproxy"
	hc.configFilePrefix = "haproxy"
	hc.configFileSuffix = ".cfg"
	hc.haproxyTemplate = newTemplate("haproxy-v07.tmpl", "/etc/haproxy/template/haproxy-v07.tmpl", 16384)
	hc.modsecConfigFile = "/etc/haproxy/spoe-modsecurity.conf"
	hc.modsecTemplate = newTemplate("spoe-modsecurity-v07.tmpl", "/etc/haproxy/modsecurity/spoe-modsecurity-v07.tmpl", 1024)
	hc.command = "/haproxy-reload.sh"

	if !(*hc.reloadStrategy == "native" || *hc.reloadStrategy == "reusesocket" || *hc.reloadStrategy == "multibinder") {
		glog.Fatalf("Unsupported reload strategy: %v", *hc.reloadStrategy)
	}
}

// SetConfig receives the ConfigMap the user has configured
func (hc *HAProxyController) SetConfig(configMap *api.ConfigMap) {
	hc.configMap = configMap
}

// BackendDefaults defines default values to the ingress core
func (hc *HAProxyController) BackendDefaults() defaults.Backend {
	return newHAProxyConfig(hc).Backend
}

// DefaultEndpoint returns the Endpoint to use as default when the
// referenced service does not exists
func (hc *HAProxyController) DefaultEndpoint() ingress.Endpoint {
	return ingress.Endpoint{
		Address:  "127.0.0.1",
		Port:     "8181",
		Draining: false,
		Target:   &api.ObjectReference{},
	}
}

// DrainSupport indicates whether or not this controller supports a "drain" mode where
// unavailable and terminating pods are included in the list of returned pods and used to
// direct certain traffic (e.g., traffic using persistence) to terminating/unavailable pods.
func (hc *HAProxyController) DrainSupport() (drainSupport bool) {
	if hc.currentConfig != nil {
		drainSupport = hc.currentConfig.Cfg.DrainSupport
	}
	return
}

// SyncIngress sync HAProxy config from a very early stage
func (hc *HAProxyController) SyncIngress(item interface{}) error {
	var ingress []*extensions.Ingress
	for _, iing := range hc.storeLister.Ingress.List() {
		ing := iing.(*extensions.Ingress)
		if class.IsValid(ing, hc.cfg.IngressClass, hc.cfg.DefaultIngressClass) {
			ingress = append(ingress, ing)
		}
	}
	sort.SliceStable(ingress, func(i, j int) bool {
		return ingress[i].ResourceVersion < ingress[j].ResourceVersion
	})

	var globalConfig map[string]string
	if hc.configMap != nil {
		globalConfig = hc.configMap.Data
	}
	converter := ingressconverter.NewIngressConverter(
		hc.converterOptions,
		hc.instance.Config(),
		globalConfig,
	)
	converter.Sync(ingress)
	hc.instance.Update()

	return nil
}

// OnUpdate regenerate the configuration file of the backend
func (hc *HAProxyController) OnUpdate(cfg ingress.Configuration) error {
	updatedConfig, err := newControllerConfig(&cfg, hc)
	if err != nil {
		return err
	}

	reloadRequired := !dynconfig.ConfigBackends(hc.currentConfig, updatedConfig)
	hc.currentConfig = updatedConfig

	modSecConf, err := hc.modsecTemplate.execute(updatedConfig)
	if err != nil {
		return err
	}

	if err := hc.writeModSecConfigFile(modSecConf); err != nil {
		return err
	}

	data, err := hc.haproxyTemplate.execute(updatedConfig)
	if err != nil {
		return err
	}

	configFile, err := hc.rewriteConfigFiles(data)
	if err != nil {
		return err
	}

	if !reloadRequired {
		glog.Infoln("HAProxy updated without needing to reload")
		return nil
	}

	reloadCmd := exec.Command(hc.command, *hc.reloadStrategy, configFile)
	out, err := reloadCmd.CombinedOutput()
	if len(out) > 0 {
		glog.Infof("HAProxy[pid=%v] output:\n%v", reloadCmd.Process.Pid, string(out))
	}
	return err
}

func (hc *HAProxyController) writeModSecConfigFile(data []byte) error {
	if err := ioutil.WriteFile(hc.modsecConfigFile, data, 644); err != nil {
		glog.Warningf("Error writing modsecurity config file: %v", err)
		return err
	}
	return nil
}

// RewriteConfigFiles safely replaces configuration files with new contents after validation
func (hc *HAProxyController) rewriteConfigFiles(data []byte) (string, error) {
	// Include timestamp in config file name to aid troubleshooting. When using a single, ever-changing config file it
	// was difficult to know what config was loaded by any given haproxy process
	timestamp := ""
	if *hc.maxOldConfigFiles > 0 {
		timestamp = time.Now().Format("-20060102-150405.000")
	}
	configFile := hc.configDir + "/" + hc.configFilePrefix + timestamp + hc.configFileSuffix

	// Write directly to configFile
	if err := ioutil.WriteFile(configFile, data, 644); err != nil {
		glog.Warningf("Error writing haproxy config file: %v", err)
		return "", err
	}

	// Validate haproxy config
	if err := checkValidity(configFile); err != nil {
		return "", err
	}

	if *hc.maxOldConfigFiles > 0 {
		if err := hc.removeOldConfigFiles(); err != nil {
			glog.Warningf("Problem removing old config files, but continuing in case it was a fluke. err=%v", err)
		}
	}

	return configFile, nil
}

func (hc *HAProxyController) removeOldConfigFiles() error {
	files, err := ioutil.ReadDir(hc.configDir)
	if err != nil {
		return err
	}

	// Sort with most recently modified first
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime().After(files[j].ModTime())
	})

	matchesFound := 0
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), hc.configFilePrefix) && strings.HasSuffix(f.Name(), hc.configFileSuffix) {
			matchesFound = matchesFound + 1
			if matchesFound > *hc.maxOldConfigFiles {
				filePath := hc.configDir + "/" + f.Name()
				glog.Infof("Removing old config file (%v). maxOldConfigFiles=%v", filePath, *hc.maxOldConfigFiles)
				if err := os.Remove(filePath); err != nil {
					return err
				}
			}
		}
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
