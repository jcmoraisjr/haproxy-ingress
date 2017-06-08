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
	"fmt"
	"github.com/golang/glog"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
	"github.com/spf13/pflag"
	"io/ioutil"
	api "k8s.io/client-go/pkg/api/v1"
	"k8s.io/ingress/core/pkg/ingress"
	"k8s.io/ingress/core/pkg/ingress/controller"
	"k8s.io/ingress/core/pkg/ingress/defaults"
	"net/http"
	"os/exec"
	"reflect"
	"sort"
)

// HAProxyController has internal data of a HAProxyController instance
type HAProxyController struct {
	controller     *controller.GenericController
	configMap      *api.ConfigMap
	storeLister    *ingress.StoreLister
	command        string
	reloadStrategy *string
	configFile     string
	template       *template
	CurrentConfig  *types.ControllerConfig
	ReloadRequired bool
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
	haproxy.reloadStrategy = flags.String("reload-strategy", "native",
		`Name of the reload strategy. Options are: native (default) or multibinder`)
	ingressClass := flags.Lookup("ingress-class")
	if ingressClass != nil {
		ingressClass.Value.Set("haproxy")
		ingressClass.DefValue = "haproxy"
	}
}

// OverrideFlags allows controller to override command line parameter flags
func (haproxy *HAProxyController) OverrideFlags(flags *pflag.FlagSet) {
	if *haproxy.reloadStrategy == "native" {
		haproxy.configFile = "/etc/haproxy/haproxy.cfg"
		haproxy.template = newTemplate("haproxy.tmpl", "/etc/haproxy/template/haproxy.tmpl")
	} else if *haproxy.reloadStrategy == "multibinder" {
		haproxy.configFile = "/etc/haproxy/haproxy.cfg.erb"
		haproxy.template = newTemplate("haproxy.cfg.erb.tmpl", "/etc/haproxy/haproxy.cfg.erb.tmpl")
	} else {
		glog.Fatalf("Unsupported reload strategy: %v", *haproxy.reloadStrategy)
	}
	haproxy.command = "/haproxy-reload.sh"
}

// SetConfig receives the ConfigMap the user has configured
func (haproxy *HAProxyController) SetConfig(configMap *api.ConfigMap) {
	haproxy.configMap = configMap
}

// BackendDefaults defines default values to the ingress core
func (haproxy *HAProxyController) BackendDefaults() defaults.Backend {
	return newHAProxyConfig(haproxy).Backend
}

// convert a list of ingress backends to a map with backend names as keys
func ingressBackendsRemap(backends []*ingress.Backend) (map[string]*ingress.Backend, []string) {
	backendsMap := map[string]*ingress.Backend{}
	keys := []string{}
	for _, ingBackend := range backends {
		backendsMap[ingBackend.Name] = ingBackend
		keys = append(keys, ingBackend.Name)
	}
	sort.Strings(keys)
	return backendsMap, keys
}

// convert a list of endpoints to a map with address:port as keys
func ingressEndpointsRemap(endpoints []ingress.Endpoint) map[string]*ingress.Endpoint {
	endpointMap := map[string]*ingress.Endpoint{}
	for i, e := range endpoints {
		endpointMap[fmt.Sprintf("%s:%s", e.Address, e.Port)] = &endpoints[i]
	}
	return endpointMap
}

// return elements in s1 but not in s2
func endpointsSubtract(s1, s2 map[string]*ingress.Endpoint) map[string]*ingress.Endpoint {
	s3 := map[string]*ingress.Endpoint{}
	for k, v := range s1 {
		_, ok := s2[k]
		if !ok {
			s3[k] = v
		}
	}
	return s3
}

// OnUpdate regenerate the configuration file of the backend
func (haproxy *HAProxyController) OnUpdate(cfg ingress.Configuration) ([]byte, error) {

	updatedConfig := newControllerConfig(&cfg, haproxy)

	reconfigureEmptySlots := false

	if haproxy.CurrentConfig != nil {
		// store backend lists for retrieval
		curBackends := haproxy.CurrentConfig.Backends
		updBackends := updatedConfig.Backends
		// store BackendSlots for retrieval
		curBackendSlots := haproxy.CurrentConfig.BackendSlots

		// exclude backend lists and slots from reflect.DeepEqual
		updatedConfig.Backends = []*ingress.Backend{}
		haproxy.CurrentConfig.Backends = updatedConfig.Backends
		haproxy.CurrentConfig.BackendSlots = updatedConfig.BackendSlots

		// check equality of everything but backends
		if !reflect.DeepEqual(updatedConfig, haproxy.CurrentConfig) {
			reconfigureEmptySlots = true
		} else {
			// set up maps
			curBackendsMap, curKeys := ingressBackendsRemap(curBackends)
			updBackendsMap, updKeys := ingressBackendsRemap(updBackends)

			if !reflect.DeepEqual(curKeys, updKeys) {
				// backend names or number of backends is different
				reconfigureEmptySlots = true
			} else {
				// same names and nr of backends, we can modify existing HAProxyBackendSlots, should not need reloading
				haproxy.ReloadRequired = false
				updatedConfig.BackendSlots = curBackendSlots
				for _, backendName := range curKeys {

					updLen := len(updBackendsMap[backendName].Endpoints)
					totalSlots := len(curBackendSlots[backendName].EmptySlots) + len(curBackendSlots[backendName].FullSlots)
					if updLen > totalSlots || updLen < (totalSlots-updatedConfig.Cfg.BackendSlotIncrement) {
						// need to resize number of empty slots by BackendSlotIncrement amount
						reconfigureEmptySlots = true
					} else {
						// everything fits so reconfigure endpoints without reloading
						// do it with maps posing as sets
						curEndpoints := ingressEndpointsRemap(curBackendsMap[backendName].Endpoints)
						updEndpoints := ingressEndpointsRemap(updBackendsMap[backendName].Endpoints)

						toRemoveEndpoints := endpointsSubtract(curEndpoints, updEndpoints)
						toAddEndpoints := endpointsSubtract(updEndpoints, curEndpoints)

						// check for new/removed entries in this backend, issue socket commands
						backendSlots := updatedConfig.BackendSlots[backendName]
						// remove endpoints
						for k, _ := range toRemoveEndpoints {
							err := utils.SendToSocket(haproxy.CurrentConfig.Cfg.StatsSocket,
								fmt.Sprintf("set server %s/%s state maint\n", backendName, backendSlots.FullSlots[k].BackendSrvName))
							if err != nil {
								glog.Warningln("failed socket command srv remove")
								haproxy.ReloadRequired = true
							}
							backendSlots.EmptySlots = append(backendSlots.EmptySlots, backendSlots.FullSlots[k].BackendSrvName)
							delete(backendSlots.FullSlots, k)
						}
						sort.Strings(backendSlots.EmptySlots)
						// add endpoints
						for k, endpoint := range toAddEndpoints {
							// rearrange slots
							backendSlots.FullSlots[k] = types.HAProxyBackendSlot{
								//backendSlots.EmptySlots[len(backendSlots.EmptySlots)-1],
								backendSlots.EmptySlots[0],
								endpoint,
							}
							backendSlots.EmptySlots = backendSlots.EmptySlots[1:]

							// send socket commands
							err1 := utils.SendToSocket(haproxy.CurrentConfig.Cfg.StatsSocket,
								fmt.Sprintf("set server %s/%s addr %s port %s\n", backendName, backendSlots.FullSlots[k].BackendSrvName, endpoint.Address, endpoint.Port))
							err2 := utils.SendToSocket(haproxy.CurrentConfig.Cfg.StatsSocket,
								fmt.Sprintf("set server %s/%s state ready\n", backendName, backendSlots.FullSlots[k].BackendSrvName))
							if err1 != nil || err2 != nil {
								glog.Warningln("failed socket command srv add")
								haproxy.ReloadRequired = true
							}
						}
						updatedConfig.BackendSlots[backendName] = backendSlots
						// reload if any socket commands were unsuccessful
					}
				}
			}
		}
		// restore backend lists
		haproxy.CurrentConfig.Backends = curBackends
		updatedConfig.Backends = updBackends
		// restore backend slots
		haproxy.CurrentConfig.BackendSlots = curBackendSlots
	}

	// expand or reduce number of slots in configuration file
	if haproxy.CurrentConfig == nil || reconfigureEmptySlots {
		haproxy.ReloadRequired = true
		updBackendsMap, updKeys := ingressBackendsRemap(updatedConfig.Backends)
		updatedConfig.BackendSlots = map[string]types.HAProxyBackendSlots{}

		for _, backendName := range updKeys {
			newBackend := types.HAProxyBackendSlots{}
			newBackend.FullSlots = map[string]types.HAProxyBackendSlot{}
			for i, endpoint := range updBackendsMap[backendName].Endpoints {
				newBackend.FullSlots[fmt.Sprintf("%s:%s", endpoint.Address, endpoint.Port)] = types.HAProxyBackendSlot{
					fmt.Sprintf("server%04d", i),
					&endpoint,
				}
			}
			fullSlotCnt := len(newBackend.FullSlots)
			// add up to BackendSlotIncrement empty slots
			extraSlotCnt := (int(fullSlotCnt/updatedConfig.Cfg.BackendSlotIncrement)+1)*updatedConfig.Cfg.BackendSlotIncrement - fullSlotCnt
			for i := 0; i < extraSlotCnt; i++ {
				newBackend.EmptySlots = append(newBackend.EmptySlots, fmt.Sprintf("server%04d", i+fullSlotCnt))
			}
			updatedConfig.BackendSlots[backendName] = newBackend
		}
	}

	haproxy.CurrentConfig = updatedConfig

	data, err := haproxy.template.execute(updatedConfig)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Reload reload the backend if the configuration has changed
func (haproxy *HAProxyController) Reload(data []byte) ([]byte, bool, error) {
	/*
		if !haproxy.configChanged(data) {
			return nil, false, nil
		}
	*/
	// TODO missing HAProxy validation before overwrite and try to reload
	err := ioutil.WriteFile(haproxy.configFile, data, 0644)
	if err != nil {
		return nil, false, err
	}

	if !haproxy.ReloadRequired {
		glog.Infoln("reload not required")
		return nil, false, nil
	}
	glog.Infoln("reload is required")

	out, err := haproxy.reloadHaproxy()
	if err == nil {
		haproxy.ReloadRequired = false
	}
	if len(out) > 0 {
		glog.Infof("HAProxy output:\n%v", string(out))
	}
	return out, true, err
}

/*
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
*/

func (haproxy *HAProxyController) reloadHaproxy() ([]byte, error) {
	out, err := exec.Command(haproxy.command, *haproxy.reloadStrategy, haproxy.configFile).CombinedOutput()
	return out, err
}
