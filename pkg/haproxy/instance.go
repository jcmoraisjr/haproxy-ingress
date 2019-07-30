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

package haproxy

import (
	"fmt"
	"os/exec"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// InstanceOptions ...
type InstanceOptions struct {
	MaxOldConfigFiles int
	HAProxyCmd        string
	HAProxyConfigFile string
	ReloadCmd         string
	ReloadStrategy    string
}

// Instance ...
type Instance interface {
	ParseTemplates() error
	Config() Config
	Update(timer *utils.Timer)
}

// CreateInstance ...
func CreateInstance(logger types.Logger, bindUtils hatypes.BindUtils, options InstanceOptions) Instance {
	return &instance{
		logger:       logger,
		bindUtils:    bindUtils,
		options:      &options,
		templates:    template.CreateConfig(),
		mapsTemplate: template.CreateConfig(),
		mapsDir:      "/etc/haproxy/maps",
	}
}

type instance struct {
	logger       types.Logger
	bindUtils    hatypes.BindUtils
	options      *InstanceOptions
	templates    *template.Config
	mapsTemplate *template.Config
	mapsDir      string
	oldConfig    Config
	curConfig    Config
}

func (i *instance) ParseTemplates() error {
	i.templates.ClearTemplates()
	i.mapsTemplate.ClearTemplates()
	if err := i.templates.NewTemplate(
		"spoe-modsecurity.tmpl",
		"/etc/haproxy/modsecurity/spoe-modsecurity.tmpl",
		"/etc/haproxy/spoe-modsecurity.conf",
		0,
		1024,
	); err != nil {
		return err
	}
	if err := i.templates.NewTemplate(
		"haproxy.tmpl",
		"/etc/haproxy/template/haproxy.tmpl",
		"/etc/haproxy/haproxy.cfg",
		i.options.MaxOldConfigFiles,
		16384,
	); err != nil {
		return err
	}
	err := i.mapsTemplate.NewTemplate(
		"map.tmpl",
		"/etc/haproxy/maptemplate/map.tmpl",
		"",
		0,
		2048,
	)
	return err
}

func (i *instance) Config() Config {
	if i.curConfig == nil {
		config := createConfig(i.bindUtils, options{
			mapsTemplate: i.mapsTemplate,
			mapsDir:      i.mapsDir,
		})
		i.curConfig = config
	}
	return i.curConfig
}

func (i *instance) Update(timer *utils.Timer) {
	if i.curConfig == nil {
		i.logger.Info("new configuration is empty")
		return
	}
	if err := i.curConfig.BuildFrontendGroup(); err != nil {
		i.logger.Error("error building configuration group: %v", err)
		i.clearConfig()
		return
	}
	if err := i.curConfig.BuildBackendMaps(); err != nil {
		i.logger.Error("error building backend maps: %v", err)
		i.clearConfig()
		return
	}
	if i.curConfig.Equals(i.oldConfig) {
		i.logger.InfoV(2, "old and new configurations match, skipping reload")
		i.clearConfig()
		return
	}
	updater := i.newDynUpdater()
	updated := updater.update()
	if err := i.templates.Write(i.curConfig); err != nil {
		i.logger.Error("error writing configuration: %v", err)
		i.clearConfig()
		return
	}
	i.clearConfig()
	timer.Tick("writeTmpl")
	if updated {
		if err := i.check(); err != nil {
			i.logger.Error("error validating config file:\n%v", err)
		}
		timer.Tick("validate")
		if updater.cmdCnt > 0 {
			i.logger.Info("HAProxy updated without needing to reload. Commands sent: %d", updater.cmdCnt)
		} else {
			i.logger.Info("old and new configurations match")
		}
		return
	}
	if err := i.reload(); err != nil {
		i.logger.Error("error reloading server:\n%v", err)
		return
	}
	timer.Tick("reload")
	i.logger.Info("HAProxy successfully reloaded")
}

func (i *instance) check() error {
	if i.options.HAProxyCmd == "" {
		i.logger.Info("(test) check was skipped")
		return nil
	}
	out, err := exec.Command(i.options.HAProxyCmd, "-c", "-f", i.options.HAProxyConfigFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf(string(out))
	}
	return nil
}

func (i *instance) reload() error {
	if i.options.ReloadCmd == "" {
		i.logger.Info("(test) reload was skipped")
		return nil
	}
	out, err := exec.Command(i.options.ReloadCmd, i.options.ReloadStrategy, i.options.HAProxyConfigFile).CombinedOutput()
	if len(out) > 0 {
		i.logger.Warn("output from haproxy:\n%v", string(out))
	}
	if err != nil {
		return err
	}
	return nil
}

func (i *instance) clearConfig() {
	// TODO releaseConfig (old support files, ...)
	i.oldConfig = i.curConfig
	i.curConfig = nil
}
