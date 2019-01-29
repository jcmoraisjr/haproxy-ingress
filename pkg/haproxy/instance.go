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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/dynconfig"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// InstanceOptions ...
type InstanceOptions struct {
	HAProxyCmd        string
	ReloadCmd         string
	HAProxyConfigFile string
	ReloadStrategy    string
}

// Instance ...
type Instance interface {
	CreateConfig() Config
	Config() Config
	Templates() *template.Config
	Update()
}

// CreateInstance ...
func CreateInstance(logger types.Logger, options InstanceOptions) Instance {
	tmpl := &template.Config{
		Logger: logger,
	}
	dynconf := &dynconfig.Config{
		Logger: logger,
	}
	return &instance{
		logger:    logger,
		options:   &options,
		templates: tmpl,
		dynconfig: dynconf,
		curConfig: createConfig(),
	}
}

type instance struct {
	logger    types.Logger
	options   *InstanceOptions
	templates *template.Config
	dynconfig *dynconfig.Config
	oldConfig Config
	curConfig Config
}

func (i *instance) Templates() *template.Config {
	return i.templates
}

func (i *instance) CreateConfig() Config {
	i.releaseConfig()
	i.oldConfig = i.curConfig
	i.curConfig = createConfig()
	return i.curConfig
}

func (i *instance) Config() Config {
	return i.curConfig
}

func (i *instance) Update() {
	if i.curConfig.Equals(i.oldConfig) {
		i.logger.InfoV(2, "old and new configurations match, skipping reload")
		return
	}
	updated := i.dynconfig.Update()
	if err := i.templates.Write(i.Config()); err != nil {
		i.logger.Error("error writing configuration: %v", err)
		return
	}
	if err := i.check(); err != nil {
		i.logger.Error("error validating config file:\n%v", err)
		return
	}
	if updated {
		i.logger.Info("HAProxy updated without needing to reload")
		return
	}
	if err := i.reload(); err != nil {
		i.logger.Error("error reloading server:\n%v", err)
		return
	}
	i.logger.Info("HAProxy successfully reloaded")
}

func (i *instance) check() error {
	i.logger.Info("VERIFIED! (skipped)")
	return nil
	out, err := exec.Command(i.options.HAProxyCmd, "-c", "-f", i.options.HAProxyConfigFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf(string(out))
	}
	return nil
}

func (i *instance) reload() error {
	i.logger.Info("RELOADED! (skipped)")
	return nil
	out, err := exec.Command(i.options.ReloadCmd, i.options.ReloadStrategy, i.options.HAProxyConfigFile).CombinedOutput()
	if len(out) > 0 {
		return fmt.Errorf(string(out))
	} else if err != nil {
		return err
	}
	return nil
}

func (i *instance) releaseConfig() {
	// TODO
}
