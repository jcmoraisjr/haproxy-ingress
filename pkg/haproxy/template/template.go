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
	"bytes"
	"fmt"
	"os"
	"strings"
	gotemplate "text/template"
)

// CreateConfig ...
func CreateConfig() *Config {
	return &Config{}
}

// Config ...
type Config struct {
	templates []*template
}

// ClearTemplates ...
func (c *Config) ClearTemplates() {
	c.templates = nil
}

// NewTemplate ...
func (c *Config) NewTemplate(name, file, output string, rotate, startingBufferSize int) error {
	tmpl, err := gotemplate.New(name).Funcs(funcMap).ParseFiles(file)
	if err != nil {
		return fmt.Errorf("cannot read template file: %v", err)
	}
	c.templates = append(c.templates, &template{
		tmpl:      tmpl,
		output:    output,
		rotate:    rotate,
		rawConfig: bytes.NewBuffer(make([]byte, 0, startingBufferSize)),
	})
	return nil
}

// Write ...
func (c *Config) Write(data interface{}) error {
	return c.WriteOutput(data, "")
}

// WriteOutput ...
func (c *Config) WriteOutput(data interface{}, output string) error {
	for _, t := range c.templates {
		t.rawConfig.Reset()
		if err := t.tmpl.Execute(t.rawConfig, data); err != nil {
			return err
		}
	}
	for _, t := range c.templates {
		if err := t.writeToDisk(output); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) WriteTemplate(tmplDef string, data any) (string, error) {
	strbld := &strings.Builder{}
	for _, t := range c.templates {
		if err := t.tmpl.ExecuteTemplate(strbld, tmplDef, data); err != nil {
			return "", err
		}
	}
	return strbld.String(), nil
}

type template struct {
	tmpl        *gotemplate.Template
	output      string
	rotate      int
	rawConfig   *bytes.Buffer
	configFiles []string
}

func (t *template) writeToDisk(output string) error {
	if output == "" {
		output = t.output
	}
	if output == "" {
		return fmt.Errorf("output file is empty, configure on NewTemplate() or use WriteOutput()")
	}
	if t.rotate > 0 {
		// Include timestamp in rotated config file names to aid troubleshooting.
		// When using a single, ever-changing config file it was difficult
		// to know what config was loaded by any given haproxy process
		//
		// rename current config file, if exists
		if f, err := os.Stat(output); f != nil {
			rotateTo := output + "." + f.ModTime().Format("20060102-150405.000")
			if err := os.Rename(output, rotateTo); err != nil {
				return fmt.Errorf("cannot rotate %s: %v", output, err)
			}
			t.configFiles = append(t.configFiles, rotateTo)
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot rotate %s: %v", output, err)
		}
		// remove old config files
		for len(t.configFiles) > t.rotate {
			name := t.configFiles[0]
			if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot remove old config file %s: %v", name, err)
			}
			t.configFiles = t.configFiles[1:]
		}
	}
	if err := os.WriteFile(output, t.rawConfig.Bytes(), 0644); err != nil {
		return fmt.Errorf("cannot write %s: %v", output, err)
	}
	return nil
}
