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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types/helper_test"
)

type testConfig struct {
	t              *testing.T
	logger         *helper_test.LoggerMock
	templateConfig *Config
	tempdir        string
	tempdirOutput  string
}

func TestNewTemplateFileNotFound(t *testing.T) {
	c := setup(t)
	defer c.teardown()
	c.templateConfig.NewTemplate("h.cfg", "/file", "/tmp/out", 0, 1024)
	c.logger.CompareLogging("FATAL cannot read template file: open /file: no such file or directory")
}

func TestWrite(t *testing.T) {
	type tmplContent struct {
		content string
		rotate  int
		outputs []string
		logging string
	}
	type data1 struct {
		Name string
	}
	type data2 struct {
		Name string
		Age  int
	}
	testCases := []struct {
		templates []tmplContent
		datas     []interface{}
		tempdir   string
	}{
		// 0
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					outputs: []string{"jack1"},
				},
			},
			datas: []interface{}{
				data1{Name: "jack1"},
			},
		},
		// 1
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					rotate:  1,
					outputs: []string{"james1"},
				},
			},
			datas: []interface{}{
				data1{Name: "james1"},
			},
		},
		// 2
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					rotate:  1,
					outputs: []string{"joe2", "joe3"},
				},
			},
			datas: []interface{}{
				data1{Name: "joe1"},
				data1{Name: "joe2"},
				data1{Name: "joe3"},
			},
		},
		// 3
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					rotate:  3,
					outputs: []string{"jane1", "jane2"},
				},
			},
			datas: []interface{}{
				data1{Name: "jane1"},
				data1{Name: "jane2"},
			},
		},
		// 4
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					rotate:  3,
					outputs: []string{"joseph3", "joseph4", "joseph5", "joseph6"},
				},
			},
			datas: []interface{}{
				data1{Name: "joseph1"},
				data1{Name: "joseph2"},
				data1{Name: "joseph3"},
				data1{Name: "joseph4"},
				data1{Name: "joseph5"},
				data1{Name: "joseph6"},
			},
		},
		// 5
		{
			templates: []tmplContent{
				{
					content: `{{ $m := map "a" .Name }}{{ $m.p1 }} - {{ $m.p2 }}`,
					outputs: []string{"a - john1"},
				},
			},
			datas: []interface{}{
				data1{Name: "john1"},
			},
		},
		// 6
		{
			templates: []tmplContent{
				{
					content: `{{ $i := int64 "525" }}{{ $j := int64 "a525" }}{{ $i }} - {{ $j }}`,
					outputs: []string{"525 - 0"},
				},
			},
			datas: []interface{}{
				data1{Name: "john1"},
			},
		},
		// 7
		{
			templates: []tmplContent{
				{
					content: "{{ .NameFail }}",
					outputs: []string{""},
					logging: `ERROR from writer: template: h1.tmpl:1:3: executing "h1.tmpl" at <.NameFail>: can't evaluate field NameFail in type template.data1`,
				},
			},
			datas: []interface{}{
				data1{Name: "joe1"},
			},
		},
		// 8
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					outputs: []string{""},
					logging: `ERROR from writer: cannot write /tmp/haproxy-ingress/cannot/stat/here/h1.cfg: open /tmp/haproxy-ingress/cannot/stat/here/h1.cfg: no such file or directory`,
				},
			},
			datas: []interface{}{
				data1{Name: "joe1"},
			},
			tempdir: "/tmp/haproxy-ingress/cannot/stat/here",
		},
		// 9
		{
			templates: []tmplContent{
				{
					content: "{{ .Name }}",
					rotate:  2,
					outputs: []string{"joe3", "joe4", "joe5"},
				},
				{
					content: "{{ .Age }}",
					rotate:  1,
					outputs: []string{"34", "35"},
				},
			},
			datas: []interface{}{
				data2{Name: "joe1", Age: 31},
				data2{Name: "joe2", Age: 32},
				data2{Name: "joe3", Age: 33},
				data2{Name: "joe4", Age: 34},
				data2{Name: "joe5", Age: 35},
			},
		},
	}

	for i, test := range testCases {
		c := setup(t)
		if test.tempdir != "" {
			c.tempdirOutput = test.tempdir
		}
		defer c.teardown()
		for _, tmpl := range test.templates {
			c.newTemplate(tmpl.content, tmpl.rotate)
		}
		for _, data := range test.datas {
			if err := c.templateConfig.Write(data); err != nil {
				c.logger.Error("from writer: %v", err)
			}
			// writes would override older configs
			// generated in the same millisecond
			time.Sleep(10 * time.Millisecond)
		}
		for j, tmpl := range test.templates {
			outs := len(tmpl.outputs)
			if tmpl.rotate < outs-1 {
				t.Errorf("test %d has len(outputs)=%d, expected rotate at least %d but was %d", i, outs, outs-1, tmpl.rotate)
				continue
			}
			outputs := c.outputs(j)
			expected := tmpl.rotate + 1
			if expected > outs {
				expected = outs
			}
			if len(outputs) != expected {
				t.Errorf("test %d expected %d rotated+actual configs but found %d", i, expected, len(outputs))
				continue
			}
			for k, out := range tmpl.outputs {
				if outputs[k] != out {
					t.Errorf("test %d expected content '%s' on item %d, but found '%v'", i, out, k, outputs[k])
				}
			}
			c.logger.CompareLogging(tmpl.logging)
		}
	}
}

func (c *testConfig) newTemplate(content string, rotate int) {
	cnt := len(c.templateConfig.templates) + 1
	templateFileName := fmt.Sprintf("h%d.tmpl", cnt)
	templatePath := c.tempdir + string(os.PathSeparator) + templateFileName
	outputFileName := fmt.Sprintf("h%d.cfg", cnt)
	outputPath := c.tempdirOutput + string(os.PathSeparator) + outputFileName
	if err := ioutil.WriteFile(templatePath, []byte(content), 0644); err != nil {
		c.t.Errorf("error writing template file: %v", err)
	}
	c.templateConfig.NewTemplate(templateFileName, templatePath, outputPath, rotate, 1024)
}

func (c *testConfig) outputs(index int) []string {
	file := c.tempdir + string(os.PathSeparator) + fmt.Sprintf("h%d.cfg", index+1)
	files, _ := filepath.Glob(file + ".*")
	contents := []string{}
	for _, f := range files {
		cnt, _ := ioutil.ReadFile(f)
		contents = append(contents, string(cnt))
	}
	cnt, _ := ioutil.ReadFile(file)
	contents = append(contents, string(cnt))
	return contents
}

func setup(t *testing.T) *testConfig {
	logger := &helper_test.LoggerMock{T: t}
	tempdir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("error creating tempdir: %v", err)
	}
	return &testConfig{
		t:      t,
		logger: logger,
		templateConfig: &Config{
			Logger: logger,
		},
		tempdir:       tempdir,
		tempdirOutput: tempdir,
	}
}

func (c *testConfig) teardown() {
	c.logger.CompareLogging("")
	if err := os.RemoveAll(c.tempdir); err != nil {
		c.t.Errorf("error removing tempdir: %v", err)
	}
}
