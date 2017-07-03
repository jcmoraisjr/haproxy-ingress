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

package utils

import (
	"github.com/golang/glog"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
)

// MergeMap copy keys from a `data` map to a `resultTo` tagged object
func MergeMap(data map[string]string, resultTo interface{}) error {
	if data != nil {
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			WeaklyTypedInput: true,
			Result:           resultTo,
			TagName:          "json",
		})
		if err != nil {
			glog.Warningf("error configuring decoder: %v", err)
		} else {
			if err = decoder.Decode(data); err != nil {
				glog.Warningf("error decoding config: %v", err)
			}
		}
		return err
	}
	return nil
}

// SendToSocket send strings to a unix socket specified
func SendToSocket(socket string, command string) error {
	c, err := net.Dial("unix", socket)
	if err != nil {
		glog.Warningf("error sending to unix socket: %v", err)
		return err
	}
	sent, err := c.Write([]byte(command))
	if err != nil || sent != len(command) {
		glog.Warningf("error sending to unix socket %s", socket)
		return err
	}
	readBuffer := make([]byte, 2048)
	rcvd, err := c.Read(readBuffer)
	if rcvd > 2 {
		glog.Infof("haproxy stat socket response: \"%s\"", string(readBuffer[:rcvd-2]))
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

// multibinderERBOnly generates a config file from ERB template by invoking multibinder-haproxy-erb
func multibinderERBOnly(configFile string) (string, error) {
	out, err := exec.Command("multibinder-haproxy-erb", "/usr/local/sbin/haproxy", "-f", configFile, "-c", "-q").CombinedOutput()
	if err != nil {
		glog.Warningf("Error validating config file:\n%v", string(out))
		return "", err
	}
	return configFile[:strings.LastIndex(configFile, ".erb")], nil
}

// RewriteConfigFiles safely replaces configuration files with new contents after validation
func RewriteConfigFiles(data []byte, reloadStrategy, configFile string) error {
	tmpf := "/etc/haproxy/new_cfg.erb"

	err := ioutil.WriteFile(tmpf, data, 644)
	if err != nil {
		glog.Warningln("Error writing rendered template to file")
		return err
	}

	if reloadStrategy == "multibinder" {
		generated, err := multibinderERBOnly(tmpf)
		if err != nil {
			return err
		}
		err = os.Rename(generated, "/etc/haproxy/haproxy.cfg")
		if err != nil {
			glog.Warningln("Error updating config file")
			return err
		}
	} else {
		err = checkValidity(tmpf)
		if err != nil {
			return err
		}
	}
	err = os.Rename(tmpf, configFile)
	if err != nil {
		glog.Warningln("Error updating config file")
		return err
	}

	return nil
}
