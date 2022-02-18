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
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"k8s.io/klog/v2"
)

// Split returns a slice of substrings from s, separated by sep.
// If s is empty, Split returns an empty slice.
// Split will also TrimSpace() all resulting substrings.
func Split(s, sep string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(s, sep)
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

// LineToSlice converts POSIX line breaks to a string slice
func LineToSlice(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// MergeMap copy keys from a `data` map to a `resultTo` tagged object
func MergeMap(data map[string]string, resultTo interface{}) error {
	if data != nil {
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			WeaklyTypedInput: true,
			Result:           resultTo,
			TagName:          "json",
		})
		if err != nil {
			klog.Warningf("error configuring decoder: %v", err)
		} else {
			if err = decoder.Decode(data); err != nil {
				klog.Warningf("error decoding config: %v", err)
			}
		}
		return err
	}
	return nil
}

// SizeSuffixToInt64 converts a size in string format with suffix
// into int64
func SizeSuffixToInt64(size string) (int64, error) {
	value, err := strconv.ParseInt(size, 10, 64)
	if err == nil {
		return value, nil
	}
	if len(size) == 0 {
		return 0, fmt.Errorf("Cannot convert empty string to int64")
	}
	valueStr := size[:len(size)-1]
	value, err = strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Cannot convert %v to int64", valueStr)
	}
	suffix := size[len(size)-1:]
	var mult int64
	switch suffix {
	case "k", "K":
		mult = 1024
	case "m", "M":
		mult = 1024 * 1024
	case "g", "G":
		mult = 1024 * 1024 * 1024
	default:
		return value, fmt.Errorf("Invalid suffix: %v", suffix)
	}
	return value * mult, nil
}

// SendToSocket send strings to a unix socket specified
func SendToSocket(socket string, command string) error {
	c, err := net.Dial("unix", socket)
	if err != nil {
		klog.Warningf("error sending to unix socket: %v", err)
		return err
	}
	sent, err := c.Write([]byte(command))
	if err != nil || sent != len(command) {
		klog.Warningf("error sending to unix socket %s", socket)
		return err
	}
	readBuffer := make([]byte, 2048)
	rcvd, _ := c.Read(readBuffer)
	if rcvd > 2 {
		klog.Infof("haproxy stat socket response: \"%s\"", string(readBuffer[:rcvd-2]))
	}
	return nil
}
