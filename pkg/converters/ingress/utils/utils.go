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

package utils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// FullQualifiedName ...
func FullQualifiedName(namespace, name string) string {
	// TODO cross namespace
	return fmt.Sprintf("%s/%s", namespace, name)
}

// GCD calculates the Greatest Common Divisor between a and b
func GCD(a, b int) int {
	for b != 0 {
		r := a % b
		a, b = b, r
	}
	return a
}

// LCM calculates the Least Common Multiple between a and b
func LCM(a, b int) int {
	return a * (b / GCD(a, b))
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
			return fmt.Errorf("error configuring decoder: %v", err)
		}
		if err = decoder.Decode(data); err != nil {
			return fmt.Errorf("error decoding config: %v", err)
		}
	}
	return nil
}

// UpdateStruct ...
//
// out param need to receive with initialized data from defaults
func UpdateStruct(defaults, in, out interface{}) (skipped []string, err []error) {
	defv := reflect.Indirect(reflect.ValueOf(defaults))
	inv := reflect.Indirect(reflect.ValueOf(in))
	outv := reflect.Indirect(reflect.ValueOf(out))
	for i := 0; i < inv.NumField(); i++ {
		structField := inv.Type().Field(i)
		name := structField.Name
		inf := inv.Field(i)
		deff := defv.FieldByName(name)
		outf := outv.FieldByName(name)
		if !outf.IsValid() {
			// output not found
			continue
		}
		// tagName := readFieldTagName(structField)
		tagName := strings.Split(structField.Tag.Get("json"), ",")[0]
		if tagName == "" {
			tagName = structField.Name
		}
		if tagName == "-" {
			// ignored field
			continue
		}
		if inf.Type().Kind() != outf.Type().Kind() {
			err = append(err, fmt.Errorf(
				"type mismatch on field '%s' of types '%s' and '%s'",
				tagName, inv.Type().String(), outv.Type().String()))
			continue
		}
		if !inf.CanInterface() || !outf.CanInterface() {
			// unexported or something
			continue
		}
		if inf.Interface() == outf.Interface() {
			// already the same value
			continue
		}
		if deff.IsValid() {
			if outf.Interface() != deff.Interface() {
				if inf.Interface() != deff.Interface() {
					skipped = append(skipped, tagName)
				}
				continue
			}
		} else if outf.Interface() != reflect.Zero(outf.Type()).Interface() {
			if inf.Interface() != reflect.Zero(inf.Type()).Interface() {
				skipped = append(skipped, tagName)
			}
			continue
		}
		outf.Set(inf)
	}
	return skipped, err
}
