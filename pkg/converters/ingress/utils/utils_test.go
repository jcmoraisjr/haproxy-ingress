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
	"testing"
)

func TestGCD(t *testing.T) {
	testCases := []struct {
		a        int
		b        int
		expected int
	}{
		{10, 1, 1},
		{10, 3, 1},
		{10, 4, 2},
		{10, 5, 5},
		{10, 10, 10},
		{10, 12, 2},
		{10, 15, 5},
		{10, 20, 10},
	}
	for _, test := range testCases {
		res := GCD(test.a, test.b)
		if res != test.expected {
			t.Errorf("expected %v from %v and %v, but was %v", test.expected, test.a, test.b, res)
		}
	}
}

func TestLCM(t *testing.T) {
	testCases := []struct {
		a        int
		b        int
		expected int
	}{
		{10, 1, 10},
		{10, 3, 30},
		{10, 4, 20},
		{10, 5, 10},
		{10, 10, 10},
		{10, 12, 60},
		{10, 15, 30},
		{10, 20, 20},
	}
	for _, test := range testCases {
		res := LCM(test.a, test.b)
		if res != test.expected {
			t.Errorf("expected %v from %v and %v, but was %v", test.expected, test.a, test.b, res)
		}
	}
}

func TestUpdateStructSame(t *testing.T) {
	type data struct {
		Name string `json:"the-name,option1,option2"`
		Age  int
	}
	testCase := []struct {
		defaults data
		in       data
		out      data
		expout   data
		expskip  []string
	}{
		{data{}, data{"jack", 28}, data{}, data{"jack", 28}, []string{}},
		{data{}, data{"jack", 28}, data{"joe", 19}, data{"joe", 19}, []string{"the-name", "Age"}},
		{data{}, data{"joe", 28}, data{"joe", 19}, data{"joe", 19}, []string{"Age"}},
		{data{}, data{"jack", 19}, data{"joe", 19}, data{"joe", 19}, []string{"the-name"}},
		{data{"joe", 19}, data{"joe", 19}, data{"jack", 28}, data{"jack", 28}, []string{}},
		{data{"joe", 19}, data{"jack", 28}, data{"joe", 19}, data{"jack", 28}, []string{}},
		{data{"jane", 19}, data{"jack", 28}, data{"joe", 19}, data{"joe", 28}, []string{"the-name"}},
		{data{"joe", 29}, data{"jack", 28}, data{"joe", 19}, data{"jack", 19}, []string{"Age"}},
		{data{"jane", 29}, data{"jack", 28}, data{"joe", 19}, data{"joe", 19}, []string{"the-name", "Age"}},
	}
	for i, test := range testCase {
		skipped, err := UpdateStruct(&test.defaults, &test.in, &test.out)
		if len(err) != 0 {
			t.Errorf("test %d expected no error but returned %v", i, err)
		}
		if !reflect.DeepEqual(test.out, test.expout) {
			t.Errorf("test %d expected out %v but was %v", i, test.expout, test.out)
		}
		if len(skipped) == len(test.expskip) {
			for j := range skipped {
				if skipped[j] != test.expskip[j] {
					t.Errorf("test %d expected skipped msg '%v' but was '%v'", i, test.expskip[j], skipped[j])
				}
			}
		} else {
			t.Errorf("test %d expected skipped %v but was %v", i, test.expskip, skipped)
		}
	}
}

func TestUpdateStructBool(t *testing.T) {
	type data struct {
		Evil bool `yaml:"the-evil"`
	}
	testCase := []struct {
		defaults data
		in       data
		out      data
		expout   data
		expskip  []string
	}{
		{data{false}, data{false}, data{false}, data{false}, []string{}},
		{data{false}, data{false}, data{true}, data{true}, []string{}},
		{data{false}, data{true}, data{false}, data{true}, []string{}},
		{data{false}, data{true}, data{true}, data{true}, []string{}},
		{data{true}, data{false}, data{false}, data{false}, []string{}},
		{data{true}, data{false}, data{true}, data{false}, []string{}},
		{data{true}, data{true}, data{false}, data{false}, []string{}},
		{data{true}, data{true}, data{true}, data{true}, []string{}},
	}
	for i, test := range testCase {
		skipped, err := UpdateStruct(&test.defaults, &test.in, &test.out)
		if len(err) != 0 {
			t.Errorf("test %d expected no error but returned %v", i, err)
		}
		if !reflect.DeepEqual(test.out, test.expout) {
			t.Errorf("test %d expected out %v but was %v", i, test.expout, test.out)
		}
		if len(skipped) == len(test.expskip) {
			for j := range skipped {
				if skipped[j] != test.expskip[j] {
					t.Errorf("test %d expected skipped msg '%v' but was '%v'", i, test.expskip[j], skipped[j])
				}
			}
		} else {
			t.Errorf("test %d expected skipped %v but was %v", i, test.expskip, skipped)
		}
	}
}

func TestUpdateStructDiff(t *testing.T) {
	type dataDef struct {
		Name  string
		Email string
	}
	type dataIn struct {
		Name  string `json:"the-name"`
		Age   int    `json:"the-age,"`
		Email string `json:",opt"`
	}
	type dataOut struct {
		Name string
		Age  int
	}
	testCase := []struct {
		defaults dataDef
		in       dataIn
		out      dataOut
		expout   dataOut
		expskip  []string
	}{
		{dataDef{}, dataIn{}, dataOut{"jack", 28}, dataOut{"jack", 28}, []string{}},
		{dataDef{"joe", ""}, dataIn{}, dataOut{"jack", 28}, dataOut{"jack", 28}, []string{"the-name"}},
		{dataDef{"jack", ""}, dataIn{"joe", 28, ""}, dataOut{"jack", 28}, dataOut{"joe", 28}, []string{}},
		{dataDef{"jack", ""}, dataIn{"joe", 19, ""}, dataOut{"jack", 28}, dataOut{"joe", 28}, []string{"the-age"}},
		{dataDef{}, dataIn{"jack", 28, "jack@example.com"}, dataOut{}, dataOut{"jack", 28}, []string{}},
		{dataDef{}, dataIn{"jack", 28, "jack@example.com"}, dataOut{"joe", 0}, dataOut{"joe", 28}, []string{"the-name"}},
		{dataDef{}, dataIn{"jack", 28, "jack@example.com"}, dataOut{"", 19}, dataOut{"jack", 19}, []string{"the-age"}},
	}
	for i, test := range testCase {
		skipped, err := UpdateStruct(test.defaults, test.in, &test.out)
		if len(err) != 0 {
			t.Errorf("test %d expected no error but returned %v", i, err)
		}
		if !reflect.DeepEqual(test.out, test.expout) {
			t.Errorf("test %d expected out %v but was %v", i, test.expout, test.out)
		}
		if len(skipped) == len(test.expskip) {
			for j := range skipped {
				if skipped[j] != test.expskip[j] {
					t.Errorf("test %d expected skipped msg '%v' but was '%v'", i, test.expskip[j], skipped[j])
				}
			}
		} else {
			t.Errorf("test %d expected skipped %v but was %v", i, test.expskip, skipped)
		}
	}
}

func TestUpdateStructUnexported(t *testing.T) {
	type dataUnexp struct {
		name string
		Age  int
	}
	type dataExp struct {
		Name string
		Age  int
	}
	UpdateStruct(dataUnexp{}, dataUnexp{}, dataUnexp{})
	UpdateStruct(dataUnexp{}, dataUnexp{}, dataExp{})
	UpdateStruct(dataUnexp{}, dataExp{}, dataUnexp{})
	UpdateStruct(dataUnexp{}, dataExp{}, dataExp{})
	UpdateStruct(dataExp{}, dataUnexp{}, dataUnexp{})
	UpdateStruct(dataExp{}, dataUnexp{}, dataExp{})
	UpdateStruct(dataExp{}, dataExp{}, dataUnexp{})
	UpdateStruct(dataExp{}, dataExp{}, dataExp{})
}

func TestUpdateStructMismatch(t *testing.T) {
	err := make([][]error, 3)
	experr := make([][]string, 3)

	// 0
	type data0a struct {
		Name string
		Age  int
	}
	type data0b struct {
		Name bool
		Age  string
	}
	_, err[0] = UpdateStruct(data0a{}, data0a{"joe", 19}, data0b{})
	experr[0] = []string{
		"type mismatch on field 'Name' of types '%s.data0a' and '%s.data0b'",
		"type mismatch on field 'Age' of types '%s.data0a' and '%s.data0b'",
	}

	// 1
	type data1a struct {
		Name string `yaml:",opt"`
		Age  int
	}
	type data1b struct {
		Name int
		Age  int
	}
	_, err[1] = UpdateStruct(data1a{}, data1a{"joe", 19}, &data1b{})
	experr[1] = []string{
		"type mismatch on field 'Name' of types '%s.data1a' and '%s.data1b'",
	}

	// 2
	type data2a struct {
		Name string
		Age  int `yaml:""`
	}
	type data2b struct {
		Name string
		Age  bool
	}
	_, err[2] = UpdateStruct(data2a{}, data2a{"joe", 19}, &data2b{})
	experr[2] = []string{
		"type mismatch on field 'Age' of types '%s.data2a' and '%s.data2b'",
	}

	pkg := "utils"
	for i := range experr {
		if len(err[i]) == len(experr[i]) {
			for j := range err[i] {
				exp := fmt.Sprintf(experr[i][j], pkg, pkg)
				if err[i][j].Error() != exp {
					t.Errorf("test %d expected error msg '%s' but was '%s'", i, exp, err[i][j].Error())
				}
			}
		} else {
			t.Errorf("test %d expected err %v but was %v", i, experr[i], err[i])
		}
	}
}
