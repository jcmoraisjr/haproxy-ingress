package config

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
)

//
// string const
//

func StringValue(value string) flag.Value {
	return &stringValue{value}
}

type stringValue struct {
	val string
}

func (s *stringValue) Get() interface{} {
	return s.val
}

func (s *stringValue) Set(val string) error {
	s.val = val
	return nil
}

func (s *stringValue) String() string {
	return s.val
}

//
// []float64
//

func FlagFloat64SliceVar(fs *flag.FlagSet, p *[]float64, name string, value []float64, usage string) {
	*p = value
	fs.Var((*float64SliceValue)(p), name, usage)
}

type float64SliceValue []float64

func (f *float64SliceValue) Get() interface{} {
	return (*[]float64)(f)
}

func (f *float64SliceValue) Set(val string) error {
	s := strings.Split(val, ",")
	*f = make([]float64, len(s))
	var err error
	for i := range s {
		(*f)[i], err = strconv.ParseFloat(s[i], 64)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *float64SliceValue) String() string {
	s := make([]string, len(*f))
	for i := range s {
		s[i] = strconv.FormatFloat((*f)[i], 'f', -1, 32)
	}
	return fmt.Sprintf("%+v", strings.Join(s, ","))
}
