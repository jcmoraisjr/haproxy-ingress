package framework

import (
	"fmt"
	"math/rand"
)

func AppendStringMap(src, add map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range src {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

func RandomHostName() string {
	return fmt.Sprintf("host-%08d.local", rand.Intn(1e8))
}
