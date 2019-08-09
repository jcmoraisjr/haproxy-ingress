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

package annotations

import (
	"regexp"
	"strconv"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

type validate struct {
	logger types.Logger
	source *Source
	key    string
	value  string
}

var (
	corsOriginRegex  = regexp.MustCompile(`^(https?://[A-Za-z0-9\-\.]*(:[0-9]+)?|\*)?$`)
	corsMethodsRegex = regexp.MustCompile(`^([A-Za-z]+,?\s?)+$`)
	corsHeadersRegex = regexp.MustCompile(`^([A-Za-z0-9\-\_]+,?\s?)+$`)
)

var validators = map[string]func(v validate) (string, bool){
	ingtypes.BackCorsAllowCredentials: validateBool,
	ingtypes.BackCorsAllowHeaders: func(v validate) (string, bool) {
		if corsHeadersRegex.MatchString(v.value) {
			return v.value, true
		}
		v.logger.Warn("ignoring invalid cors headers on %s: %s", v.source, v.value)
		return "", false
	},
	ingtypes.BackCorsAllowMethods: func(v validate) (string, bool) {
		if corsMethodsRegex.MatchString(v.value) {
			return v.value, true
		}
		v.logger.Warn("ignoring invalid cors methods on %s: %s", v.source, v.value)
		return "", false
	},
	ingtypes.BackCorsAllowOrigin: func(v validate) (string, bool) {
		if corsOriginRegex.MatchString(v.value) {
			return v.value, true
		}
		v.logger.Warn("ignoring invalid cors origin on %s: %s", v.source, v.value)
		return "", false
	},
	ingtypes.BackCorsExposeHeaders: func(v validate) (string, bool) {
		if corsHeadersRegex.MatchString(v.value) {
			return v.value, true
		}
		v.logger.Warn("ignoring invalid cors expose headers on %s: %s", v.source, v.value)
		return "", false
	},
	ingtypes.BackCorsMaxAge: func(v validate) (string, bool) {
		maxAge, err := strconv.Atoi(v.value)
		if err == nil || maxAge > 0 {
			return v.value, true
		}
		v.logger.Warn("ignoring invalid cors max age on %s: %s", v.source, v.value)
		return "", false
	},
	ingtypes.BackHSTS:                  validateBool,
	ingtypes.BackHSTSMaxAge:            validateInt,
	ingtypes.BackHSTSPreload:           validateBool,
	ingtypes.BackHSTSIncludeSubdomains: validateBool,
	ingtypes.BackSSLRedirect:           validateBool,
}

func validateBool(v validate) (string, bool) {
	if res, err := strconv.ParseBool(v.value); err == nil {
		return strconv.FormatBool(res), true
	}
	v.logger.Warn("ignoring invalid bool expression on %s key '%s': %s", v.source, v.key, v.value)
	return "", false
}

func validateInt(v validate) (string, bool) {
	if res, err := strconv.Atoi(v.value); err == nil {
		return strconv.Itoa(res), true
	}
	v.logger.Warn("ignoring invalid int expression on %s key '%s': %s", v.source, v.key, v.value)
	return "", false
}
