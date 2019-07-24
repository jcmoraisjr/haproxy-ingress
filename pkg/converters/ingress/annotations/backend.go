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
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	ingutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/utils"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func (c *updater) buildBackendAffinity(d *backData) {
	affinity, srcAffinity, foundAffinity := d.mapper.GetStr(ingtypes.BackAffinity)
	if affinity != "cookie" {
		if foundAffinity && affinity != "" {
			c.logger.Error("unsupported affinity type on %v: %s", srcAffinity, affinity)
		}
		return
	}
	name := d.mapper.GetStrValue(ingtypes.BackSessionCookieName)
	if name == "" {
		name = "INGRESSCOOKIE"
	}
	strategy, srcStrategy, foundStrategy := d.mapper.GetStr(ingtypes.BackSessionCookieStrategy)
	switch strategy {
	case "insert", "rewrite", "prefix":
	default:
		if foundStrategy {
			c.logger.Warn("invalid affinity cookie strategy '%s' on %v, using 'insert' instead", strategy, srcStrategy)
		}
		strategy = "insert"
	}
	d.backend.Cookie.Name = name
	d.backend.Cookie.Strategy = strategy
	d.backend.Cookie.Dynamic = d.mapper.GetBoolValue(ingtypes.BackSessionCookieDynamic)
}

func (c *updater) buildBackendAuthHTTP(d *backData) {
	authType, srcAuthType, foundAuthType := d.mapper.GetStr(ingtypes.BackAuthType)
	if authType != "basic" {
		if foundAuthType && authType != "" {
			c.logger.Error("unsupported authentication type on %v: %s", srcAuthType, authType)
		}
		return
	}
	authSecret, srcAuthSecret, foundAuthSecret := d.mapper.GetStr(ingtypes.BackAuthSecret)
	if !foundAuthSecret {
		srcAuthSecret = srcAuthType
	}
	if authSecret == "" {
		c.logger.Error("missing secret name on basic authentication on %v", srcAuthSecret)
		return
	}
	secretName := ingutils.FullQualifiedName(srcAuthSecret.Namespace, authSecret)
	listName := strings.Replace(secretName, "/", "_", 1)
	userlist := c.haproxy.FindUserlist(listName)
	if userlist == nil {
		userb, err := c.cache.GetSecretContent(secretName, "auth")
		if err != nil {
			c.logger.Error("error reading basic authentication on %v: %v", srcAuthSecret, err)
			return
		}
		userstr := string(userb)
		users, errs := extractUserlist(srcAuthSecret.Name, secretName, userstr)
		for _, err := range errs {
			c.logger.Warn("ignoring malformed usr/passwd on secret '%s', declared on %v: %v", secretName, srcAuthSecret, err)
		}
		userlist = c.haproxy.AddUserlist(listName, users)
		if len(users) == 0 {
			c.logger.Warn("userlist on %v for basic authentication is empty", srcAuthSecret)
		}
	}
	d.backend.Userlist.Name = userlist.Name
	realm := "localhost" // HAProxy's backend name would be used if missing
	authRealm, srcAuthRealm, _ := d.mapper.GetStr(ingtypes.BackAuthRealm)
	if strings.Index(authRealm, `"`) >= 0 {
		c.logger.Warn("ignoring auth-realm with quotes on %v", srcAuthRealm)
	} else if authRealm != "" {
		realm = authRealm
	}
	d.backend.Userlist.Realm = realm
}

func extractUserlist(source, secret, users string) ([]hatypes.User, []error) {
	var userlist []hatypes.User
	var err []error
	for i, usr := range strings.Split(users, "\n") {
		if usr == "" {
			continue
		}
		sep := strings.Index(usr, ":")
		if sep == -1 {
			err = append(err, fmt.Errorf("missing password of user '%s' line %d", usr, i+1))
			continue
		}
		username := usr[:sep]
		if username == "" {
			err = append(err, fmt.Errorf("missing username line %d", i+1))
			continue
		}
		if sep == len(usr)-1 || usr[sep:] == "::" {
			err = append(err, fmt.Errorf("missing password of user '%s' line %d", username, i+1))
			continue
		}
		var user hatypes.User
		if string(usr[sep+1]) == ":" {
			// usr::pwd
			user = hatypes.User{
				Name:      username,
				Passwd:    usr[sep+2:],
				Encrypted: false,
			}
		} else {
			// usr:pwd
			user = hatypes.User{
				Name:      username,
				Passwd:    usr[sep+1:],
				Encrypted: true,
			}
		}
		userlist = append(userlist, user)
	}
	return userlist, err
}

func (c *updater) buildBackendBlueGreen(d *backData) {
	balance, srcBalance, _ := d.mapper.GetStr(ingtypes.BackBlueGreenBalance)
	if balance == "" {
		balance, srcBalance, _ = d.mapper.GetStr(ingtypes.BackBlueGreenDeploy)
		if balance == "" {
			return
		}
	}
	type deployWeight struct {
		labelName  string
		labelValue string
		weight     int
		endpoints  []*hatypes.Endpoint
	}
	var deployWeights []*deployWeight
	for _, weight := range strings.Split(balance, ",") {
		dwSlice := strings.Split(weight, "=")
		if len(dwSlice) != 3 {
			c.logger.Error("blue/green config on %v has an invalid weight format: %s", srcBalance, weight)
			return
		}
		w, err := strconv.ParseInt(dwSlice[2], 10, 0)
		if err != nil {
			c.logger.Error("blue/green config on %v has an invalid weight value: %v", srcBalance, err)
			return
		}
		if w < 0 {
			c.logger.Warn("invalid weight '%d' on %v, using '0' instead", w, srcBalance)
			w = 0
		}
		if w > 256 {
			c.logger.Warn("invalid weight '%d' on %v, using '256' instead", w, srcBalance)
			w = 256
		}
		dw := &deployWeight{
			labelName:  dwSlice[0],
			labelValue: dwSlice[1],
			weight:     int(w),
		}
		deployWeights = append(deployWeights, dw)
	}
	for _, ep := range d.backend.Endpoints {
		if ep.Weight == 0 {
			// Draining endpoint, remove from blue/green calc
			continue
		}
		hasLabel := false
		if pod, err := c.cache.GetPod(ep.TargetRef); err == nil {
			for _, dw := range deployWeights {
				if label, found := pod.Labels[dw.labelName]; found {
					if label == dw.labelValue {
						// mode == pod and gcdGroupWeight == 0 need ep.Weight assgined,
						// otherwise ep.Weight will be rewritten after rebalance
						ep.Weight = dw.weight
						dw.endpoints = append(dw.endpoints, ep)
						hasLabel = true
					}
				}
			}
		} else {
			if ep.TargetRef == "" {
				err = fmt.Errorf("endpoint does not reference a pod")
			}
			c.logger.Warn("endpoint '%s:%d' on %v was removed from balance: %v", ep.IP, ep.Port, srcBalance, err)
		}
		if !hasLabel {
			// no label match, set weight as zero to remove new traffic
			// without remove from the balancer
			ep.Weight = 0
		}
	}
	for _, dw := range deployWeights {
		if len(dw.endpoints) == 0 {
			c.logger.InfoV(3, "blue/green balance label '%s=%s' on %v does not reference any endpoint", dw.labelName, dw.labelValue, srcBalance)
		}
	}
	if mode, srcMode, foundMode := d.mapper.GetStr(ingtypes.BackBlueGreenMode); mode == "pod" {
		// mode == pod, same weight as defined on balance annotation,
		// no need to rebalance
		return
	} else if foundMode && mode != "deploy" {
		c.logger.Warn("unsupported blue/green mode '%s' on %v, falling back to 'deploy'", mode, srcMode)
	}
	// mode == deploy, need to recalc based on the number of replicas
	lcmCount := 0
	for _, dw := range deployWeights {
		count := len(dw.endpoints)
		if count == 0 {
			continue
		}
		if lcmCount > 0 {
			lcmCount = ingutils.LCM(lcmCount, count)
		} else {
			lcmCount = count
		}
	}
	if lcmCount == 0 {
		// all counts are zero, this config won't be used
		return
	}
	gcdGroupWeight := 0
	maxWeight := 0
	for _, dw := range deployWeights {
		count := len(dw.endpoints)
		if count == 0 || dw.weight == 0 {
			continue
		}
		groupWeight := dw.weight * lcmCount / count
		if gcdGroupWeight > 0 {
			gcdGroupWeight = ingutils.GCD(gcdGroupWeight, groupWeight)
		} else {
			gcdGroupWeight = groupWeight
		}
		if groupWeight > maxWeight {
			maxWeight = groupWeight
		}
	}
	if gcdGroupWeight == 0 {
		// all weights are zero, no need to rebalance
		return
	}
	// HAProxy weight must be between 0..256.
	// weightFactor has how many times the max weight is greater than 256.
	weightFactor := float32(maxWeight) / float32(gcdGroupWeight) / float32(256)
	// LCM of denominators and GCD of the results are known. Updating ep.Weight
	for _, dw := range deployWeights {
		for _, ep := range dw.endpoints {
			weight := dw.weight * lcmCount / len(dw.endpoints) / gcdGroupWeight
			if weightFactor > 1 {
				propWeight := int(float32(weight) / weightFactor)
				if propWeight == 0 && dw.weight > 0 {
					propWeight = 1
				}
				ep.Weight = propWeight
			} else {
				ep.Weight = weight
			}
		}
	}
}

var (
	corsOriginRegex  = regexp.MustCompile(`^(https?://[A-Za-z0-9\-\.]*(:[0-9]+)?|\*)?$`)
	corsMethodsRegex = regexp.MustCompile(`^([A-Za-z]+,?\s?)+$`)
	corsHeadersRegex = regexp.MustCompile(`^([A-Za-z0-9\-\_]+,?\s?)+$`)
)

func (c *updater) buildBackendCors(d *backData) {
	if enable := d.mapper.GetBoolValue(ingtypes.BackCorsEnable); !enable {
		return
	}
	d.backend.Cors.Enabled = true
	allowOrigin, srcAllowOrigin, foundAllowOrigin := d.mapper.GetStr(ingtypes.BackCorsAllowOrigin)
	if foundAllowOrigin && corsOriginRegex.MatchString(allowOrigin) {
		d.backend.Cors.AllowOrigin = allowOrigin
	} else {
		if foundAllowOrigin {
			c.logger.Warn("invalid cors origin on %s, using '*' instead: %s", srcAllowOrigin, allowOrigin)
		}
		d.backend.Cors.AllowOrigin = "*"
	}
	allowHeaders, srcAllowHeaders, foundAllowHeaders := d.mapper.GetStr(ingtypes.BackCorsAllowHeaders)
	if corsHeadersRegex.MatchString(allowHeaders) {
		d.backend.Cors.AllowHeaders = allowHeaders
	} else {
		if foundAllowHeaders {
			c.logger.Warn("invalid cors headers on %s, using default config instead: %s", srcAllowHeaders, allowHeaders)
		}
		d.backend.Cors.AllowHeaders =
			"DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"
	}
	allowMethods, srcAllowMethods, foundAllowMethods := d.mapper.GetStr(ingtypes.BackCorsAllowMethods)
	if corsMethodsRegex.MatchString(allowMethods) {
		d.backend.Cors.AllowMethods = allowMethods
	} else {
		if foundAllowMethods {
			c.logger.Warn("invalid cors methods on %s, using default config instead: %s", srcAllowMethods, allowMethods)
		}
		d.backend.Cors.AllowMethods = "GET, PUT, POST, DELETE, PATCH, OPTIONS"
	}
	d.backend.Cors.AllowCredentials = d.mapper.GetBoolValue(ingtypes.BackCorsAllowCredentials)
	maxAge, srcMaxAge, foundMaxAge := d.mapper.GetInt(ingtypes.BackCorsMaxAge)
	if maxAge > 0 {
		d.backend.Cors.MaxAge = maxAge
	} else {
		if foundMaxAge {
			c.logger.Warn("invalid cors max age '%d' on %s, using '86400' instead", maxAge, srcMaxAge)
		}
		d.backend.Cors.MaxAge = 86400
	}
	exposeHeaders, srcExposeHeaders, foundExposeHeaders := d.mapper.GetStr(ingtypes.BackCorsExposeHeaders)
	if corsHeadersRegex.MatchString(exposeHeaders) {
		d.backend.Cors.ExposeHeaders = exposeHeaders
	} else if foundExposeHeaders {
		c.logger.Warn("ignoring invalid cors expose headers on %s: %s", srcExposeHeaders, exposeHeaders)
	}
}

func (c *updater) buildBackendHSTS(d *backData) {
	rawHSTSList := d.mapper.GetBackendConfig(d.backend,
		ingtypes.BackHSTS, ingtypes.BackHSTSMaxAge, ingtypes.BackHSTSPreload, ingtypes.BackHSTSIncludeSubdomains)
	for _, rawHSTS := range rawHSTSList {
		d.backend.HSTS = append(d.backend.HSTS, &hatypes.BackendConfigHSTS{
			Paths: rawHSTS.Paths,
			Config: hatypes.HSTS{
				Enabled:    d.mapper.GetBoolFromMap(d.backend, rawHSTS, ingtypes.BackHSTS),
				MaxAge:     d.mapper.GetIntFromMap(d.backend, rawHSTS, ingtypes.BackHSTSMaxAge),
				Subdomains: d.mapper.GetBoolFromMap(d.backend, rawHSTS, ingtypes.BackHSTSIncludeSubdomains),
				Preload:    d.mapper.GetBoolFromMap(d.backend, rawHSTS, ingtypes.BackHSTSPreload),
			},
		})
	}
}

var (
	oauthHeaderRegex = regexp.MustCompile(`^[A-Za-z0-9-]+:[A-Za-z0-9-_]+$`)
)

func (c *updater) buildBackendOAuth(d *backData) {
	oauth, srcOAuth, foundOAuth := d.mapper.GetStr(ingtypes.BackOAuth)
	if !foundOAuth || oauth == "" {
		return
	}
	if oauth != "oauth2_proxy" {
		c.logger.Warn("ignoring invalid oauth implementation '%s' on %v", oauth, srcOAuth)
		return
	}
	uriPrefix := "/oauth2"
	headers := []string{"X-Auth-Request-Email:auth_response_email"}
	if prefix, _, found := d.mapper.GetStr(ingtypes.BackOAuthURIPrefix); found {
		uriPrefix = prefix
	}
	h, srcHeaders, foundHeders := d.mapper.GetStr(ingtypes.BackOAuthHeaders)
	if foundHeders {
		headers = strings.Split(h, ",")
	}
	uriPrefix = strings.TrimRight(uriPrefix, "/")
	namespace := srcOAuth.Namespace
	backend := c.findBackend(namespace, uriPrefix)
	if backend == nil {
		c.logger.Error("path '%s' was not found on namespace '%s'", uriPrefix, namespace)
		return
	}
	headersMap := make(map[string]string, len(headers))
	for _, header := range headers {
		if len(header) == 0 {
			continue
		}
		if !oauthHeaderRegex.MatchString(header) {
			c.logger.Warn("invalid header format '%s' on %v", header, srcHeaders)
			continue
		}
		h := strings.Split(header, ":")
		headersMap[h[0]] = h[1]
	}
	d.backend.OAuth.Impl = oauth
	d.backend.OAuth.BackendName = backend.ID
	d.backend.OAuth.URIPrefix = uriPrefix
	d.backend.OAuth.Headers = headersMap
}

func (c *updater) findBackend(namespace, uriPrefix string) *hatypes.HostBackend {
	for _, host := range c.haproxy.Hosts() {
		for _, path := range host.Paths {
			if strings.TrimRight(path.Path, "/") == uriPrefix && path.Backend.Namespace == namespace {
				return &path.Backend
			}
		}
	}
	return nil
}

var (
	rewriteURLRegex = regexp.MustCompile(`^[^"' ]+$`)
)

func (c *updater) buildBackendRewriteURL(d *backData) {
	rewrite, srcRewrite, foundRewrite := d.mapper.GetStr(ingtypes.BackRewriteTarget)
	if !foundRewrite || rewrite == "" {
		return
	}
	if !rewriteURLRegex.MatchString(rewrite) {
		c.logger.Warn("rewrite-target does not allow white spaces or single/double quotes on %v: %s", srcRewrite, rewrite)
		return
	}
	d.backend.RewriteURL = rewrite
}

func (c *updater) buildBackendWAF(d *backData) {
	waf, srcWaf, foundWaf := d.mapper.GetStr(ingtypes.BackWAF)
	if !foundWaf {
		return
	}
	if waf != "modsecurity" {
		c.logger.Warn("ignoring invalid WAF mode on %s: %s", srcWaf, waf)
		return
	}
	d.backend.WAF = waf
}

func (c *updater) buildBackendWhitelistHTTP(d *backData) {
	if d.backend.ModeTCP {
		return
	}
	for _, wlist := range d.mapper.GetBackendConfigStr(d.backend, ingtypes.BackWhitelistSourceRange) {
		var cidrlist []string
		for _, cidr := range utils.Split(wlist.Config, ",") {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				c.logger.Warn("skipping invalid cidr '%s' in whitelist config on backend '%s/%s'",
					cidr, d.backend.Namespace, d.backend.Name)
			} else {
				cidrlist = append(cidrlist, cidr)
			}
		}
		d.backend.WhitelistHTTP = append(d.backend.WhitelistHTTP, &hatypes.BackendConfigWhitelist{
			Paths:  wlist.Paths,
			Config: cidrlist,
		})
	}
}

func (c *updater) buildBackendWhitelistTCP(d *backData) {
	if !d.backend.ModeTCP {
		return
	}
	wlist, srcWlist, foundWlist := d.mapper.GetStr(ingtypes.BackWhitelistSourceRange)
	if !foundWlist {
		return
	}
	var cidrlist []string
	for _, cidr := range utils.Split(wlist, ",") {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			c.logger.Warn("skipping invalid cidr '%s' in whitelist config on %v", cidr, srcWlist)
		} else {
			cidrlist = append(cidrlist, cidr)
		}
	}
	d.backend.WhitelistTCP = cidrlist
}
