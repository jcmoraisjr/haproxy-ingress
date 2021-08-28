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
	"regexp"
	"strconv"
	"strings"

	ingtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/types"
	ingutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/ingress/utils"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

func (c *updater) buildBackendAffinity(d *backData) {
	affinity := d.mapper.Get(ingtypes.BackAffinity)
	if affinity.Source == nil {
		return
	}
	if affinity.Value != "cookie" {
		c.logger.Error("unsupported affinity type on %v: %s", affinity.Source, affinity.Value)
		return
	}
	name := d.mapper.Get(ingtypes.BackSessionCookieName).Value
	if name == "" {
		name = "INGRESSCOOKIE"
	}
	strategy := d.mapper.Get(ingtypes.BackSessionCookieStrategy)
	var strategyName string
	switch strategy.Value {
	case "insert", "rewrite", "prefix":
		strategyName = strategy.Value
	default:
		if strategy.Source != nil {
			c.logger.Warn("invalid affinity cookie strategy '%s' on %v, using 'insert' instead", strategy.Value, strategy.Source)
		}
		strategyName = "insert"
	}
	d.backend.Cookie.Name = name
	d.backend.Cookie.Strategy = strategyName
	keywords := d.mapper.Get(ingtypes.BackSessionCookieKeywords)
	keywordsValue := keywords.Value
	if strategyName == "insert" && keywordsValue == "" {
		keywordsValue = "indirect nocache httponly"
	}
	if strings.Contains(keywordsValue, "preserve") {
		// just warn, no error, for keeping backwards compatibility where "preserve" may have been used in the "keywords" section
		c.logger.Warn("session-cookie-keywords on %s contains 'preserve'; consider using 'session-cookie-preserve' instead for better dynamic update cookie persistence", keywords.Source)
	}
	d.backend.Cookie.Keywords = keywordsValue
	d.backend.Cookie.Dynamic = d.mapper.Get(ingtypes.BackSessionCookieDynamic).Bool()
	d.backend.Cookie.Preserve = d.mapper.Get(ingtypes.BackSessionCookiePreserve).Bool()
	d.backend.Cookie.SameSite = d.mapper.Get(ingtypes.BackSessionCookieSameSite).Bool()
	d.backend.Cookie.Shared = d.mapper.Get(ingtypes.BackSessionCookieShared).Bool()

	cookieStrategy := d.mapper.Get(ingtypes.BackSessionCookieValue)
	switch cookieStrategy.Value {
	case "pod-uid":
		d.backend.EpCookieStrategy = hatypes.EpCookiePodUid
	case "server-name":
		d.backend.EpCookieStrategy = hatypes.EpCookieName
	default:
		c.logger.Warn("invalid session-cookie-value-strategy '%s' on %s, using 'server-name' instead", cookieStrategy.Value, cookieStrategy.Source)
		fallthrough
	case "":
		d.backend.EpCookieStrategy = hatypes.EpCookieName
	}
}

func (c *updater) buildBackendAuthHTTP(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		authType := config.Get(ingtypes.BackAuthType)
		if authType == nil || authType.Source == nil {
			continue
		}
		if authType.Value != "basic" {
			c.logger.Error("unsupported authentication type on %v: %s", authType.Source, authType.Value)
			continue
		}
		authSecret := config.Get(ingtypes.BackAuthSecret)
		if authSecret == nil || authSecret.Source == nil {
			c.logger.Error("missing secret name on basic authentication on %v", authType.Source)
			continue
		}
		secretName := authSecret.Value
		if strings.Index(secretName, "/") < 0 {
			secretName = authSecret.Source.Namespace + "/" + secretName
		}
		listName := strings.Replace(secretName, "/", "_", 1)
		userlist := c.haproxy.Userlists().Find(listName)
		if userlist == nil {
			userb, err := c.cache.GetSecretContent(
				authSecret.Source.Namespace,
				authSecret.Value, "auth",
				convtypes.TrackingTarget{
					Backend:  d.backend.BackendID(),
					Userlist: listName,
				},
			)
			if err != nil {
				c.logger.Error("error reading basic authentication on %v: %v", authSecret.Source, err)
				continue
			}
			userstr := string(userb)
			users, errs := extractUserlist(authSecret.Source.Name, secretName, userstr)
			for _, err := range errs {
				c.logger.Warn("ignoring malformed usr/passwd on secret '%s', declared on %v: %v", secretName, authSecret.Source, err)
			}
			userlist = c.haproxy.Userlists().Replace(listName, users)
			if len(users) == 0 {
				c.logger.Warn("userlist on %v for basic authentication is empty", authSecret.Source)
			}
		}
		// Add secret->backend tracking again to properly track the backend if a userlist was reused
		// Backends need always to be tracked because only hosts and backends tracking can properly start a partial update
		// Tracker will take care of deduplicate trackings
		// TODO build a stronger tracking
		c.tracker.TrackBackend(convtypes.SecretType, secretName, d.backend.BackendID())
		realm := "localhost" // HAProxy's backend name would be used if missing
		authRealm := config.Get(ingtypes.BackAuthRealm)
		if authRealm == nil || authRealm.Source == nil {
			// leave default
		} else if strings.Index(authRealm.Value, `"`) >= 0 {
			c.logger.Warn("ignoring auth-realm with quotes on %v", authRealm.Source)
		} else if authRealm.Value != "" {
			realm = authRealm.Value
		}
		path.AuthHTTP.UserlistName = userlist.Name
		path.AuthHTTP.Realm = realm
	}
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

func (c *updater) buildBackendBlueGreenBalance(d *backData) {
	balance := d.mapper.Get(ingtypes.BackBlueGreenBalance)
	if balance.Source == nil || balance.Value == "" {
		balance = d.mapper.Get(ingtypes.BackBlueGreenDeploy)
		if balance.Source == nil {
			return
		}
	}
	initialWeight := d.mapper.Get(ingtypes.BackInitialWeight).Int()
	type deployWeight struct {
		labelName  string
		labelValue string
		weight     int
		endpoints  []*hatypes.Endpoint
	}
	var deployWeights []*deployWeight
	for _, weight := range strings.Split(balance.Value, ",") {
		dwSlice := strings.Split(weight, "=")
		if len(dwSlice) != 3 {
			c.logger.Error("blue/green config on %v has an invalid weight format: %s", balance.Source, weight)
			return
		}
		w, err := strconv.ParseInt(dwSlice[2], 10, 0)
		if err != nil {
			c.logger.Error("blue/green config on %v has an invalid weight value: %v", balance.Source, err)
			return
		}
		if w < 0 {
			c.logger.Warn("invalid weight '%d' on %v, using '0' instead", w, balance.Source)
			w = 0
		}
		if w > 256 {
			c.logger.Warn("invalid weight '%d' on %v, using '256' instead", w, balance.Source)
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
			c.logger.Warn("endpoint '%s:%d' on %v was removed from balance: %v", ep.IP, ep.Port, balance.Source, err)
		}
		if !hasLabel {
			// no label match, set weight as zero to remove new traffic
			// without remove from the balancer
			ep.Weight = 0
		}
	}
	for _, dw := range deployWeights {
		if len(dw.endpoints) == 0 {
			c.logger.InfoV(3, "blue/green balance label '%s=%s' on %v does not reference any endpoint", dw.labelName, dw.labelValue, balance.Source)
		}
	}
	if mode := d.mapper.Get(ingtypes.BackBlueGreenMode); mode.Value == "pod" {
		// mode == pod, same weight as defined on balance annotation,
		// no need to rebalance
		return
	} else if mode.Source != nil && mode.Value != "deploy" {
		c.logger.Warn("unsupported blue/green mode '%s' on %s, falling back to 'deploy'", mode.Value, mode.Source)
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
	minWeight := -1
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
		if groupWeight < minWeight || minWeight < 0 {
			minWeight = groupWeight
		}
		if groupWeight > maxWeight {
			maxWeight = groupWeight
		}
	}
	if gcdGroupWeight == 0 {
		// all weights are zero, no need to rebalance
		return
	}
	// Agent works better if weight is `initial-weight` or
	// at least the higher value weightFactor will let it to be
	// weightFactorMin has how many times minWeight is lesser than `initial-weight`.
	weightFactorMin := float32(initialWeight*gcdGroupWeight) / float32(minWeight)
	// HAProxy weight must be between 0..256.
	// weightFactor has how many times the max weight will be greater than 256.
	weightFactor := weightFactorMin * float32(maxWeight) / float32(256*gcdGroupWeight)
	// LCM of denominators and GCD of the results are known. Updating ep.Weight
	for _, dw := range deployWeights {
		for _, ep := range dw.endpoints {
			weight := weightFactorMin * float32(dw.weight*lcmCount) / float32(len(dw.endpoints)*gcdGroupWeight)
			if weightFactor > 1 {
				propWeight := int(weight / weightFactor)
				if propWeight == 0 && dw.weight > 0 {
					propWeight = 1
				}
				ep.Weight = propWeight
			} else {
				ep.Weight = int(weight)
			}
		}
	}
}

const validLabelRegexStr = "([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]"
const bluegreenSeparator = ":"

var validNamePairRegex = regexp.MustCompile(`^` + validLabelRegexStr + bluegreenSeparator + validLabelRegexStr + `$`)

func (c *updater) buildBackendBlueGreenSelector(d *backData) {
	cookie := d.mapper.Get(ingtypes.BackBlueGreenCookie)
	header := d.mapper.Get(ingtypes.BackBlueGreenHeader)
	if cookie.Value == "" && header.Value == "" {
		return
	}
	if cookie.Value != "" && !validNamePairRegex.MatchString(cookie.Value) {
		c.logger.Error("invalid CookieName:LabelName pair on %s: %s", cookie.Source, cookie.Value)
		return
	}
	if header.Value != "" && !validNamePairRegex.MatchString(header.Value) {
		c.logger.Error("invalid HeaderName:LabelName pair on %s: %s", header.Source, header.Value)
		return
	}
	vcookie := strings.Split(cookie.Value, bluegreenSeparator)
	vheader := strings.Split(header.Value, bluegreenSeparator)
	var labelName string
	if cookie.Value != "" {
		d.backend.BlueGreen.CookieName = vcookie[0]
		labelName = vcookie[1]
	}
	if header.Value != "" {
		if labelName != "" && labelName != vheader[1] {
			c.logger.Error(
				"CookieName:LabelName and HeaderName:LabelName pairs, used in the same backend on %s and %s, should have the same label name",
				cookie.Source, header.Source,
			)
			d.backend.BlueGreen.CookieName = ""
			return
		}
		d.backend.BlueGreen.HeaderName = vheader[0]
		labelName = vheader[1]
	}
	for _, ep := range d.backend.Endpoints {
		if !ep.Enabled {
			continue
		}
		if pod, err := c.cache.GetPod(ep.TargetRef); err == nil {
			if labelValue, found := pod.Labels[labelName]; found {
				ep.Label = labelValue
			}
		} else {
			if ep.TargetRef == "" {
				err = fmt.Errorf("endpoint does not reference a pod")
			}
			c.logger.Warn("endpoint '%s:%d' on backend '%s' was removed from blue/green label: %v", ep.IP, ep.Port, d.backend.ID, err)
		}
	}
}

func (c *updater) buildBackendBodySize(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		bodysize := config.Get(ingtypes.BackProxyBodySize)
		if bodysize == nil || bodysize.Value == "" || bodysize.Value == "unlimited" {
			continue
		}
		value, err := utils.SizeSuffixToInt64(bodysize.Value)
		if err != nil {
			c.logger.Warn("ignoring invalid body size on %v: %s", bodysize.Source, bodysize.Value)
			continue
		}
		path.MaxBodySize = value
	}
}

func (c *updater) buildBackendCors(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		enabled := config.Get(ingtypes.BackCorsEnable).Bool()
		if enabled {
			path.Cors = hatypes.Cors{
				Enabled:          enabled,
				AllowCredentials: config.Get(ingtypes.BackCorsAllowCredentials).Bool(),
				AllowHeaders:     config.Get(ingtypes.BackCorsAllowHeaders).Value,
				AllowMethods:     config.Get(ingtypes.BackCorsAllowMethods).Value,
				AllowOrigin:      config.Get(ingtypes.BackCorsAllowOrigin).Value,
				ExposeHeaders:    config.Get(ingtypes.BackCorsExposeHeaders).Value,
				MaxAge:           config.Get(ingtypes.BackCorsMaxAge).Int(),
			}
		}
	}
}

func (c *updater) buildBackendCustomConfig(d *backData) {
	config := d.mapper.Get(ingtypes.BackConfigBackend)
	if config.Source == nil {
		return
	}
	lines := utils.LineToSlice(config.Value)
	if len(lines) == 0 {
		return
	}
	for _, keyword := range c.options.DisableKeywords {
		if keyword == "*" {
			c.logger.Warn("skipping configuration snippet on %s: custom configuration is disabled", config.Source)
			return
		}
		for _, line := range lines {
			if firstToken(line) == keyword {
				c.logger.Warn("skipping configuration snippet on %s: keyword '%s' not allowed", config.Source, keyword)
				return
			}
		}
	}
	d.backend.CustomConfig = lines
}

// kindly provided by strings/strings.go
var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func firstToken(s string) string {
	// only ascii spaces supported, code<128
	start := 0
	for ; len(s) > start; start++ {
		if asciiSpace[s[start]] == 0 {
			break
		}
	}
	end := start
	for ; len(s) > end; end++ {
		if asciiSpace[s[end]] == 1 {
			break
		}
	}
	return s[start:end]
}

func (c *updater) buildBackendDNS(d *backData) {
	resolverName := d.mapper.Get(ingtypes.BackUseResolver).Value
	if resolverName == "" {
		return
	}
	exists := func() bool {
		for _, resolver := range c.haproxy.Global().DNS.Resolvers {
			if resolver.Name == resolverName {
				return true
			}
		}
		return false
	}()
	if !exists {
		c.logger.Warn("skipping undeclared DNS resolver: %s", resolverName)
		return
	}
	d.backend.Resolver = resolverName
}

func (c *updater) buildBackendDynamic(d *backData) {
	d.backend.Dynamic = hatypes.DynBackendConfig{
		DynUpdate:    d.mapper.Get(ingtypes.BackDynamicScaling).Bool(),
		BlockSize:    d.mapper.Get(ingtypes.BackBackendServerSlotsInc).Int(),
		MinFreeSlots: d.mapper.Get(ingtypes.BackSlotsMinFree).Int(),
	}
}

func (c *updater) buildBackendAgentCheck(d *backData) {
	d.backend.AgentCheck.Addr = d.mapper.Get(ingtypes.BackAgentCheckAddr).Value
	d.backend.AgentCheck.Interval = c.validateTime(d.mapper.Get(ingtypes.BackAgentCheckInterval))
	d.backend.AgentCheck.Port = d.mapper.Get(ingtypes.BackAgentCheckPort).Int()
	d.backend.AgentCheck.Send = d.mapper.Get(ingtypes.BackAgentCheckSend).Value
}

func (c *updater) buildBackendHealthCheck(d *backData) {
	d.backend.HealthCheck.Addr = d.mapper.Get(ingtypes.BackHealthCheckAddr).Value
	d.backend.HealthCheck.FallCount = d.mapper.Get(ingtypes.BackHealthCheckFallCount).Int()
	interval := d.mapper.Get(ingtypes.BackHealthCheckInterval)
	if interval.Value == "" {
		interval = d.mapper.Get(ingtypes.BackBackendCheckInterval)
	}
	d.backend.HealthCheck.Interval = c.validateTime(interval)
	d.backend.HealthCheck.Port = d.mapper.Get(ingtypes.BackHealthCheckPort).Int()
	d.backend.HealthCheck.RiseCount = d.mapper.Get(ingtypes.BackHealthCheckRiseCount).Int()
	d.backend.HealthCheck.URI = d.mapper.Get(ingtypes.BackHealthCheckURI).Value
}

func (c *updater) buildBackendHeaders(d *backData) {
	headers := d.mapper.Get(ingtypes.BackHeaders)
	if headers.Value == "" {
		return
	}
	for _, header := range utils.LineToSlice(headers.Value) {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		idx := strings.IndexAny(header, ": ")
		if idx <= 0 {
			c.logger.Warn("ignored missing header name or value on %v: %s", headers.Source, header)
			continue
		}
		name := strings.TrimRight(header[:idx], ":")
		value := strings.TrimSpace(header[idx+1:])
		// TODO this should use a structured type and a smart match/replace if growing a bit more
		value = strings.ReplaceAll(value, "%[service]", d.backend.Name)
		value = strings.ReplaceAll(value, "%[namespace]", d.backend.Namespace)
		d.backend.Headers = append(d.backend.Headers, &hatypes.BackendHeader{
			Name:  name,
			Value: value,
		})
	}
}

func (c *updater) buildBackendHSTS(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		path.HSTS.Enabled = config.Get(ingtypes.BackHSTS).Bool()
		path.HSTS.MaxAge = config.Get(ingtypes.BackHSTSMaxAge).Int()
		path.HSTS.Subdomains = config.Get(ingtypes.BackHSTSIncludeSubdomains).Bool()
		path.HSTS.Preload = config.Get(ingtypes.BackHSTSPreload).Bool()
	}
}

func (c *updater) buildBackendLimit(d *backData) {
	d.backend.Limit.RPS = d.mapper.Get(ingtypes.BackLimitRPS).Int()
	d.backend.Limit.Connections = d.mapper.Get(ingtypes.BackLimitConnections).Int()
	d.backend.Limit.Whitelist = c.splitCIDR(d.mapper.Get(ingtypes.BackLimitWhitelist))
}

var (
	oauthHeaderRegex = regexp.MustCompile(`^[A-Za-z0-9-]+:[A-Za-z0-9-_]+$`)
)

func (c *updater) buildBackendOAuth(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		oauth := config.Get(ingtypes.BackOAuth)
		if oauth.Source == nil {
			continue
		}
		// starting here the oauth backend should be configured or requests should be denied
		// AlwaysDeny will be changed to false if the configuration succeed
		path.OAuth.AlwaysDeny = true
		if oauth.Value != "oauth2_proxy" {
			c.logger.Warn("ignoring invalid oauth implementation '%s' on %v", oauth, oauth.Source)
			continue
		}
		external := c.haproxy.Global().External
		if external.IsExternal() && !external.HasLua {
			c.logger.Warn("oauth2_proxy on %v needs Lua socket, install Lua libraries and enable 'external-has-lua' global config", oauth.Source)
			continue
		}
		uriPrefix := "/oauth2"
		headers := []string{"X-Auth-Request-Email:auth_response_email"}
		if prefix := config.Get(ingtypes.BackOAuthURIPrefix); prefix.Source != nil {
			uriPrefix = prefix.Value
		}
		h := config.Get(ingtypes.BackOAuthHeaders)
		if h.Source != nil {
			headers = strings.Split(h.Value, ",")
		}
		uriPrefix = strings.TrimRight(uriPrefix, "/")
		namespace := oauth.Source.Namespace
		backend := c.findBackend(namespace, uriPrefix)
		if backend == nil {
			c.logger.Error("path '%s' was not found on namespace '%s'", uriPrefix, namespace)
			continue
		}
		headersMap := make(map[string]string, len(headers))
		for _, header := range headers {
			if len(header) == 0 {
				continue
			}
			if !oauthHeaderRegex.MatchString(header) {
				c.logger.Warn("invalid header format '%s' on %v", header, h.Source)
				continue
			}
			h := strings.Split(header, ":")
			headersMap[h[0]] = h[1]
		}
		path.OAuth.AlwaysDeny = false
		path.OAuth.Impl = oauth.Value
		path.OAuth.BackendName = backend.ID
		path.OAuth.URIPrefix = uriPrefix
		path.OAuth.Headers = headersMap
	}
}

func (c *updater) findBackend(namespace, uriPrefix string) *hatypes.HostBackend {
	for _, host := range c.haproxy.Hosts().Items() {
		for _, path := range host.Paths {
			if strings.TrimRight(path.Path, "/") == uriPrefix && path.Backend.Namespace == namespace {
				return &path.Backend
			}
		}
	}
	return nil
}

var validDomainRegex = regexp.MustCompile(`^([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6}$`)

func (c *updater) buildBackendProtocol(d *backData) {
	proto := d.mapper.Get(ingtypes.BackBackendProtocol)
	var protocol string
	var secure bool
	switch strings.ToLower(proto.Value) {
	case "", "h1", "http":
		protocol = "h1"
		secure = false
	case "h1-ssl", "https":
		protocol = "h1"
		secure = true
	case "h2", "grpc":
		protocol = "h2"
		secure = false
	case "h2-ssl", "grpcs":
		protocol = "h2"
		secure = true
	default:
		c.logger.Warn("ignoring invalid backend protocol on %v: %s", proto.Source, proto.Value)
		return
	}
	if protocol == "h2" && !c.haproxy.Global().UseHTX {
		c.logger.Warn("ignoring h2 protocol on %v due to HTX disabled, changing to h1", proto.Source)
		protocol = "h1"
	}
	if !secure {
		secure = d.mapper.Get(ingtypes.BackSecureBackends).Bool()
	}
	d.backend.Server.Protocol = protocol
	d.backend.Server.Secure = secure
	if !secure {
		return
	}
	if crt := d.mapper.Get(ingtypes.BackSecureCrtSecret); crt.Value != "" {
		if crtFile, err := c.cache.GetTLSSecretPath(
			crt.Source.Namespace,
			crt.Value,
			convtypes.TrackingTarget{Backend: d.backend.BackendID()},
		); err == nil {
			d.backend.Server.CrtFilename = crtFile.Filename
			d.backend.Server.CrtHash = crtFile.SHA1Hash
		} else {
			c.logger.Warn("skipping client certificate on %v: %v", crt.Source, err)
		}
	}
	if sni := d.mapper.Get(ingtypes.BackSecureSNI); sni.Value != "" {
		switch sni.Value {
		case "sni":
			d.backend.Server.SNI = "ssl_fc_sni"
		case "host":
			d.backend.Server.SNI = "var(req.host)"
		default:
			if validDomainRegex.MatchString(sni.Value) {
				d.backend.Server.SNI = fmt.Sprintf("str(%s)", sni.Value)
			} else {
				c.logger.Warn("skipping invalid domain (SNI) on %v: %s", sni.Source, sni.Value)
			}
		}
	}
	if host := d.mapper.Get(ingtypes.BackSecureVerifyHostname); host.Value != "" {
		if validDomainRegex.MatchString(host.Value) {
			d.backend.Server.VerifyHost = host.Value
		} else {
			c.logger.Warn("skipping invalid domain (verify-hostname) on %v: %s", host.Source, host.Value)
		}
	}
	if ca := d.mapper.Get(ingtypes.BackSecureVerifyCASecret); ca.Value != "" {
		if caFile, crlFile, err := c.cache.GetCASecretPath(
			ca.Source.Namespace,
			ca.Value,
			convtypes.TrackingTarget{Backend: d.backend.BackendID()},
		); err == nil {
			d.backend.Server.CAFilename = caFile.Filename
			d.backend.Server.CAHash = caFile.SHA1Hash
			d.backend.Server.CRLFilename = crlFile.Filename
			d.backend.Server.CRLHash = crlFile.SHA1Hash
		} else {
			c.logger.Warn("skipping CA on %v: %v", ca.Source, err)
		}
	}
}

func (c *updater) buildBackendProxyProtocol(d *backData) {
	cfg := d.mapper.Get(ingtypes.BackProxyProtocol)
	if cfg.Source == nil {
		return
	}
	switch cfg.Value {
	case "v1":
		d.backend.Server.SendProxy = "send-proxy"
	case "v2":
		d.backend.Server.SendProxy = "send-proxy-v2"
	case "v2-ssl":
		d.backend.Server.SendProxy = "send-proxy-v2-ssl"
	case "v2-ssl-cn":
		d.backend.Server.SendProxy = "send-proxy-v2-ssl-cn"
	default:
		c.logger.Warn("ignoring invalid proxy protocol version on %v: %s", cfg.Source, cfg.Value)
	}
}

var (
	rewriteURLRegex = regexp.MustCompile(`^[^"' ]*$`)
)

func (c *updater) buildBackendRewriteURL(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		rewrite := config.Get(ingtypes.BackRewriteTarget)
		if rewrite == nil || rewrite.Value == "" {
			continue
		}
		if !rewriteURLRegex.MatchString(rewrite.Value) {
			c.logger.Warn(
				"rewrite-target does not allow white spaces or single/double quotes on %v: '%s'",
				rewrite.Source, rewrite.Value)
			continue
		}
		path.RewriteURL = rewrite.Value
	}
}

var epNamingRegex = regexp.MustCompile(`^(seq(uence)?|pod|ip)$`)

func (c *updater) buildBackendServerNaming(d *backData) {
	// Only warning here. d.backend.EpNaming should be updated before backend.AcquireEndpoint()
	naming := d.mapper.Get(ingtypes.BackBackendServerNaming)
	if !epNamingRegex.MatchString(naming.Value) {
		c.logger.Warn("ignoring invalid naming type '%s' on %s, using 'seq' instead", naming.Value, naming.Source)
	}
}

func (c *updater) buildBackendSSL(d *backData) {
	d.backend.TLS.AddCertHeader = d.mapper.Get(ingtypes.BackAuthTLSCertHeader).Bool()
	d.backend.TLS.FingerprintLower = d.mapper.Get(ingtypes.BackSSLFingerprintLower).Bool()
	if cfg := d.mapper.Get(ingtypes.BackSSLCiphersBackend); cfg.Source != nil {
		d.backend.Server.Ciphers = cfg.Value
	}
	if cfg := d.mapper.Get(ingtypes.BackSSLCipherSuitesBackend); cfg.Source != nil {
		d.backend.Server.CipherSuites = cfg.Value
	}
	d.backend.Server.Options = d.mapper.Get(ingtypes.BackSSLOptionsBackend).Value
}

func (c *updater) buildBackendSSLRedirect(d *backData) {
	noTLSRedir := utils.Split(d.mapper.Get(ingtypes.GlobalNoTLSRedirectLocations).Value, ",")
	for _, path := range d.backend.Paths {
		redir := path.Host != nil && path.Host.HasTLS() &&
			d.mapper.GetConfig(path.Link).Get(ingtypes.BackSSLRedirect).Bool()
		if redir {
			for _, noredir := range noTLSRedir {
				if strings.HasPrefix(path.Path(), noredir) {
					redir = false
				}
			}
		}
		path.SSLRedirect = redir
	}
}

func (c *updater) buildBackendTimeout(d *backData) {
	if cfg := d.mapper.Get(ingtypes.BackTimeoutConnect); cfg.Source != nil {
		d.backend.Timeout.Connect = c.validateTime(cfg)
	}
	if cfg := d.mapper.Get(ingtypes.BackTimeoutHTTPRequest); cfg.Source != nil {
		d.backend.Timeout.HTTPRequest = c.validateTime(cfg)
	}
	if cfg := d.mapper.Get(ingtypes.BackTimeoutKeepAlive); cfg.Source != nil {
		d.backend.Timeout.KeepAlive = c.validateTime(cfg)
	}
	if cfg := d.mapper.Get(ingtypes.BackTimeoutQueue); cfg.Source != nil {
		d.backend.Timeout.Queue = c.validateTime(cfg)
	}
	if cfg := d.mapper.Get(ingtypes.BackTimeoutServer); cfg.Source != nil {
		d.backend.Timeout.Server = c.validateTime(cfg)
	}
	if cfg := d.mapper.Get(ingtypes.BackTimeoutServerFin); cfg.Source != nil {
		d.backend.Timeout.ServerFin = c.validateTime(cfg)
	}
	if cfg := d.mapper.Get(ingtypes.BackTimeoutTunnel); cfg.Source != nil {
		d.backend.Timeout.Tunnel = c.validateTime(cfg)
	}
}

func (c *updater) buildBackendWAF(d *backData) {
	for _, path := range d.backend.Paths {
		config := d.mapper.GetConfig(path.Link)
		waf := config.Get(ingtypes.BackWAF)
		module := waf.Value
		if module == "" {
			continue
		}
		if module != "modsecurity" {
			c.logger.Warn("ignoring invalid WAF module on %s: %s", waf.Source, module)
			continue
		}
		wafMode := config.Get(ingtypes.BackWAFMode)
		mode := wafMode.Value
		if mode != "" && mode != "deny" && mode != "detect" {
			c.logger.Warn("ignoring invalid WAF mode '%s' on %s, using 'deny' instead", mode, wafMode.Source)
			mode = "deny"
		}
		path.WAF.Module = module
		path.WAF.Mode = mode
	}
}

func (c *updater) buildBackendWhitelistHTTP(d *backData) {
	if !d.backend.ModeTCP {
		for _, path := range d.backend.Paths {
			config := d.mapper.GetConfig(path.Link)
			path.AllowedIPHTTP, path.DeniedIPHTTP = c.readAccessConfig(config)
		}
	}
}

func (c *updater) buildBackendWhitelistTCP(d *backData) {
	if !d.backend.ModeTCP {
		return
	}
	d.backend.AllowedIPTCP, d.backend.DeniedIPTCP = c.readAccessConfig(d.mapper)
}

type configValueGetter interface {
	Get(key string) *ConfigValue
}

func (c *updater) readAccessConfig(config configValueGetter) (allowed, denied hatypes.AccessConfig) {
	allowcfg := config.Get(ingtypes.BackAllowlistSourceRange)
	denycfg := config.Get(ingtypes.BackDenylistSourceRange)
	whitecfg := config.Get(ingtypes.BackWhitelistSourceRange)
	if allowcfg.Value == "" {
		allowcfg = whitecfg
	} else if whitecfg.Value != "" {
		c.logger.Warn("both allowlist and whitelist were used on %s, ignoring whitelist content: %s",
			whitecfg.Source, whitecfg.Value)
	}
	allowed.Rule, allowed.Exception = c.splitDualCIDR(allowcfg)
	denied.Rule, denied.Exception = c.splitDualCIDR(denycfg)
	return allowed, denied
}
