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

package haproxy

import (
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	hautils "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// InstanceOptions ...
type InstanceOptions struct {
	AcmeSigner        acme.Signer
	AcmeQueue         utils.Queue
	LeaderElector     types.LeaderElector
	MaxOldConfigFiles int
	HAProxyCmd        string
	HAProxyConfigFile string
	Metrics           types.Metrics
	ReloadCmd         string
	ReloadStrategy    string
	ValidateConfig    bool
}

// Instance ...
type Instance interface {
	AcmeCheck(source string) (int, error)
	ParseTemplates() error
	Config() Config
	CalcIdleMetric()
	Update(timer *utils.Timer)
}

// CreateInstance ...
func CreateInstance(logger types.Logger, options InstanceOptions) Instance {
	return &instance{
		logger:       logger,
		options:      &options,
		templates:    template.CreateConfig(),
		mapsTemplate: template.CreateConfig(),
		mapsDir:      "/etc/haproxy/maps",
		metrics:      options.Metrics,
	}
}

type instance struct {
	logger       types.Logger
	options      *InstanceOptions
	templates    *template.Config
	mapsTemplate *template.Config
	mapsDir      string
	oldConfig    Config
	curConfig    Config
	metrics      types.Metrics
}

func (i *instance) AcmeCheck(source string) (int, error) {
	var count int
	if i.oldConfig == nil {
		return count, fmt.Errorf("controller wasn't started yet")
	}
	if i.options.AcmeQueue == nil {
		return count, fmt.Errorf("Acme queue wasn't configured")
	}
	hasAccount := i.acmeEnsureConfig(i.oldConfig.AcmeData())
	if !hasAccount {
		return count, fmt.Errorf("Cannot create or retrieve the acme client account")
	}
	le := i.options.LeaderElector
	if !le.IsLeader() {
		msg := fmt.Sprintf("skipping acme periodic check, leader is %s", le.LeaderName())
		i.logger.Info(msg)
		return count, fmt.Errorf(msg)
	}
	i.logger.Info("starting certificate check (%s)", source)
	for storage, domains := range i.oldConfig.AcmeData().Certs {
		i.acmeAddCert(storage, domains)
		count++
	}
	if count == 0 {
		i.logger.Info("certificate list is empty")
	} else {
		i.logger.Info("finish adding %d certificate(s) to the work queue", count)
	}
	return count, nil
}

func (i *instance) acmeEnsureConfig(acmeConfig *hatypes.AcmeData) bool {
	signer := i.options.AcmeSigner
	signer.AcmeConfig(acmeConfig.Expiring)
	signer.AcmeAccount(acmeConfig.Endpoint, acmeConfig.Emails, acmeConfig.TermsAgreed)
	return signer.HasAccount()
}

func (i *instance) acmeBuildCert(storage string, domains map[string]struct{}) string {
	cert := make([]string, len(domains))
	n := 0
	for dom := range domains {
		cert[n] = dom
		n++
	}
	sort.Slice(cert, func(i, j int) bool {
		return cert[i] < cert[j]
	})
	return strings.Join(cert, ",")
}

func (i *instance) acmeAddCert(storage string, domains map[string]struct{}) {
	strcert := i.acmeBuildCert(storage, domains)
	i.logger.InfoV(3, "enqueue certificate for processing: storage=%s domain(s)=%s",
		storage, strcert)
	i.options.AcmeQueue.Add(storage + "," + strcert)
}

func (i *instance) acmeRemoveCert(storage string, domains map[string]struct{}) {
	strcert := i.acmeBuildCert(storage, domains)
	i.options.AcmeQueue.Remove(storage + "," + strcert)
}

func (i *instance) ParseTemplates() error {
	i.templates.ClearTemplates()
	i.mapsTemplate.ClearTemplates()
	if err := i.templates.NewTemplate(
		"spoe-modsecurity.tmpl",
		"/etc/haproxy/modsecurity/spoe-modsecurity.tmpl",
		"/etc/haproxy/spoe-modsecurity.conf",
		0,
		1024,
	); err != nil {
		return err
	}
	if err := i.templates.NewTemplate(
		"haproxy.tmpl",
		"/etc/haproxy/template/haproxy.tmpl",
		"/etc/haproxy/haproxy.cfg",
		i.options.MaxOldConfigFiles,
		16384,
	); err != nil {
		return err
	}
	err := i.mapsTemplate.NewTemplate(
		"map.tmpl",
		"/etc/haproxy/maptemplate/map.tmpl",
		"",
		0,
		2048,
	)
	return err
}

func (i *instance) Config() Config {
	if i.curConfig == nil {
		config := createConfig(options{
			mapsTemplate: i.mapsTemplate,
			mapsDir:      i.mapsDir,
		})
		i.curConfig = config
	}
	return i.curConfig
}

var idleRegex = regexp.MustCompile(`Idle_pct: ([0-9]+)`)

func (i *instance) CalcIdleMetric() {
	if i.oldConfig == nil {
		return
	}
	msg, err := hautils.HAProxyCommand(i.oldConfig.Global().AdminSocket, i.metrics.HAProxyShowInfoResponseTime, "show info")
	if err != nil {
		i.logger.Error("error reading admin socket: %v", err)
		return
	}
	idleStr := idleRegex.FindStringSubmatch(msg[0])
	if len(idleStr) < 2 {
		i.logger.Error("cannot find Idle_pct field in the show info socket command")
		return
	}
	idle, err := strconv.Atoi(idleStr[1])
	if err != nil {
		i.logger.Error("Idle_pct has an invalid integer: %s", idleStr[1])
	}
	i.metrics.AddIdleFactor(idle)
}

func (i *instance) Update(timer *utils.Timer) {
	i.acmeUpdate()
	i.haproxyUpdate(timer)
}

func (i *instance) acmeUpdate() {
	if i.oldConfig == nil || i.curConfig == nil || i.options.AcmeQueue == nil {
		return
	}
	le := i.options.LeaderElector
	if le.IsLeader() {
		hasAccount := i.acmeEnsureConfig(i.curConfig.AcmeData())
		if !hasAccount {
			return
		}
	}
	var updated bool
	oldCerts := i.oldConfig.AcmeData().Certs
	curCerts := i.curConfig.AcmeData().Certs
	// Remove from the retry queue certs that was removed from the config
	for storage, domains := range oldCerts {
		curdomains, found := curCerts[storage]
		if !found || !reflect.DeepEqual(domains, curdomains) {
			if le.IsLeader() {
				i.acmeRemoveCert(storage, domains)
			}
			updated = true
		}
	}
	// Add new certs to the work queue
	for storage, domains := range curCerts {
		olddomains, found := oldCerts[storage]
		if !found || !reflect.DeepEqual(domains, olddomains) {
			if le.IsLeader() {
				i.acmeAddCert(storage, domains)
			}
			updated = true
		}
	}
	if updated && !le.IsLeader() {
		i.logger.InfoV(2, "skipping acme update check, leader is %s", le.LeaderName())
	}
}

func (i *instance) haproxyUpdate(timer *utils.Timer) {
	// nil config, just ignore
	if i.curConfig == nil {
		i.logger.Info("new configuration is empty")
		return
	}
	//
	// this should be taken into account when refactoring this func:
	//   - dynUpdater might change config state, so it should be called before templates.Write()
	//   - i.metrics.IncUpdate<Status>() should be called always, but only once
	//   - i.metrics.UpdateSuccessful(<bool>) should be called only if haproxy is reloaded or cfg is validated
	//
	defer i.rotateConfig()
	i.curConfig.SyncConfig()
	if err := i.curConfig.BuildFrontendGroup(); err != nil {
		i.logger.Error("error building configuration group: %v", err)
		i.metrics.IncUpdateNoop()
		return
	}
	if err := i.curConfig.BuildBackendMaps(); err != nil {
		i.logger.Error("error building backend maps: %v", err)
		i.metrics.IncUpdateNoop()
		return
	}
	if i.curConfig.Equals(i.oldConfig) {
		i.logger.InfoV(2, "old and new configurations match, skipping reload")
		i.metrics.IncUpdateNoop()
		return
	}
	updater := i.newDynUpdater()
	updated := updater.update()
	if !updated || updater.cmdCnt > 0 {
		// only need to rewrtite config files if:
		//   - !updated           - there are changes that cannot be dynamically applied
		//   - updater.cmdCnt > 0 - there are changes that was dynamically applied
		err := i.templates.Write(i.curConfig)
		timer.Tick("write_tmpl")
		if err != nil {
			i.logger.Error("error writing configuration: %v", err)
			i.metrics.IncUpdateNoop()
			return
		}
	}
	if updated {
		if updater.cmdCnt > 0 {
			if i.options.ValidateConfig {
				var err error
				if err = i.check(); err != nil {
					i.logger.Error("error validating config file:\n%v", err)
				}
				timer.Tick("validate_cfg")
				i.metrics.UpdateSuccessful(err == nil)
			}
			i.logger.Info("HAProxy updated without needing to reload. Commands sent: %d", updater.cmdCnt)
			i.metrics.IncUpdateDynamic()
		} else {
			i.logger.Info("old and new configurations match")
			i.metrics.IncUpdateNoop()
		}
		return
	}
	i.updateCertExpiring()
	i.metrics.IncUpdateFull()
	if err := i.reload(); err != nil {
		i.logger.Error("error reloading server:\n%v", err)
		i.metrics.UpdateSuccessful(false)
		return
	}
	timer.Tick("reload_haproxy")
	i.metrics.UpdateSuccessful(true)
	i.logger.Info("HAProxy successfully reloaded")
}

func (i *instance) updateCertExpiring() {
	// TODO move to dynupdate when dynamic crt update is implemented
	if i.oldConfig == nil {
		for _, curHost := range i.curConfig.Hosts().Items {
			if curHost.TLS.HasTLS() {
				i.metrics.SetCertExpireDate(curHost.Hostname, curHost.TLS.TLSCommonName, &curHost.TLS.TLSNotAfter)
			}
		}
		return
	}
	for _, oldHost := range i.oldConfig.Hosts().Items {
		if !oldHost.TLS.HasTLS() {
			continue
		}
		curHost := i.curConfig.Hosts().FindHost(oldHost.Hostname)
		if curHost == nil || oldHost.TLS.TLSCommonName != curHost.TLS.TLSCommonName {
			i.metrics.SetCertExpireDate(oldHost.Hostname, oldHost.TLS.TLSCommonName, nil)
		}
	}
	for _, curHost := range i.curConfig.Hosts().Items {
		if !curHost.TLS.HasTLS() {
			continue
		}
		oldHost := i.oldConfig.Hosts().FindHost(curHost.Hostname)
		if oldHost == nil || oldHost.TLS.TLSCommonName != curHost.TLS.TLSCommonName || oldHost.TLS.TLSNotAfter != curHost.TLS.TLSNotAfter {
			i.metrics.SetCertExpireDate(curHost.Hostname, curHost.TLS.TLSCommonName, &curHost.TLS.TLSNotAfter)
		}
	}
}

func (i *instance) check() error {
	if i.options.HAProxyCmd == "" {
		i.logger.Info("(test) check was skipped")
		return nil
	}
	out, err := exec.Command(i.options.HAProxyCmd, "-c", "-f", i.options.HAProxyConfigFile).CombinedOutput()
	outstr := string(out)
	if err != nil {
		return fmt.Errorf(outstr)
	}
	return nil
}

func (i *instance) reload() error {
	if i.options.ReloadCmd == "" {
		i.logger.Info("(test) reload was skipped")
		return nil
	}
	out, err := exec.Command(i.options.ReloadCmd, i.options.ReloadStrategy, i.options.HAProxyConfigFile).CombinedOutput()
	outstr := string(out)
	if len(outstr) > 0 {
		i.logger.Warn("output from haproxy:\n%v", outstr)
	}
	if err != nil {
		return err
	}
	return nil
}

func (i *instance) rotateConfig() {
	// TODO releaseConfig (old support files, ...)
	i.oldConfig = i.curConfig
	i.curConfig = nil
}
