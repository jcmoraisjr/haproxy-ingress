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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/socket"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/template"
	hatypes "github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"k8s.io/apimachinery/pkg/util/wait"
)

// InstanceOptions ...
type InstanceOptions struct {
	AcmeSigner        acme.Signer
	AcmeQueue         utils.Queue
	RootFSPrefix      string
	LocalFSPrefix     string
	BackendShards     int
	HAProxyCfgDir     string
	HAProxyMapsDir    string
	LeaderElector     types.LeaderElector
	IsMasterWorker    bool
	IsExternal        bool
	MasterSocket      string
	AdminSocket       string
	AcmeSocket        string
	MaxOldConfigFiles int
	Metrics           types.Metrics
	ReloadQueue       utils.Queue
	ReloadStrategy    string
	SortEndpointsBy   string
	StopCh            chan struct{}
	TrackInstances    bool
	ValidateConfig    bool
	// TODO Fake is used to skip real haproxy calls. Use a mock instead.
	fake bool
}

// Instance ...
type Instance interface {
	AcmeCheck(source string) (int, error)
	ParseTemplates() error
	Config() Config
	CalcIdleMetric()
	Update(timer *utils.Timer)
	Reload(timer *utils.Timer)
	Shutdown()
}

// CreateInstance ...
func CreateInstance(logger types.Logger, options InstanceOptions) Instance {
	return &instance{
		waitProc: make(chan struct{}),
		logger:   logger,
		options:  &options,
		conns:    newConnections(options.MasterSocket, options.AdminSocket),
		metrics:  options.Metrics,
		//
		haproxyTmpl:     template.CreateConfig(),
		mapsTmpl:        template.CreateConfig(),
		modsecTmpl:      template.CreateConfig(),
		haResponseTmpl:  template.CreateConfig(),
		luaResponseTmpl: template.CreateConfig(),
	}
}

type instance struct {
	up          bool
	waitProc    chan struct{}
	failedSince *time.Time
	logger      types.Logger
	options     *InstanceOptions
	config      Config
	conns       *connections
	metrics     types.Metrics
	//
	haproxyTmpl     *template.Config
	mapsTmpl        *template.Config
	modsecTmpl      *template.Config
	haResponseTmpl  *template.Config
	luaResponseTmpl *template.Config
}

func (i *instance) AcmeCheck(source string) (int, error) {
	var count int
	if !i.up {
		return count, fmt.Errorf("controller wasn't started yet")
	}
	if i.options.AcmeQueue == nil {
		return count, fmt.Errorf("Acme queue wasn't configured")
	}
	hasAccount := i.acmeEnsureConfig(i.config.AcmeData())
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
	for _, storage := range i.config.AcmeData().Storages().BuildAcmeStorages() {
		i.acmeAddStorage(storage)
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

func (i *instance) acmeAddStorage(storage string) {
	// TODO change to a proper entity
	items := strings.Split(storage, ",")
	if len(items) >= 2 {
		name := items[0]
		prefChain := items[1]
		domains := strings.Join(items[2:], ",")
		i.logger.InfoV(3, "enqueue certificate for processing: storage=%s domain(s)=%s preferred-chain=%s", name, domains, prefChain)
	}
	i.options.AcmeQueue.Add(storage)
}

func (i *instance) acmeRemoveStorage(storage string) {
	i.options.AcmeQueue.Remove(storage)
}

func (i *instance) ParseTemplates() error {
	i.haproxyTmpl.ClearTemplates()
	i.mapsTmpl.ClearTemplates()
	i.modsecTmpl.ClearTemplates()
	i.haResponseTmpl.ClearTemplates()
	i.luaResponseTmpl.ClearTemplates()
	templatesDir := i.options.RootFSPrefix + "/etc/templates"
	if err := i.modsecTmpl.NewTemplate(
		"modsecurity.tmpl",
		templatesDir+"/modsecurity/modsecurity.tmpl",
		i.options.HAProxyCfgDir+"/spoe-modsecurity.conf",
		0,
		1024,
	); err != nil {
		return err
	}
	if err := i.haproxyTmpl.NewTemplate(
		"haproxy.tmpl",
		templatesDir+"/haproxy/haproxy.tmpl",
		i.options.HAProxyCfgDir+"/haproxy.cfg",
		i.options.MaxOldConfigFiles,
		16384,
	); err != nil {
		return err
	}
	if err := i.mapsTmpl.NewTemplate(
		"map.tmpl",
		templatesDir+"/map/map.tmpl",
		"",
		0,
		2048,
	); err != nil {
		return err
	}
	if err := i.haResponseTmpl.NewTemplate(
		"response.http.tmpl",
		templatesDir+"/responses/response.http.tmpl",
		"",
		0,
		2048,
	); err != nil {
		return err
	}
	if err := i.luaResponseTmpl.NewTemplate(
		"responses.lua.tmpl",
		templatesDir+"/responses/responses.lua.tmpl",
		i.options.HAProxyCfgDir+"/lua/responses.lua",
		0,
		2048,
	); err != nil {
		return err
	}
	return nil
}

func (i *instance) Config() Config {
	if i.config == nil {
		config := createConfig(options{
			mapsTemplate: i.mapsTmpl,
			mapsDir:      i.options.HAProxyMapsDir,
			shardCount:   i.options.BackendShards,
		})
		i.config = config
	}
	return i.config
}

var idleRegex = regexp.MustCompile(`Idle_pct: ([0-9]+)`)

func (i *instance) CalcIdleMetric() {
	if !i.up {
		return
	}
	msg, err := i.conns.IdleChk().Send(i.metrics.HAProxyShowInfoResponseTime, "show info")
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
	if i.config == nil || i.options.AcmeQueue == nil {
		return
	}
	storages := i.config.AcmeData().Storages()
	le := i.options.LeaderElector
	if le.IsLeader() {
		hasAccount := i.acmeEnsureConfig(i.config.AcmeData())
		if !hasAccount {
			return
		}
		for _, add := range storages.BuildAcmeStoragesAdd() {
			i.acmeAddStorage(add)
		}
		for _, del := range storages.BuildAcmeStoragesDel() {
			i.acmeRemoveStorage(del)
		}
	} else if storages.Updated() {
		i.logger.InfoV(2, "skipping acme update check, leader is %s", le.LeaderName())
	}
}

func (i *instance) haproxyUpdate(timer *utils.Timer) {
	// nil config, just ignore
	if i.config == nil {
		return
	}
	//
	// this should be taken into account when refactoring this func:
	//   - dynUpdater might change config state, so it should be called before templates.Write()
	//   - i.metrics.IncUpdate<Status>() should be called always, but only once
	//   - i.updateSuccessful(<bool>) should be called only if haproxy is reloaded or cfg is validated
	//
	defer i.config.Commit()
	i.config.SyncConfig()
	i.config.Shrink()
	if err := i.config.WriteTCPServicesMaps(); err != nil {
		i.logger.Error("error building tcp services maps: %v", err)
		i.metrics.IncUpdateNoop()
		return
	}
	if err := i.config.WriteFrontendMaps(); err != nil {
		i.logger.Error("error building frontend maps: %v", err)
		i.metrics.IncUpdateNoop()
		return
	}
	if err := i.config.WriteBackendMaps(); err != nil {
		i.logger.Error("error building backend maps: %v", err)
		i.metrics.IncUpdateNoop()
		return
	}
	timer.Tick("write_maps")
	if !i.options.fake {
		// TODO update tests and remove `if !fake` above
		i.logChanged()
	}
	updater := i.newDynUpdater()
	updated := updater.update()
	if i.options.SortEndpointsBy != "random" {
		i.config.Backends().SortChangedEndpoints(i.options.SortEndpointsBy)
	} else if !updated {
		// Only shuffle if need to reload
		i.config.Backends().ShuffleAllEndpoints()
		timer.Tick("shuffle_endpoints")
	}
	i.config.Backends().FillSourceIPs()
	if !updated || updater.cmdCnt > 0 {
		// only need to rewrite config files if:
		//   - !updated           - there are changes that cannot be dynamically applied
		//   - updater.cmdCnt > 0 - there are changes that was dynamically applied
		err := i.writeConfig()
		timer.Tick("write_config")
		if err != nil {
			i.logger.Error("error writing configuration: %v", err)
			i.metrics.IncUpdateNoop()
			return
		}
	}
	i.updateCertExpiring()
	defer func() {
		if i.failedSince != nil {
			i.logger.Error("haproxy failed to reload, first occurrence at %s", i.failedSince.Format("2006-01-02 15:04:05.999999 -0700 MST"))
		}
	}()
	if updated {
		if updater.cmdCnt > 0 {
			if i.options.ValidateConfig {
				var err error
				if err = i.check(); err != nil {
					i.logger.Error("error validating config file:\n%v", err)
				}
				timer.Tick("validate_cfg")
				i.updateSuccessful(err == nil)
			}
			i.logger.Info("haproxy updated without needing to reload. Commands sent: %d", updater.cmdCnt)
			i.metrics.IncUpdateDynamic()
		} else {
			i.logger.Info("old and new configurations match")
			i.metrics.IncUpdateNoop()
		}
		return
	}
	if i.options.ReloadQueue != nil {
		i.options.ReloadQueue.Notify()
		i.logger.InfoV(2, "haproxy reload enqueued")
	} else {
		i.Reload(timer)
	}
}

func (i *instance) Reload(timer *utils.Timer) {
	i.metrics.IncUpdateFull()
	if i.options.TrackInstances {
		timeoutStopDur := i.config.Global().TimeoutStopDuration
		closeSessDur := i.config.Global().CloseSessionsDuration
		i.conns.TrackCurrentInstance(timeoutStopDur, closeSessDur)
	}
	err := i.reloadHAProxy()
	timer.Tick("reload_haproxy")
	if err != nil {
		i.logger.Error("error reloading server: %v", err)
		i.updateSuccessful(false)
		if i.options.TrackInstances {
			i.conns.ReleaseLastInstance()
		}
		return
	}
	i.up = true
	i.updateSuccessful(true)
	message := "haproxy successfully reloaded"
	if i.options.IsExternal {
		message += " (external)"
	} else if i.options.IsMasterWorker {
		message += " (embedded master-worker)"
	} else {
		message += " (embedded daemon)"
	}
	if i.options.TrackInstances {
		message += "; tracked instance(s): " + strconv.Itoa(i.conns.OldInstancesCount())
	}
	i.logger.Info(message)
}

func (i *instance) Shutdown() {
	if !i.up || i.options.IsExternal {
		// lifecycle isn't controlled by HAProxy Ingress
		return
	}
	if i.options.IsMasterWorker {
		<-i.waitProc
		return
	}
	i.logger.Info("shutting down embedded haproxy")
	out, err := exec.Command(
		i.options.RootFSPrefix+"/haproxy-shutdown.sh",
		i.options.LocalFSPrefix,
	).CombinedOutput()
	outstr := string(out)
	if outstr != "" {
		i.logger.Warn("output from the shutdown process: %v", outstr)
	}
	if err != nil {
		i.logger.Error("error shutting down haproxy: %v", err)
	}
}

func (i *instance) logChanged() {
	hostsAdd := i.config.Hosts().ItemsAdd()
	if len(hostsAdd) < 100 {
		hostsDel := i.config.Hosts().ItemsDel()
		hosts := make([]string, 0, len(hostsAdd))
		for host := range hostsAdd {
			hosts = append(hosts, host)
		}
		for host := range hostsDel {
			if _, found := hostsAdd[host]; !found {
				hosts = append(hosts, host)
			}
		}
		sort.Strings(hosts)
		i.logger.InfoV(2, "updating %d host(s): %v", len(hosts), hosts)
	} else {
		i.logger.InfoV(2, "updating %d hosts", len(hostsAdd))
	}
	backsAdd := i.config.Backends().ItemsAdd()
	if len(backsAdd) < 100 {
		backsDel := i.config.Backends().ItemsDel()
		backs := make([]string, 0, len(backsAdd))
		for back := range backsAdd {
			backs = append(backs, back)
		}
		for back := range backsDel {
			if _, found := backsAdd[back]; !found {
				backs = append(backs, back)
			}
		}
		sort.Strings(backs)
		i.logger.InfoV(2, "updating %d backend(s): %v", len(backs), backs)
	} else {
		i.logger.InfoV(2, "updating %d backends", len(backsAdd))
	}
}

func (i *instance) writeConfig() (err error) {
	//
	// modsec template execution
	//
	err = i.modsecTmpl.Write(i.config)
	if err != nil {
		return err
	}
	//
	// custom responses template execution, raw HTTP HAProxy based
	//
	for _, response := range i.config.Global().CustomHTTPHAResponses {
		err = i.haResponseTmpl.WriteOutput(
			response, fmt.Sprintf("%s/errorfiles/%s.http", i.options.HAProxyCfgDir, response.Name))
		if err != nil {
			return err
		}
	}
	//
	// custom responses template execution, Lua script based
	//
	err = i.luaResponseTmpl.Write(i.config.Global().CustomHTTPLuaResponses)
	if err != nil {
		return err
	}
	//
	// haproxy template execution
	//
	//   a single template is used to generate all haproxy cfg files
	//   of a multi-file configuration. `datatype` is the root type
	//   that the template recognizes, which will behave accordingly
	//   to the filled/ignored attributes.
	//
	type datatype struct {
		Cfg      Config
		Global   *hatypes.Global
		Backends []*hatypes.Backend
	}
	// main cfg -- fills the .Cfg attribute
	err = i.haproxyTmpl.Write(datatype{Cfg: i.config})
	if err != nil {
		return err
	}
	// backend shards -- fills the .Global and .Backends attributes
	if i.options.BackendShards > 0 {
		shards := i.config.Backends().ChangedShards()
		if len(shards) > 0 {
			strshards := make([]string, len(shards))
			for n, j := range shards {
				str := fmt.Sprintf("%03d", j)
				configFile := filepath.Join(i.options.HAProxyCfgDir, "haproxy5-backend"+str+".cfg")
				if err = i.haproxyTmpl.WriteOutput(datatype{
					Global:   i.config.Global(),
					Backends: i.config.Backends().BuildSortedShard(j),
				}, configFile); err != nil {
					return err
				}
				strshards[n] = str
			}
			i.logger.InfoV(2, "updated main cfg and %d backend file(s): %v", len(strshards), strshards)
		}
	}
	return err
}

func (i *instance) updateSuccessful(success bool) {
	if success {
		i.failedSince = nil
	} else if i.failedSince == nil {
		now := time.Now()
		i.failedSince = &now
	}
	i.metrics.UpdateSuccessful(success)
}

func (i *instance) updateCertExpiring() {
	hostsAdd := i.config.Hosts().ItemsAdd()
	hostsDel := i.config.Hosts().ItemsDel()
	if !i.config.Hosts().HasCommit() {
		// TODO the time between this reset and finishing to repopulate the gauge would lead
		// to incomplete data scraped by Prometheus. This however happens only when a full parsing
		// happens - edit globals, edit default crt, invalid data coming from lister events
		i.metrics.ClearCertExpire()
	}
	for hostname, oldHost := range hostsDel {
		if oldHost.TLS.HasTLS() {
			curHost, found := hostsAdd[hostname]
			if !found || oldHost.TLS.TLSCommonName != curHost.TLS.TLSCommonName {
				i.metrics.SetCertExpireDate(hostname, oldHost.TLS.TLSCommonName, nil)
			}
		}
	}
	for hostname, curHost := range hostsAdd {
		if curHost.TLS.HasTLS() {
			oldHost, found := hostsDel[hostname]
			if !found || oldHost.TLS.TLSCommonName != curHost.TLS.TLSCommonName || oldHost.TLS.TLSNotAfter != curHost.TLS.TLSNotAfter {
				i.metrics.SetCertExpireDate(hostname, curHost.TLS.TLSCommonName, &curHost.TLS.TLSNotAfter)
			}
		}
	}
}

func (i *instance) check() error {
	if i.options.fake {
		i.logger.Info("(test) check was skipped")
		return nil
	}
	if i.options.IsExternal {
		// TODO check config on remote haproxy
	} else {
		// TODO Move all magic strings to a single place
		out, err := exec.Command("haproxy", "-c", "-f", i.options.HAProxyCfgDir).CombinedOutput()
		outstr := string(out)
		if err != nil {
			return fmt.Errorf(outstr)
		}
	}
	return nil
}

func (i *instance) reloadHAProxy() error {
	if i.options.fake {
		i.logger.Info("(test) reload was skipped")
		return nil
	}
	if i.options.IsExternal {
		return i.reloadExternal()
	} else if i.options.IsMasterWorker {
		return i.reloadEmbeddedMasterWorker()
	}
	return i.reloadEmbeddedDaemon()
}

func (i *instance) reloadEmbeddedDaemon() error {
	state := "0"
	if i.config.Global().LoadServerState {
		state = "1"
	}
	// TODO Move all magic strings to a single place
	out, err := exec.Command(
		i.options.RootFSPrefix+"/haproxy-reload.sh",
		i.options.ReloadStrategy,
		i.options.HAProxyCfgDir,
		i.options.LocalFSPrefix,
		state,
	).CombinedOutput()
	outstr := string(out)
	if len(outstr) > 0 {
		i.logger.Warn("output from haproxy:\n%v", outstr)
	}
	return err
}

func (i *instance) reloadEmbeddedMasterWorker() error {
	if !i.up {
		go func() {
			wait.Until(i.startHAProxySync, 4*time.Second, i.options.StopCh)
			close(i.waitProc)
		}()
		if err := i.waitMaster(); err != nil {
			return err
		}
	} else {
		if err := i.reloadWorker(); err != nil {
			return err
		}
	}
	return i.waitWorker()
}

func (i *instance) startHAProxySync() {
	cmd := exec.Command(
		"haproxy",
		"-W",
		"-S", i.options.MasterSocket+",mode,600",
		"-f", i.options.HAProxyCfgDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		i.logger.Error("error starting haproxy: %v", err)
		return
	}
	wait := make(chan struct{})
	go func() {
		if err := cmd.Wait(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				i.logger.Info("haproxy stopped (exit code: %d)", exitError.ExitCode())
			} else {
				i.logger.Error("error while running haproxy: %v", err)
			}
		} else {
			i.logger.Info("haproxy stopped")
		}
		close(wait)
	}()
	select {
	case <-i.options.StopCh:
		i.logger.Info("stopping haproxy master process (pid: %d)", cmd.Process.Pid)
		cmd.Process.Signal(syscall.SIGTERM)
		<-wait
	case <-wait:
	}
}

func (i *instance) reloadExternal() error {
	if !i.up {
		// first run, wait until the external haproxy is running
		// and successfully listening to the master socket.
		if err := i.waitMaster(); err != nil {
			return err
		}
	}
	if err := i.reloadWorker(); err != nil {
		return err
	}
	return i.waitWorker()
}

func (i *instance) waitMaster() error {
	if i.options.IsExternal {
		i.logger.Info("waiting for the external haproxy...")
	} else {
		i.logger.Info("waiting for master socket...")
	}
	errCh := make(chan error)
	masterSock := i.conns.Master()
	go func() {
		_, err := socket.HAProxyProcs(masterSock)
		errCh <- err
	}()
	for {
		select {
		case err := <-errCh:
			return err
		case <-i.options.StopCh:
			return fmt.Errorf("received sigterm")
		case <-time.After(10 * time.Second):
			i.logger.Info("... still waiting for the master socket '%s'", masterSock.Address())
		}
	}
}

func (i *instance) reloadWorker() error {
	if _, err := i.conns.Master().Send(nil, "reload"); err != nil {
		return fmt.Errorf("error sending reload to master socket: %w", err)
	}
	return nil
}

func (i *instance) waitWorker() error {
	out, err := socket.HAProxyProcs(i.conns.Master())
	if err != nil {
		return fmt.Errorf("error reading procs from master socket: %w", err)
	}
	if len(out.Workers) == 0 || out.Master.Failed > 0 {
		// `len(out.Workers) == 0` => haproxy 2.2 to 2.4
		// `out.Master.Failed > 0` => haproxy 2.5+
		return fmt.Errorf("external haproxy was not successfully reloaded")
	}
	return nil
}
