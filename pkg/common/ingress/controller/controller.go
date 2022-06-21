/*
Copyright 2015 The Kubernetes Authors.

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

package controller

import (
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	apiv1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// NewCtrlIntf is a temporary interface used by this generic and now
// deprecated controller to call functionality moved to the new controller.
type NewCtrlIntf interface {
	GetIngressList() ([]*networking.Ingress, error)
	GetSecret(name string) (*apiv1.Secret, error)
	IsValidClass(ing *networking.Ingress) bool
}

// GenericController holds the boilerplate code required to build an Ingress controller.
type GenericController struct {
	cfg            *Configuration
	newctrl        NewCtrlIntf
	syncStatus     StatusSync
	sslCertTracker *sslCertTracker
	stopLock       *sync.Mutex
	stopCh         chan struct{}
}

// Configuration contains all the settings required by an Ingress controller
type Configuration struct {
	Client       types.Client
	MasterWorker bool
	MasterSocket string

	RateLimitUpdate  float32
	ReloadInterval   time.Duration
	ResyncPeriod     time.Duration
	WaitBeforeUpdate time.Duration

	DefaultService           string
	IngressClass             string
	IngressClassPrecedence   bool
	ControllerName           string
	WatchIngressWithoutClass bool
	WatchGateway             bool
	WatchNamespace           string
	ConfigMapName            string

	ReloadStrategy    string
	MaxOldConfigFiles int
	ValidateConfig    bool
	LocalFSPrefix     string

	ForceNamespaceIsolation bool
	WaitBeforeShutdown      int
	AllowCrossNamespace     bool
	DisablePodList          bool
	DisableExternalName     bool
	DisableConfigKeywords   string
	AnnPrefix               []string

	AcmeServer              bool
	AcmeCheckPeriod         time.Duration
	AcmeFailInitialDuration time.Duration
	AcmeFailMaxDuration     time.Duration
	AcmeElectionID          string
	AcmeSecretKeyName       string
	AcmeTokenConfigmapName  string
	AcmeTrackTLSAnn         bool

	BucketsResponseTime []float64

	TCPConfigMapName       string
	DefaultSSLCertificate  string
	VerifyHostname         bool
	DefaultHealthzURL      string
	StatsCollectProcPeriod time.Duration
	PublishService         string
	TrackOldInstances      bool
	Backend                ingress.Controller

	UpdateStatus           bool
	UseNodeInternalIP      bool
	ElectionID             string
	UpdateStatusOnShutdown bool

	BackendShards   int
	SortEndpointsBy string
}

// newIngressController creates an Ingress controller
func newIngressController(config *Configuration) *GenericController {

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{
		Interface: config.Client.CoreV1().Events(config.WatchNamespace),
	})

	ic := GenericController{
		cfg:            config,
		stopLock:       &sync.Mutex{},
		stopCh:         make(chan struct{}),
		sslCertTracker: newSSLCertTracker(),
	}

	if config.UpdateStatus {
		ic.syncStatus = NewStatusSyncer(&ic)
	} else {
		klog.Warning("Update of ingress status is disabled (flag --update-status=false was specified)")
	}

	return &ic
}

// GetConfig expose the controller configuration
func (ic *GenericController) GetConfig() *Configuration {
	return ic.cfg
}

// GetStopCh ...
func (ic *GenericController) GetStopCh() chan struct{} {
	return ic.stopCh
}

// SetNewCtrl ...
func (ic *GenericController) SetNewCtrl(newctrl NewCtrlIntf) {
	ic.newctrl = newctrl
}

// Info returns information about the backend
func (ic GenericController) Info() *ingress.BackendInfo {
	return ic.cfg.Backend.Info()
}

// GetCertificate get a SSLCert object from a secret name
func (ic *GenericController) GetCertificate(namespace, secretName string) (*ingress.SSLCert, error) {
	name := fmt.Sprintf("%s/%s", namespace, secretName)
	crt, exists := ic.sslCertTracker.Get(name)
	if !exists {
		ic.SyncSecret(name)
		crt, exists = ic.sslCertTracker.Get(name)
	}
	if exists {
		return crt.(*ingress.SSLCert), nil
	}
	if _, err := ic.newctrl.GetSecret(name); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("secret '%v' have neither ca.crt nor tls.crt/tls.key pair", name)
}

// UpdateSecret ...
func (ic GenericController) UpdateSecret(key string) {
	if _, found := ic.sslCertTracker.Get(key); found {
		ic.SyncSecret(key)
	}
}

// DeleteSecret ...
func (ic GenericController) DeleteSecret(key string) {
	ic.sslCertTracker.DeleteAll(key)
}

// Stop stops the loadbalancer controller.
func (ic GenericController) Stop() error {
	ic.stopLock.Lock()
	defer ic.stopLock.Unlock()

	if ic.stopCh != nil {
		klog.Infof("shutting down controller queues")
		close(ic.stopCh)
		if ic.syncStatus != nil {
			ic.syncStatus.Shutdown()
		}
		return nil
	}

	return fmt.Errorf("shutdown already in progress")
}

// StartAsync starts the Ingress controller.
func (ic *GenericController) StartAsync() {
	if ic.syncStatus != nil {
		go ic.syncStatus.Run(ic.stopCh)
	}
}

// CreateDefaultSSLCertificate ...
func (ic *GenericController) CreateDefaultSSLCertificate() (path, hash string, crt *x509.Certificate) {
	defCert, defKey := ssl.GetFakeSSLCert(
		[]string{"Acme Co"}, "Kubernetes Ingress Controller Fake Certificate", []string{"ingress.local"},
	)
	c, err := ssl.AddOrUpdateCertAndKey("default-fake-certificate", defCert, defKey, []byte{})
	if err != nil {
		klog.Fatalf("Error generating self signed certificate: %v", err)
	}
	return c.PemFileName, c.PemSHA, c.Certificate
}
