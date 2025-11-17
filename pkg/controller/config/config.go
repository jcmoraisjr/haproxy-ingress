/*
Copyright 2022 The HAProxy Ingress Controller Authors.

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

package config

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gwapiversioned "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
)

// Create ...
func Create(opt *Options) (*Config, error) {
	return CreateWithConfig(context.Background(), nil, opt)
}

// CreateWithConfig ...
func CreateWithConfig(ctx context.Context, restConfig *rest.Config, opt *Options) (*Config, error) {
	versionInfo := version.Info{
		Name:       version.NAME,
		Release:    version.RELEASE,
		Build:      version.COMMIT,
		Repository: version.REPO,
	}

	if opt.Version {
		fmt.Printf("%#v\n", versionInfo)
		os.Exit(0)
	}

	if !opt.LogZap {
		if opt.LogDev || opt.LogCaller || opt.LogEnableStacktrace || opt.LogEncoder != "" || opt.LogEncodeTime != "" {
			return nil, fmt.Errorf("--log-dev, --log-caller, --log-enable-stacktrace --log-encoder and --log-encode-time are only supported if --log-zap is enabled")
		}
		var level klog.Level
		if err := level.Set(strconv.Itoa(opt.LogLevel - 1)); err != nil {
			return nil, err
		}
		ctrl.SetLogger(klog.NewKlogr())
	} else {
		logger, err := newZapLogger(opt.LogDev, opt.LogLevel, opt.LogCaller, opt.LogEnableStacktrace, opt.LogEncoder, opt.LogEncodeTime)
		if err != nil {
			return nil, err
		}
		ctrl.SetLogger(logger)
		klog.SetLogger(logger)
	}

	rootLogger := ctrl.Log
	configLog := rootLogger.WithName("config")

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1alpha2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1beta1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))

	var kubeConfig *rest.Config
	switch {
	case restConfig != nil:
		kubeConfig = restConfig
	case opt.ApiserverHost != "":
		kubeConfigFile := opt.KubeConfig.String()
		if kubeConfigFile == "" {
			return nil, fmt.Errorf("--kubeconfig is mandatory when --apiserver-host is configured")
		}
		var err error
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigFile},
			&clientcmd.ConfigOverrides{
				ClusterInfo: clientcmdapi.Cluster{
					Server: opt.ApiserverHost,
				},
			}).ClientConfig()
		if err != nil {
			return nil, err
		}
	default:
		var err error
		kubeConfig, err = ctrl.GetConfig()
		if err != nil {
			return nil, err
		}
	}
	if opt.DisableAPIWarnings {
		kubeConfig.WarningHandler = rest.NoWarnings{}
	}

	// `kubeConfig` is the real `*rest.Config` used
	// by the manager to create the controller's client
	//
	// the clients below are just used locally to validate some config options
	client := kubernetes.NewForConfigOrDie(kubeConfig)
	clientGateway := gwapiversioned.NewForConfigOrDie(kubeConfig)

	configLog.Info("version info",
		"controller-publicname", versionInfo.Name,
		"controller-release", versionInfo.Release,
		"controller-build", versionInfo.Build,
		"controller-repo", versionInfo.Repository,
	)

	// deprecated area
	if opt.AcmeElectionID != "" {
		configLog.Info("DEPRECATED: --acme-election-id is ignored, acme and status update leader uses the same ID from --election-id command-line option.")
	}
	if opt.HealthzPort > 0 {
		configLog.Info(fmt.Sprintf("DEPRECATED: --healthz-addr=:%d should be used instead", opt.HealthzPort))
	}
	if opt.IgnoreIngressWithoutClass {
		configLog.Info("DEPRECATED: --ignore-ingress-without-class is now ignored and can be safely removed")
	}
	if opt.DisableNodeList {
		configLog.Info("DEPRECATED: --disable-node-list is now ignored and can be safely removed")
	}
	if opt.DisablePodList {
		configLog.Info("DEPRECATED: --disable-pod-list is ignored, controller-runtime automatically configures this option.")
	}
	if opt.ForceIsolation {
		configLog.Info("DEPRECATED: --force-namespace-isolation is ignored, use allow-cross-namespace command-line options or cross-namespace configuration keys instead.")
	}
	if !opt.EnableEndpointSlicesAPI {
		configLog.Info("DEPRECATED: Endpoints API is deprecated since Kubernetes 1.33, --enable-endpointslices-api cannot be disabled and EndpointSlices API will always be used.")
	}

	// warning area
	if opt.ShutdownTimeout < opt.HAProxyGracePeriod {
		configLog.Info(fmt.Sprintf("WARNING: --shutdown-timeout=%s is less than --haproxy-grace-period=%s", opt.ShutdownTimeout.String(), opt.HAProxyGracePeriod.String()))
	}

	if opt.IngressClass != "" {
		configLog.Info("watching for ingress resources with 'kubernetes.io/ingress.class'", "annotation", opt.IngressClass)
	}

	var waitShutdown time.Duration
	if opt.WaitBeforeShutdown != "" {
		var err error
		waitShutdown, err = time.ParseDuration(opt.WaitBeforeShutdown)
		if err != nil {
			waitInt, err := strconv.Atoi(opt.WaitBeforeShutdown)
			if err != nil {
				return nil, fmt.Errorf("--wait-before-shutdown='%s' is neither a valid int (seconds) nor a valid duration", opt.WaitBeforeShutdown)
			}
			configLog.Info(fmt.Sprintf("DEPRECATED: --wait-before-shutdown=%s is missing a time suffix", opt.WaitBeforeShutdown))
			waitShutdown = time.Duration(waitInt) * time.Second
		}
	}

	rootcontext := logr.NewContext(createRootContext(ctx, rootLogger, waitShutdown), rootLogger)

	controllerName := "haproxy-ingress.github.io/controller"
	if opt.ControllerClass != "" {
		controllerName += "/" + strings.TrimLeft(opt.ControllerClass, "/")
	}
	configLog.Info("watching for ingress resources with IngressClass", "controller-name", controllerName)

	if opt.WatchIngressWithoutClass {
		configLog.Info("watching for ingress resources without any class reference - --watch-ingress-without-class is true")
	} else {
		configLog.Info("ignoring ingress resources without any class reference - --watch-ingress-without-class is false")
	}

	if opt.WatchGateway {
		configLog.Info("watching for Gateway API resources - --watch-gateway is true")
	}

	var hasGatewayV1, hasGatewayB1, hasGatewayA2, hasTCPRouteA2, hasTLSRouteA2 bool
	if opt.WatchGateway {
		gwapis := []string{"gatewayclass", "gateway", "httproute"}
		tcpapis := []string{"tcproute"}
		tlsapis := []string{"tlsroute"}

		gwV1 := configHasAPI(clientGateway.Discovery(), gatewayv1.GroupVersion, gwapis...)
		if gwV1 {
			configLog.Info("found custom resource definition for gateway API v1")
		}
		gwB1 := configHasAPI(clientGateway.Discovery(), gatewayv1beta1.GroupVersion, gwapis...)
		if gwB1 {
			configLog.Info("found custom resource definition for gateway API v1beta1")
		}
		gwA2 := configHasAPI(clientGateway.Discovery(), gatewayv1alpha2.GroupVersion, gwapis...)
		if gwA2 {
			configLog.Info("found custom resource definition for gateway API v1alpha2")
		}

		// only one GatewayClass/Gateway/HTTPRoute version should be enabled at the same time,
		// otherwise we'd be retrieving the same duplicated resource from distinct api endpoints.
		gw := gwV1 || gwB1 || gwA2
		hasGatewayV1 = gwV1
		hasGatewayB1 = gwB1 && !hasGatewayV1
		hasGatewayA2 = gwA2 && !hasGatewayB1

		tcpA2 := configHasAPI(clientGateway.Discovery(), gatewayv1alpha2.GroupVersion, tcpapis...)
		if tcpA2 {
			configLog.Info("found custom resource definition for TCPRoute API v1alpha2")
		}

		tlsA2 := configHasAPI(clientGateway.Discovery(), gatewayv1alpha2.GroupVersion, tlsapis...)
		if tlsA2 {
			configLog.Info("found custom resource definition for TLSRoute API v1alpha2")
		}

		// TODO: cannot enable TCPRoute or TLSRoute without Gateway and GatewayClass, but currently
		// HTTPRoute discovery is coupled and its CRD should be installed as well, even if not used.
		// We should use a distinct flag for HTTPRoute.
		hasTCPRouteA2 = tcpA2 && gw
		hasTLSRouteA2 = tlsA2 && gw
	}

	if opt.EnableEndpointSlicesAPI {
		configLog.Info("watching endpointslices - --enable-endpointslices-api is true")
	} else {
		configLog.Info("watching endpoints - --enable-endpointslices-api is false")
	}

	if opt.PublishService != "" && opt.PublishAddress != "" {
		return nil, fmt.Errorf("configure only one of --publish-service or --publish-address")
	}

	var publishAddressHostnames, publishAddressIPs []string
	for _, addr := range strings.Split(opt.PublishAddress, ",") {
		if addr == "" {
			continue
		}
		if net.ParseIP(addr) == nil {
			publishAddressHostnames = append(publishAddressHostnames, addr)
		} else {
			publishAddressIPs = append(publishAddressIPs, addr)
		}
	}

	controllerPod := types.NamespacedName{
		Namespace: os.Getenv("POD_NAMESPACE"),
		Name:      os.Getenv("POD_NAME"),
	}

	controllerPodSelector, err := getControllerPodSelector(ctx, configLog, client, controllerPod)
	if err != nil {
		return nil, fmt.Errorf("error getting controller pod selector: %w", err)
	}

	// we could `|| hasGateway[version...]` instead of `|| opt.WatchGateway` here,
	// but we're choosing a consistent startup behavior despite of the cluster configuration.
	election := opt.UpdateStatus || opt.AcmeServer || opt.WatchGateway
	if election && controllerPod.Namespace == "" {
		return nil, fmt.Errorf("POD_NAMESPACE envvar should be configured when --update-status=true, --acme-server=true, or --watch-gateway=true")
	}
	if election && opt.IngressClass == "" {
		return nil, fmt.Errorf("--ingress-class should not be empty when --update-status=true, --acme-server=true, or --watch-gateway=true")
	}
	var electionID string
	if election {
		if strings.Contains(opt.ElectionID, "%s") {
			electionID = fmt.Sprintf(opt.ElectionID, opt.IngressClass)
		} else {
			// backward compatibility behavior
			electionID = opt.ElectionID + "-" + opt.IngressClass
		}
	}

	if opt.UpdateStatus && controllerPod.Name == "" && opt.PublishService == "" && len(publishAddressHostnames)+len(publishAddressIPs) == 0 {
		return nil, fmt.Errorf("one of --publish-service, --publish-address or POD_NAME envvar should be configured when --update-status=true")
	}

	acmeSecretKeyNamespaceName := opt.AcmeSecretKeyName
	if !strings.Contains(acmeSecretKeyNamespaceName, "/") {
		acmeSecretKeyNamespaceName = controllerPod.Namespace + "/" + acmeSecretKeyNamespaceName
	}
	acmeTokenConfigMapNamespaceName := opt.AcmeTokenConfigMapName
	if !strings.Contains(acmeTokenConfigMapNamespaceName, "/") {
		acmeTokenConfigMapNamespaceName = controllerPod.Namespace + "/" + acmeTokenConfigMapNamespaceName
	}

	masterWorkerCfg := opt.MasterWorker
	if !masterWorkerCfg && opt.MasterSocket != "" {
		return nil, fmt.Errorf("master-worker mode cannot be disabled when using external haproxy configuration")
	}
	if opt.MasterSocket != "" {
		configLog.Info("running external haproxy", "master-unix-socket", opt.MasterSocket)
	} else if masterWorkerCfg {
		configLog.Info("running embedded haproxy", "mode", "master-worker")
	} else {
		configLog.Info("running embedded haproxy", "mode", "daemon")
	}

	if opt.ReloadStrategy != "native" && opt.ReloadStrategy != "reusesocket" && opt.ReloadStrategy != "multibinder" {
		return nil, fmt.Errorf("unsupported reload strategy: %s", opt.ReloadStrategy)
	}
	if opt.ReloadStrategy == "multibinder" {
		configLog.Info("WARN: multibinder is deprecated, using reusesocket strategy instead. update your deployment configuration")
	}

	if opt.ConfigMap != "" {
		ns, name, err := cache.SplitMetaNamespaceKey(opt.ConfigMap)
		if err != nil {
			return nil, fmt.Errorf("invalid format for global ConfigMap '%s': %w", opt.ConfigMap, err)
		}
		_, err = client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error reading global ConfigMap '%s': %w", opt.ConfigMap, err)
		}
		configLog.Info("watching for global config options - --configmap was defined", "configmap", opt.ConfigMap)
	}

	if opt.DefaultSvc != "" {
		ns, name, err := cache.SplitMetaNamespaceKey(opt.DefaultSvc)
		if err != nil {
			return nil, fmt.Errorf("invalid format for service '%s': %w", opt.DefaultSvc, err)
		}
		_, err = client.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if errors.IsForbidden(err) {
				return nil, fmt.Errorf("it seems the cluster is running with Authorization enabled (like RBAC) and there is no permissions for the ingress controller. Please check the configuration")
			}
			return nil, fmt.Errorf("no service with name '%s' found: %w", opt.DefaultSvc, err)
		}
		configLog.Info("using default backend", "service", opt.DefaultSvc)
	}

	if svc := opt.PublishService; svc != "" {
		ns, name, err := cache.SplitMetaNamespaceKey(svc)
		if err != nil {
			return nil, fmt.Errorf("invalid service format: %w", err)
		}
		svc, err := client.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting information about service '%s': %w", svc, err)
		}
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			if len(svc.Spec.ExternalIPs) == 0 {
				return nil, fmt.Errorf("service '%s' does not (yet) have ingress points", svc)
			}
			configLog.Info("service validated as assigned with externalIP", "service", svc)
		} else {
			configLog.Info("service validated as source of Ingress status", "service", svc)
		}
	}

	if opt.WatchNamespace != "" {
		_, err := client.NetworkingV1().Ingresses(opt.WatchNamespace).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			return nil, fmt.Errorf("no namespace with name '%s' found: %w", opt.WatchNamespace, err)
		}
	} else {
		_, err := client.CoreV1().Services("default").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("error connecting to the apiserver: %w", err)
		}
	}

	if opt.RateLimitUpdate < 0.05 {
		return nil, fmt.Errorf(
			"rate limit update (%v) is too low: '%v' seconds between Ingress reloads. Use at least 0.05, which means 20 seconds between updates",
			opt.RateLimitUpdate, 1.0/opt.RateLimitUpdate)
	}

	if opt.RateLimitUpdate > 10 {
		return nil, fmt.Errorf(
			"rate limit update is too high: up to '%v' Ingress updates per second (max is 10)",
			opt.RateLimitUpdate)
	}

	if opt.ResyncPeriod.Seconds() < 10 {
		return nil, fmt.Errorf("resync period (%vs) is too low", opt.ResyncPeriod.Seconds())
	}

	if opt.WatchNamespace != corev1.NamespaceAll && opt.AllowCrossNamespace {
		return nil, fmt.Errorf("cannot use --watch-namespace if --allow-cross-namespace is true")
	}

	var annPrefixList []string
	for _, prefix := range strings.Split(opt.AnnPrefix, ",") {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			annPrefixList = append(annPrefixList, prefix)
		}
	}
	switch len(annPrefixList) {
	case 0:
		return nil, fmt.Errorf("at least one annotation prefix should be configured")
	case 1:
		configLog.Info("using annotations prefix", "prefix", annPrefixList[0])
	default:
		configLog.Info(
			fmt.Sprintf("using %d distinct annotations prefix", len(annPrefixList)),
			"precedence", strings.Join(annPrefixList, ", "))
	}

	sortEndpoints := strings.ToLower(opt.SortEndpointsBy)
	if sortEndpoints == "" {
		if opt.SortBackends {
			sortEndpoints = "name"
		} else {
			sortEndpoints = "endpoint"
		}
	}
	if !regexp.MustCompile(`^(ep|endpoint|ip|name|random)$`).MatchString(sortEndpoints) {
		return nil, fmt.Errorf("unsupported --sort-endpoint-by option: %s", sortEndpoints)
	}

	defaultDirCerts := "/var/lib/haproxy/crt"
	defaultDirCACerts := "/var/lib/haproxy/cacerts"
	defaultDirCrl := "/var/lib/haproxy/crl"
	defaultDirDHParam := "/var/lib/haproxy/dhparam"
	defaultDirVarRun := "/var/run/haproxy"
	defaultDirMaps := "/etc/haproxy/maps"
	defaultDirErrorfiles := "/etc/haproxy/errorfiles"
	defaultDirLuaScripts := "/etc/haproxy/lua"

	for _, dir := range []*string{
		&defaultDirCerts,
		&defaultDirCACerts,
		&defaultDirCrl,
		&defaultDirDHParam,
		&defaultDirVarRun,
		&defaultDirMaps,
		&defaultDirErrorfiles,
		&defaultDirLuaScripts,
	} {
		*dir = opt.LocalFSPrefix + *dir
		if err := os.MkdirAll(*dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to 'mkdir %s': %w", *dir, err)
		}
	}

	disableKeywords := utils.Split(opt.DisableConfigKeywords, ",")
	var healthz string
	if opt.HealthzPort > 0 {
		healthz = fmt.Sprintf(":%d", opt.HealthzPort)
	} else {
		healthz = opt.HealthzAddr
	}

	return &Config{
		AcmeCheckPeriod:          opt.AcmeCheckPeriod,
		AcmeFailInitialDuration:  opt.AcmeFailInitialDuration,
		AcmeFailMaxDuration:      opt.AcmeFailMaxDuration,
		AcmeSecretKeyName:        acmeSecretKeyNamespaceName,
		AcmeServer:               opt.AcmeServer,
		AcmeTokenConfigMapName:   acmeTokenConfigMapNamespaceName,
		AcmeTrackTLSAnn:          opt.AcmeTrackTLSAnn,
		AllowCrossNamespace:      opt.AllowCrossNamespace,
		AnnPrefix:                annPrefixList,
		BackendShards:            opt.BackendShards,
		BucketsResponseTime:      opt.BucketsResponseTime,
		ConfigMapName:            opt.ConfigMap,
		ControllerName:           controllerName,
		ControllerPod:            controllerPod,
		ControllerPodSelector:    controllerPodSelector,
		DefaultDirCACerts:        defaultDirCACerts,
		DefaultDirCerts:          defaultDirCerts,
		DefaultDirCrl:            defaultDirCrl,
		DefaultDirDHParam:        defaultDirDHParam,
		DefaultDirMaps:           defaultDirMaps,
		DefaultDirVarRun:         defaultDirVarRun,
		DefaultService:           opt.DefaultSvc,
		DefaultSSLCertificate:    opt.DefSSLCertificate,
		DisableExternalName:      opt.DisableExternalName,
		DisableKeywords:          disableKeywords,
		DisableIngressClassAPI:   opt.DisableIngressClassAPI,
		Election:                 election,
		ElectionID:               electionID,
		ElectionNamespace:        controllerPod.Namespace,
		ForceNamespaceIsolation:  opt.ForceIsolation,
		HasGatewayA2:             hasGatewayA2,
		HasGatewayB1:             hasGatewayB1,
		HasGatewayV1:             hasGatewayV1,
		HasTCPRouteA2:            hasTCPRouteA2,
		HasTLSRouteA2:            hasTLSRouteA2,
		HealthzAddr:              healthz,
		HealthzURL:               opt.HealthzURL,
		IngressClass:             opt.IngressClass,
		IngressClassPrecedence:   opt.IngressClassPrecedence,
		KubeConfig:               kubeConfig,
		LocalFSPrefix:            opt.LocalFSPrefix,
		MasterSocket:             opt.MasterSocket,
		MasterWorker:             masterWorkerCfg,
		MaxOldConfigFiles:        opt.MaxOldConfigFiles,
		Profiling:                opt.Profiling,
		PublishAddressHostnames:  publishAddressHostnames,
		PublishAddressIPs:        publishAddressIPs,
		PublishService:           opt.PublishService,
		RateLimitUpdate:          opt.RateLimitUpdate,
		ReadyzURL:                opt.ReadyzURL,
		ReloadInterval:           opt.ReloadInterval,
		ReloadRetry:              opt.ReloadRetry,
		ReloadStrategy:           opt.ReloadStrategy,
		ResyncPeriod:             &opt.ResyncPeriod,
		RootContext:              rootcontext,
		Scheme:                   scheme,
		ShutdownTimeout:          &opt.ShutdownTimeout,
		HAProxyGracePeriod:       opt.HAProxyGracePeriod,
		SortEndpointsBy:          sortEndpoints,
		StatsCollectProcPeriod:   opt.StatsCollectProcPeriod,
		StopHandler:              opt.StopHandler,
		TCPConfigMapName:         opt.TCPConfigMapName,
		TrackOldInstances:        opt.TrackOldInstances,
		UpdateStatus:             opt.UpdateStatus,
		UpdateStatusOnShutdown:   opt.UpdateStatusOnShutdown,
		UseNodeInternalIP:        opt.UseNodeInternalIP,
		ValidateConfig:           opt.ValidateConfig,
		VerifyHostname:           opt.VerifyHostname,
		VersionInfo:              versionInfo,
		WaitBeforeUpdate:         opt.WaitBeforeUpdate,
		WatchIngressWithoutClass: opt.WatchIngressWithoutClass,
		WatchNamespace:           opt.WatchNamespace,
	}, nil
}

func newZapLogger(logDev bool, logLevel int, logCaller, logEnableStacktrace bool, logEncoder, logEncodeTime string) (logr.Logger, error) {
	var zc zap.Config
	if logDev {
		zc = zap.NewDevelopmentConfig()
	} else {
		zc = zap.NewProductionConfig()
	}

	encoderName := logEncoder
	if encoderName == "" {
		encoderName = zc.Encoding
	}

	encodeTime := logEncodeTime
	if encodeTime == "" {
		if logDev {
			encodeTime = "iso8601"
		} else {
			encodeTime = "rfc3339nano"
		}
	}

	var baseEncoder func(zapcore.EncoderConfig) zapcore.Encoder
	switch encoderName {
	case "json":
		baseEncoder = zapcore.NewJSONEncoder
	case "console":
		baseEncoder = zapcore.NewConsoleEncoder
	default:
		return logr.Logger{}, fmt.Errorf("invalid encode name: %s", logEncoder)
	}

	klogEncoderName := "klog"
	if err := zap.RegisterEncoder(klogEncoderName, func(ec zapcore.EncoderConfig) (zapcore.Encoder, error) {
		return klogEncoder{baseEncoder(ec)}, nil
	}); err != nil {
		return logr.Logger{}, fmt.Errorf("error registering log encoder: %v", err)
	}

	zc.Encoding = klogEncoderName
	zc.Level = zap.NewAtomicLevelAt(zapcore.Level(1 - logLevel))
	zc.DisableStacktrace = !logEnableStacktrace
	err := zc.EncoderConfig.EncodeTime.UnmarshalText([]byte(encodeTime))
	if err != nil {
		return logr.Logger{}, fmt.Errorf("error unmarshalling encode time: %v", err)
	}

	zl, err := zc.Build(
		zap.WithCaller(logCaller),
		zap.AddCallerSkip(0),
	)
	if err != nil {
		return logr.Logger{}, fmt.Errorf("error configuring zap logger: %v", err)
	}
	return zapr.NewLogger(zl), nil
}

type klogEncoder struct {
	zapcore.Encoder
}

func (e klogEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	// klog always add a hardcoded line break that mess the zap output
	entry.Message = strings.TrimRight(entry.Message, "\n")
	return e.Encoder.EncodeEntry(entry, fields)
}

func createRootContext(ctx context.Context, rootLogger logr.Logger, waitShutdown time.Duration) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal, 3)
	signal.Notify(c, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log := rootLogger.WithName("signal")
		s := <-c
		log.Info("signal received", "signal", s.String())
		if waitShutdown > 0 {
			log.Info("waiting before shutdown controller manager", "duration", waitShutdown.String())
			select {
			case <-time.After(waitShutdown):
			case <-c:
				log.Info("skipping wait shutdown")
			}
		}
		cancel()
		<-c
		log.Info("second signal, killing process")
		os.Exit(1)
	}()
	return ctx
}

func configHasAPI(discovery discovery.DiscoveryInterface, gv metav1.GroupVersion, kind ...string) bool {
	gvstr := gv.String()
	resources, err := discovery.ServerResourcesForGroupVersion(gvstr)
	if err == nil && resources != nil {
		names := make(map[string]bool, len(resources.APIResources))
		for _, r := range resources.APIResources {
			names[r.SingularName] = true
		}
		for _, k := range kind {
			if !names[k] {
				return false
			}
		}
		return true
	}
	return false
}

func getControllerPodSelector(ctx context.Context, configLog logr.Logger, client kubernetes.Interface, controllerPod types.NamespacedName) (labels.Selector, error) {
	if controllerPod.Name == "" || controllerPod.Namespace == "" {
		// a missing selector is fine, everyone that needs it
		// (status, peers) should validate on config processing.
		return nil, nil
	}

	pod, err := client.CoreV1().Pods(controllerPod.Namespace).Get(ctx, controllerPod.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var owner *metav1.OwnerReference
	for i := range pod.OwnerReferences {
		owner = &pod.OwnerReferences[i]
		if *owner.Controller {
			break
		}
	}

	var podSelector labels.Selector
	if owner != nil {
		var labelSelector *metav1.LabelSelector
		switch owner.Kind {
		case "ReplicaSet":
			rs, err := client.AppsV1().ReplicaSets(controllerPod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				configLog.Error(err, "error reading controller's ReplicaSet, falling back to the default selector")
			} else {
				labelSelector = rs.Spec.Selector
				// we want old and new pods during rolling updates
				delete(labelSelector.MatchLabels, "pod-template-hash")
			}
		case "DaemonSet":
			ds, err := client.AppsV1().DaemonSets(controllerPod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				configLog.Error(err, "error reading controller's DaemonSet, falling back to the default selector")
			} else {
				labelSelector = ds.Spec.Selector
			}
		default:
			configLog.Info("controller pod owner is of an unsupported kind, falling back to the default selector", "kind", owner.Kind)
		}
		if labelSelector != nil {
			var err error
			podSelector, err = metav1.LabelSelectorAsSelector(labelSelector)
			if err != nil {
				return nil, fmt.Errorf("error parsing controller pod selector: %w", err)
			}
		}
	} else {
		configLog.Info("controller pod owner was not found, falling back to the default selector", "controller-pod", controllerPod.String())
	}

	if podSelector == nil {
		// we failed to identify a proper selector, lets use controller's labels
		// and remove the ones that uniquely identify a pod or a replicaSet.
		podLabels := pod.GetLabels()
		delete(podLabels, "controller-revision-hash")
		delete(podLabels, "pod-template-generation")
		delete(podLabels, "pod-template-hash")
		delete(podLabels, "apps.kubernetes.io/pod-index")
		delete(podLabels, "statefulset.kubernetes.io/pod-name")
		podSelector = labels.SelectorFromSet(podLabels)
	}

	configLog.Info("controller pod selector configured", "selector", podSelector.String(), "namespace", controllerPod.Namespace)

	return podSelector, nil
}

// Config ...
type Config struct {
	AcmeCheckPeriod          time.Duration
	AcmeFailInitialDuration  time.Duration
	AcmeFailMaxDuration      time.Duration
	AcmeSecretKeyName        string
	AcmeServer               bool
	AcmeTokenConfigMapName   string
	AcmeTrackTLSAnn          bool
	AllowCrossNamespace      bool
	AnnPrefix                []string
	BackendShards            int
	BucketsResponseTime      []float64
	ConfigMapName            string
	ControllerName           string
	ControllerPod            types.NamespacedName
	ControllerPodSelector    labels.Selector
	DefaultDirCerts          string
	DefaultDirCACerts        string
	DefaultDirCrl            string
	DefaultDirDHParam        string
	DefaultDirMaps           string
	DefaultDirVarRun         string
	DefaultService           string
	DefaultSSLCertificate    string
	DisableExternalName      bool
	DisableKeywords          []string
	DisableIngressClassAPI   bool
	Election                 bool
	ElectionID               string
	ElectionNamespace        string
	ForceNamespaceIsolation  bool
	HasGatewayA2             bool
	HasGatewayB1             bool
	HasGatewayV1             bool
	HasTCPRouteA2            bool
	HasTLSRouteA2            bool
	HealthzAddr              string
	HealthzURL               string
	IngressClass             string
	IngressClassPrecedence   bool
	KubeConfig               *rest.Config
	LocalFSPrefix            string
	MasterSocket             string
	MasterWorker             bool
	MaxOldConfigFiles        int
	Profiling                bool
	PublishAddressHostnames  []string
	PublishAddressIPs        []string
	PublishService           string
	RateLimitUpdate          float64
	ReadyzURL                string
	ReloadInterval           time.Duration
	ReloadRetry              time.Duration
	ReloadStrategy           string
	ResyncPeriod             *time.Duration
	RootContext              context.Context
	Scheme                   *runtime.Scheme
	ShutdownTimeout          *time.Duration
	HAProxyGracePeriod       time.Duration
	SortEndpointsBy          string
	StatsCollectProcPeriod   time.Duration
	StopHandler              bool
	TCPConfigMapName         string
	TrackOldInstances        bool
	UpdateStatus             bool
	UpdateStatusOnShutdown   bool
	UseNodeInternalIP        bool
	ValidateConfig           bool
	VerifyHostname           bool
	VersionInfo              version.Info
	WaitBeforeUpdate         time.Duration
	WatchIngressWithoutClass bool
	WatchNamespace           string
}
