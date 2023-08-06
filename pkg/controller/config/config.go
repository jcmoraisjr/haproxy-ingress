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
	"flag"
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
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gwapiversioned "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/version"
)

// Create ...
func Create() (*Config, error) {
	// controller-runtime already declares --kubeconfig
	kubeconfig := flag.Lookup("kubeconfig")

	apiserverHost := flag.String("apiserver-host", "",
		`The address of the Kubernetes API server to connect to, in the format of
protocol://address:port, e.g., http://localhost:8080. If not specified, the
default value from in cluster discovery or from a provided kubeconfig is used.`)

	localFSPrefix := flag.String("local-filesystem-prefix", "",
		`Defines the prefix of a temporary directory HAProxy Ingress should create and
maintain all the configuration files. Useful for local deployment.`)

	disableAPIWarnings := flag.Bool("disable-api-warnings", false,
		`Disable warnings from the API server.`)

	defaultSvc := flag.String("default-backend-service", "",
		`Service used to serve a 404 page for the default backend. Takes the form
namespace/name. The controller uses the first node port of this Service for the
default backend.`)

	ingressClass := flag.String("ingress-class", "haproxy",
		`Name of the IngressClass to route through this controller.`)

	ingressClassPrecedence := flag.Bool("ingress-class-precedence", false,
		`Defines if IngressClass resource should take precedence over
kubernetes.io/ingress.class annotation if both are defined and conflicting.`)

	reloadStrategy := flag.String("reload-strategy", "reusesocket",
		`Name of the reload strategy. Options are: native or reusesocket`)

	maxOldConfigFiles := flag.Int("max-old-config-files", 0,
		`Maximum number of old HAProxy timestamped config files to retain. Older files
are cleaned up. A value <= 0 indicates only a single non-timestamped config
file will be retained.`)

	validateConfig := flag.Bool("validate-config", false,
		`Define if the resulting configuration files should be validated when a dynamic
update was applied. Default value is false, which means the validation will
only happen when HAProxy needs to be reloaded. If validation fails, HAProxy
Ingress will log the error and set the metric 'haproxyingress_update_success'
as failed (zero)`)

	controllerClass := flag.String("controller-class", "",
		`Defines an alternative controller name this controller should listen to. If
empty, this controller will listen to ingress resources whose controller's
IngressClass is 'haproxy-ingress.github.io/controller'. Non-empty values add a
new /path, e.g., controller-class=staging will make this controller look for
'haproxy-ingress.github.io/controller/staging'`)

	watchIngressWithoutClass := flag.Bool("watch-ingress-without-class", false,
		`Defines if this controller should also listen to ingress resources that don't
declare neither the kubernetes.io/ingress.class annotation nor the
<ingress>.spec.ingressClassName field. Defaults to false`)

	watchGateway := flag.Bool("watch-gateway", true,
		`Watch and parse resources from the Gateway API`)

	masterWorker := flag.Bool("master-worker", false,
		`Defines if haproxy should be configured in master-worker mode. If 'false', one
single process is forked in the background. If 'true', a master process is
started in the foreground and can be used to manage current and old worker
processes.`)

	masterSocket := flag.String("master-socket", "",
		`Defines the master CLI unix socket of an external HAProxy running in
master-worker mode. Defaults to use the embedded HAProxy if not declared.`)

	configMap := flag.String("configmap", "",
		`Name of the ConfigMap that contains the custom configuration to use`)

	acmeServer := flag.Bool("acme-server", false,
		`Enables ACME server. This server is used to receive and answer challenges from
Let's Encrypt or other ACME implementations.`)

	acmeCheckPeriod := flag.Duration("acme-check-period", 24*time.Hour,
		`Time between checks of invalid or expiring certificates`)

	acmeFailInitialDuration := flag.Duration("acme-fail-initial-duration", 5*time.Minute,
		`The initial time to wait to retry sign a new certificate after a failure. The
time between retries will grow exponentially until 'acme-fail-max-duration'`)

	acmeFailMaxDuration := flag.Duration("acme-fail-max-duration", 8*time.Hour,
		`The maximum time to wait after failing to sign a new certificate`)

	acmeSecretKeyName := flag.String("acme-secret-key-name", "acme-private-key",
		`Name and an optional namespace of the secret which will store the acme account
private key. If a namespace is not provided, the secret will be created in the
same namespace of the controller pod`)

	acmeTokenConfigMapName := flag.String("acme-token-configmap-name", "acme-validation-tokens",
		`Name and an optional namespace of the configmap which will store acme tokens
used to answer the acme challenges. If a namespace is not provided, the secret
will be created in the same namespace of the controller pod`)

	acmeTrackTLSAnn := flag.Bool("acme-track-tls-annotation", false,
		`Enable tracking of ingress objects annotated with 'kubernetes.io/tls-acme'`)

	bucketsResponseTime := flagFloat64("buckets-response-time", []float64{.0005, .001, .002, .005, .01},
		`Configures the buckets of the histogram used to compute the response time of
the haproxy's admin socket. The response time unit is in seconds.`)

	publishSvc := flag.String("publish-service", "",
		`Service fronting the ingress controllers. Takes the form namespace/name. The
controller will set the endpoint records on the ingress objects to reflect
those on the service.`)

	publishAddress := flag.String("publish-address", "",
		`Comma separated list of hostname/IP addresses that should be used to configure
ingress status. This option cannot be used if --publish-service is configured`)

	tcpConfigMapName := flag.String("tcp-services-configmap", "",
		`Name of the ConfigMap that contains the definition of the TCP services to
expose. The key in the map indicates the external port to be used. The value is
the name of the service with the format namespace/serviceName and the port of
the service could be a number of the name of the port. The ports 80 and 443 are
not allowed as external ports. This ports are reserved for the backend`)

	annPrefix := flag.String("annotations-prefix", "haproxy-ingress.github.io,ingress.kubernetes.io",
		`Defines a comma-separated list of annotation prefix for ingress and service`)

	rateLimitUpdate := flag.Float64("rate-limit-update", 0.5,
		`Maximum of updates per second this controller should perform. Default is 0.5,
which means wait 2 seconds between Ingress updates in order to add more changes
in a single reload`)

	reloadInterval := flag.Duration("reload-interval", 0,
		`Minimal time between two consecutive HAProxy reloads. The default value is 0,
which means to always reload HAProxy just after a configuration change enforces
a reload. The interval should be configured with a time suffix, eg 30s means
that if two distinct and consecutive configuration changes enforce a reload,
the second reload will be enqueued until 30 seconds have passed from the first
one, applying every new configuration changes made between this interval`)

	waitBeforeUpdate := flag.Duration("wait-before-update", 200*time.Millisecond,
		`Amount of time to wait before start a reconciliation and update haproxy, giving
the time to receive all/most of the changes of a batch update.`)

	resyncPeriod := flag.Duration("sync-period", 10*time.Hour,
		`Configures the default resync period of Kubernetes' informer factory.`)

	watchNamespace := flag.String("watch-namespace", v1.NamespaceAll,
		`Namespace to watch for Ingress. Default is to watch all namespaces`)

	statsCollectProcPeriod := flag.Duration("stats-collect-processing-period", 500*time.Millisecond,
		`Defines the interval between two consecutive readings of haproxy's Idle_pct.
haproxy updates Idle_pct every 500ms, which makes that the best configuration
value. Change to 0 (zero) to disable this metric.`)

	healthzAddr := flag.String("healthz-addr", ":10254",
		`The address the healthz service should bind to. Configure with an empty string
to disable it`)

	healthzURL := flag.String("health-check-path", "/healthz",
		`Defines the URL to be used as health check.`)

	readyzURL := flag.String("ready-check-path", "/readyz",
		`Defines the URL to be used as readyness check.`)

	profiling := flag.Bool("profiling", true,
		`Enable profiling via web interface host:healthzport/debug/pprof/`)

	stopHandler := flag.Bool("stop-handler", false,
		`Allows to stop the controller via a POST request to host:healthzport/stop
endpoint`)

	defSSLCertificate := flag.String("default-ssl-certificate", "",
		`Name of the secret that contains a SSL certificate to be used as
default for a HTTPS catch-all server`)

	verifyHostname := flag.Bool("verify-hostname", true,
		`Defines if the controller should verify if the provided certificate is valid,
ie, it's SAN extension has the hostname.`)

	updateStatus := flag.Bool("update-status", true,
		`Indicates if the controller should update the 'status' attribute of all the
Ingress resources that this controller is tracking.`)

	electionID := flag.String("election-id", "fc5ae9f3.haproxy-ingress.github.io",
		`Election id to be used for status update and certificate sign.`)

	waitBeforeShutdown := flag.String("wait-before-shutdown", "",
		`Defines the amount of time the controller should wait between receiving a
SIGINT or SIGTERM signal, and notifying the controller manager to gracefully
stops the controller. Use with a time suffix.`)

	shutdownTimeout := flag.Duration("shutdown-timeout", 25*time.Second,
		`Defines the amount of time the controller should wait, after receiving a
SIGINT or a SIGTERM, for all of its internal services to gracefully stop before
shutting down the process. It starts to count after --wait-before-shutdown has
been passed, if configured.`)

	allowCrossNamespace := flag.Bool("allow-cross-namespace", false,
		`Defines if the ingress controller can reference resources of another
namespaces. Cannot be used if force-namespace-isolation is true`)

	disableExternalName := flag.Bool("disable-external-name", false,
		`Disables services of type ExternalName`)

	disableConfigKeywords := flag.String("disable-config-keywords", "",
		`Defines a comma-separated list of HAProxy keywords that should not be used on
annotation based configuration snippets. Configuration snippets added as a
global config does not follow this option. Use an asterisk * to disable
configuration snippets using annotations.`)

	updateStatusOnShutdown := flag.Bool("update-status-on-shutdown", true,
		`Indicates if the ingress controller should update the Ingress status
IP/hostname when the controller is being stopped.`)

	backendShards := flag.Int("backend-shards", 0,
		`Defines how much files should be used to configure the haproxy backends`)

	sortBackends := flag.Bool("sort-backends", false,
		`Defines if backend's endpoints should be sorted by name. This option has less
precedence than --sort-endpoints-by if both are declared.`)

	sortEndpointsBy := flag.String("sort-endpoints-by", "",
		`Defines how to sort backend's endpoints. Allowed values are: 'endpoint' - same
k8s endpoint order (default); 'name' - server/endpoint name;
'ip' - server/endpoint IP and port; 'random' - shuffle endpoints on every
haproxy reload`)

	trackOldInstances := flag.Bool("track-old-instances", false,
		`Creates an internal list of connections to old HAProxy instances. These
connections are used to read or send data to stopping instances, which is
usually serving long lived connections like TCP services or websockets.`)

	useNodeInternalIP := flag.Bool("report-node-internal-ip-address", false,
		`Defines if the nodes IP address to be returned in the ingress status should be
the internal instead of the external IP address`)

	enableEndpointSlicesAPI := flag.Bool("enable-endpointslices-api", false,
		`Enables EndpointSlices API and disables watching Endpoints API. Only enable in
k8s >=1.21+`)

	logZap := flag.Bool("log-zap", false,
		`Enables zap as the log sink for all the logging outputs.`)

	logDev := flag.Bool("log-dev", false,
		`Defines if development style logging should be used. Needs --log-zap enabled.`)

	logCaller := flag.Bool("log-caller", false,
		`Defines if the log output should add a reference of the caller with file name
and line number. Needs --log-zap enabled.`)

	logLevel := flag.Int("v", 2,
		`Number for the log level verbosity. 1: info; 2: add low verbosity debug.`)

	logEnableStacktrace := flag.Bool("log-enable-stacktrace", false,
		`Defines if error output should add stracktraces. Needs --log-zap enabled.`)

	logEncoder := flag.String("log-encoder", "",
		`Defines the log encoder. Options are: 'console' or 'json'. Defaults to 'json' if
--log-dev is false and 'console' if --log-dev is true. Needs --log-zap enabled.`)

	logEncodeTime := flag.String("log-encode-time", "",
		`Configures the encode time used in the logs. Options are: rfc3339nano, rfc3339,
iso8601, millis, nanos. Defaults to 'rfc3339nano' if --log-dev is false and
'iso8601' if --log-dev is true. Needs --log-zap enabled.`)

	//
	// Deprecated options
	//

	acmeElectionID := flag.String("acme-election-id", "",
		`DEPRECATED: acme and status update leader uses the same ID from --election-id
command-line option.`)

	healthzPort := flag.Int("healthz-port", 0,
		`DEPRECATED: Use --healthz-addr instead.`)

	disableNodeList := flag.Bool("disable-node-list", false,
		`DEPRECATED: This flag used to disable node listing due to missing permissions.
Actually node listing isn't needed and it is always disabled`)

	disablePodList := flag.Bool("disable-pod-list", false,
		`DEPRECATED: used to define if HAProxy Ingress should disable pod watch and in
memory list. This configuration is now ignored, the controller-runtime takes
care of it.`)

	forceIsolation := flag.Bool("force-namespace-isolation", false,
		`DEPRECATED: this flag used to enforce that one namespace cannot read secrets
and services from other namespaces, actually implemented by
allow-cross-namespace command line option and cross-namespace configuration
keys.`)

	ignoreIngressWithoutClass := flag.Bool("ignore-ingress-without-class", false,
		`DEPRECATED: Use --watch-ingress-without-class command-line option instead to
define if ingress without class should be tracked.`)

	//

	showVersion := flag.Bool("version", false,
		`Shows release information about the Ingress controller`)

	flag.Parse()

	versionInfo := version.Info{
		Name:       version.NAME,
		Release:    version.RELEASE,
		Build:      version.COMMIT,
		Repository: version.REPO,
	}

	if *showVersion {
		fmt.Printf("%#v\n", versionInfo)
		os.Exit(0)
	}

	if !*logZap {
		if *logDev || *logCaller || *logEnableStacktrace || *logEncoder != "" || *logEncodeTime != "" {
			klog.Exit("--log-dev, --log-caller, --log-enable-stacktrace --log-encoder and --log-encode-time are only supported if --log-zap is enabled.")
		}
		var level klog.Level
		level.Set(strconv.Itoa(*logLevel - 1))
		ctrl.SetLogger(klog.NewKlogr())
	} else {
		logger := newZapLogger(*logDev, *logLevel, *logCaller, *logEnableStacktrace, *logEncoder, *logEncodeTime)
		ctrl.SetLogger(logger)
		klog.SetLogger(logger)
	}

	rootLogger := ctrl.Log
	configLog := rootLogger.WithName("config")

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1alpha2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1beta1.AddToScheme(scheme))

	var kubeConfig *rest.Config
	if *apiserverHost == "" {
		var err error
		kubeConfig, err = ctrl.GetConfig()
		if err != nil {
			return nil, err
		}
	} else {
		kubeConfigFile := kubeconfig.Value.String()
		var err error
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigFile},
			&clientcmd.ConfigOverrides{
				ClusterInfo: clientcmdapi.Cluster{
					Server: *apiserverHost,
				},
			}).ClientConfig()
		if err != nil {
			return nil, err
		}
	}
	if *disableAPIWarnings {
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

	if *acmeElectionID != "" {
		configLog.Info("DEPRECATED: --acme-election-id is ignored, acme and status update leader uses the same ID from --election-id command-line option.")
	}
	if *healthzPort > 0 {
		configLog.Info(fmt.Sprintf("DEPRECATED: --healthz-addr=:%d should be used instead", *healthzPort))
	}
	if *ignoreIngressWithoutClass {
		configLog.Info("DEPRECATED: --ignore-ingress-without-class is now ignored and can be safely removed")
	}
	if *disableNodeList {
		configLog.Info("DEPRECATED: --disable-node-list is now ignored and can be safely removed")
	}
	if *disablePodList {
		configLog.Info("DEPRECATED: --disable-pod-list is ignored, controller-runtime automatically configures this option.")
	}
	if *forceIsolation {
		configLog.Info("DEPRECATED: --force-namespace-isolation is ignored, use allow-cross-namespace command-line options or cross-namespace configuration keys instead.")
	}

	if *ingressClass != "" {
		configLog.Info("watching for ingress resources with 'kubernetes.io/ingress.class'", "annotation", *ingressClass)
	}

	var waitShutdown time.Duration
	if *waitBeforeShutdown != "" {
		var err error
		waitShutdown, err = time.ParseDuration(*waitBeforeShutdown)
		if err != nil {
			waitInt, err := strconv.Atoi(*waitBeforeShutdown)
			if err != nil {
				return nil, fmt.Errorf("--wait-before-shutdown='%s' is neither a valid int (seconds) nor a valid duration", *waitBeforeShutdown)
			}
			configLog.Info(fmt.Sprintf("DEPRECATED: --wait-before-shutdown=%s is missing a time suffix", *waitBeforeShutdown))
			waitShutdown = time.Duration(waitInt) * time.Second
		}
	}

	ctx := logr.NewContext(createRootContext(rootLogger, waitShutdown), rootLogger)

	controllerName := "haproxy-ingress.github.io/controller"
	if *controllerClass != "" {
		controllerName += "/" + strings.TrimLeft(*controllerClass, "/")
	}
	configLog.Info("watching for ingress resources with IngressClass", "controller-name", controllerName)

	if *watchIngressWithoutClass {
		configLog.Info("watching for ingress resources without any class reference - --watch-ingress-without-class is true")
	} else {
		configLog.Info("ignoring ingress resources without any class reference - --watch-ingress-without-class is false")
	}

	if *watchGateway {
		configLog.Info("watching for Gateway API resources - --watch-gateway is true")
	}

	hasGatewayA2 := *watchGateway && configHasAPI(
		clientGateway.Discovery(),
		gatewayv1alpha2.GroupVersion,
		"gatewayclass", "gateway", "httproute")
	if hasGatewayA2 {
		configLog.Info("found custom resource definition for gateway API v1alpha2")
	}
	hasGatewayB1 := *watchGateway && configHasAPI(
		clientGateway.Discovery(),
		gatewayv1beta1.GroupVersion,
		"gatewayclass", "gateway", "httproute")
	if hasGatewayB1 {
		configLog.Info("found custom resource definition for gateway API v1beta1")
	}

	if *enableEndpointSlicesAPI {
		configLog.Info("watching endpointslices - --enable-endpointslices-api is true")
	}

	if *publishSvc != "" && *publishAddress != "" {
		return nil, fmt.Errorf("configure only one of --publish-service or --publish-address")
	}

	var publishAddressHostnames, publishAddressIPs []string
	for _, addr := range strings.Split(*publishAddress, ",") {
		if addr == "" {
			continue
		}
		if net.ParseIP(addr) == nil {
			publishAddressHostnames = append(publishAddressHostnames, addr)
		} else {
			publishAddressIPs = append(publishAddressIPs, addr)
		}
	}

	podNamespace := os.Getenv("POD_NAMESPACE")
	podName := os.Getenv("POD_NAME")

	// we could `|| hasGateway[version...]` instead of `|| *watchGateway` here,
	// but we're choosing a consistent startup behavior despite of the cluster configuration.
	election := *updateStatus || *acmeServer || *watchGateway
	if election && podNamespace == "" {
		return nil, fmt.Errorf("POD_NAMESPACE envvar should be configured when --update-status=true, --acme-server=true, or --watch-gateway=true")
	}

	if *updateStatus && podName == "" && *publishSvc == "" && len(publishAddressHostnames)+len(publishAddressIPs) == 0 {
		return nil, fmt.Errorf("one of --publish-service, --publish-address or POD_NAME envvar should be configured when --update-status=true")
	}

	acmeSecretKeyNamespaceName := *acmeSecretKeyName
	if !strings.Contains(acmeSecretKeyNamespaceName, "/") {
		acmeSecretKeyNamespaceName = podNamespace + "/" + acmeSecretKeyNamespaceName
	}
	acmeTokenConfigMapNamespaceName := *acmeTokenConfigMapName
	if !strings.Contains(acmeTokenConfigMapNamespaceName, "/") {
		acmeTokenConfigMapNamespaceName = podNamespace + "/" + acmeTokenConfigMapNamespaceName
	}

	masterWorkerCfg := *masterWorker
	if !masterWorkerCfg && *masterSocket != "" {
		// TODO Change to FATAL when default masterWorker changes to true
		configLog.Info("WARN: changing --master-worker=true due to external haproxy configuration")
		masterWorkerCfg = true
	}
	if *masterSocket != "" {
		configLog.Info("running external haproxy", "master-unix-socket", *masterSocket)
	} else if masterWorkerCfg {
		configLog.Info("running embedded haproxy", "mode", "master-worker")
	} else {
		configLog.Info("running embedded haproxy", "mode", "daemon")
	}

	if !(*reloadStrategy == "native" || *reloadStrategy == "reusesocket" || *reloadStrategy == "multibinder") {
		return nil, fmt.Errorf("Unsupported reload strategy: %s", *reloadStrategy)
	}
	if *reloadStrategy == "multibinder" {
		configLog.Info("WARN: multibinder is deprecated, using reusesocket strategy instead. update your deployment configuration")
	}

	if *configMap != "" {
		ns, name, err := cache.SplitMetaNamespaceKey(*configMap)
		if err != nil {
			return nil, fmt.Errorf("invalid format for global ConfigMap '%s': %w", *configMap, err)
		}
		_, err = client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error reading global ConfigMap '%s': %w", *configMap, err)
		}
		configLog.Info("watching for global config options - --configmap was defined", "configmap", *configMap)
	}

	if *defaultSvc != "" {
		ns, name, err := cache.SplitMetaNamespaceKey(*defaultSvc)
		if err != nil {
			return nil, fmt.Errorf("invalid format for service '%s': %w", *defaultSvc, err)
		}
		_, err = client.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if errors.IsForbidden(err) {
				return nil, fmt.Errorf("it seems the cluster is running with Authorization enabled (like RBAC) and there is no permissions for the ingress controller. Please check the configuration")
			}
			return nil, fmt.Errorf("no service with name '%s' found: %w", *defaultSvc, err)
		}
		configLog.Info("using default backend", "service", *defaultSvc)
	}

	if *publishSvc != "" {
		ns, name, err := cache.SplitMetaNamespaceKey(*publishSvc)
		if err != nil {
			return nil, fmt.Errorf("invalid service format: %w", err)
		}
		svc, err := client.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting information about service '%s': %w", *publishSvc, err)
		}
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			if len(svc.Spec.ExternalIPs) == 0 {
				return nil, fmt.Errorf("service '%s' does not (yet) have ingress points", *publishSvc)
			}
			configLog.Info("service validated as assigned with externalIP", "service", *publishSvc)
		} else {
			configLog.Info("service validated as source of Ingress status", "service", *publishSvc)
		}
	}

	if *watchNamespace != "" {
		_, err := client.NetworkingV1().Ingresses(*watchNamespace).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			return nil, fmt.Errorf("no watchNamespace with name '%s' found: %w", *watchNamespace, err)
		}
	} else {
		_, err := client.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error connecting to the apiserver: %w", err)
		}
	}

	if *rateLimitUpdate < 0.05 {
		return nil, fmt.Errorf(
			"rate limit update (%v) is too low: '%v' seconds between Ingress reloads. Use at least 0.05, which means 20 seconds between updates",
			*rateLimitUpdate, 1.0 / *rateLimitUpdate)
	}

	if *rateLimitUpdate > 10 {
		return nil, fmt.Errorf(
			"rate limit update is too high: up to '%v' Ingress updates per second (max is 10)",
			*rateLimitUpdate)
	}

	if resyncPeriod.Seconds() < 10 {
		return nil, fmt.Errorf("resync period (%vs) is too low", resyncPeriod.Seconds())
	}

	if *watchNamespace != v1.NamespaceAll && *allowCrossNamespace {
		return nil, fmt.Errorf("Cannot use --watch-namespace if --force-namespace-isolation is true")
	}

	var annPrefixList []string
	for _, prefix := range strings.Split(*annPrefix, ",") {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			annPrefixList = append(annPrefixList, prefix)
		}
	}
	switch len(annPrefixList) {
	case 0:
		return nil, fmt.Errorf("At least one annotation prefix should be configured")
	case 1:
		configLog.Info("using annotations prefix", "prefix", annPrefixList[0])
	default:
		configLog.Info(
			fmt.Sprintf("using %d distinct annotations prefix", len(annPrefixList)),
			"precedence", strings.Join(annPrefixList, ", "))
	}

	sortEndpoints := strings.ToLower(*sortEndpointsBy)
	if sortEndpoints == "" {
		if *sortBackends {
			sortEndpoints = "name"
		} else {
			sortEndpoints = "endpoint"
		}
	}
	if !regexp.MustCompile(`^(ep|endpoint|ip|name|random)$`).MatchString(sortEndpoints) {
		return nil, fmt.Errorf("Unsupported --sort-endpoint-by option: %s", sortEndpoints)
	}

	defaultDirCerts := "/var/lib/haproxy/crt"
	defaultDirCACerts := "/var/lib/haproxy/cacerts"
	defaultDirCrl := "/var/lib/haproxy/crl"
	defaultDirDHParam := "/var/lib/haproxy/dhparam"
	defaultDirVarRun := "/var/run/haproxy"
	defaultDirMaps := "/etc/haproxy/maps"
	// defaultDirErrorfiles := "/etc/haproxy/errorfiles"
	// defaultDirLuaScripts := "/etc/haproxy/lua"

	for _, dir := range []*string{
		&defaultDirCerts,
		&defaultDirCACerts,
		&defaultDirCrl,
		&defaultDirDHParam,
		&defaultDirVarRun,
		&defaultDirMaps,
		// &defaultDirErrorfiles,
		// &defaultDirLuaScripts,
	} {
		*dir = *localFSPrefix + *dir
		if err := os.MkdirAll(*dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to 'mkdir %s': %w", *dir, err)
		}
	}

	disableKeywords := utils.Split(*disableConfigKeywords, ",")
	var healthz string
	if *healthzPort > 0 {
		healthz = fmt.Sprintf(":%d", *healthzPort)
	} else {
		healthz = *healthzAddr
	}

	return &Config{
		AcmeCheckPeriod:          *acmeCheckPeriod,
		AcmeFailInitialDuration:  *acmeFailInitialDuration,
		AcmeFailMaxDuration:      *acmeFailMaxDuration,
		AcmeSecretKeyName:        acmeSecretKeyNamespaceName,
		AcmeServer:               *acmeServer,
		AcmeTokenConfigMapName:   acmeTokenConfigMapNamespaceName,
		AcmeTrackTLSAnn:          *acmeTrackTLSAnn,
		AllowCrossNamespace:      *allowCrossNamespace,
		AnnPrefix:                annPrefixList,
		BackendShards:            *backendShards,
		BucketsResponseTime:      *bucketsResponseTime,
		ConfigMapName:            *configMap,
		ControllerName:           controllerName,
		DefaultDirCACerts:        defaultDirCACerts,
		DefaultDirCerts:          defaultDirCerts,
		DefaultDirCrl:            defaultDirCrl,
		DefaultDirDHParam:        defaultDirDHParam,
		DefaultDirMaps:           defaultDirMaps,
		DefaultDirVarRun:         defaultDirVarRun,
		DefaultService:           *defaultSvc,
		DefaultSSLCertificate:    *defSSLCertificate,
		DisableExternalName:      *disableExternalName,
		DisableKeywords:          disableKeywords,
		Election:                 election,
		ElectionID:               *electionID,
		ElectionNamespace:        podNamespace,
		EnableEndpointSliceAPI:   *enableEndpointSlicesAPI,
		ForceNamespaceIsolation:  *forceIsolation,
		HasGatewayA2:             hasGatewayA2,
		HasGatewayB1:             hasGatewayB1,
		HealthzAddr:              healthz,
		HealthzURL:               *healthzURL,
		IngressClass:             *ingressClass,
		IngressClassPrecedence:   *ingressClassPrecedence,
		KubeConfig:               kubeConfig,
		LocalFSPrefix:            *localFSPrefix,
		MasterSocket:             *masterSocket,
		MasterWorker:             masterWorkerCfg,
		MaxOldConfigFiles:        *maxOldConfigFiles,
		PodName:                  podName,
		PodNamespace:             podNamespace,
		Profiling:                *profiling,
		PublishAddressHostnames:  publishAddressHostnames,
		PublishAddressIPs:        publishAddressIPs,
		PublishService:           *publishSvc,
		RateLimitUpdate:          *rateLimitUpdate,
		ReadyzURL:                *readyzURL,
		ReloadInterval:           *reloadInterval,
		ReloadStrategy:           *reloadStrategy,
		ResyncPeriod:             resyncPeriod,
		RootContext:              ctx,
		Scheme:                   scheme,
		ShutdownTimeout:          shutdownTimeout,
		SortEndpointsBy:          sortEndpoints,
		StatsCollectProcPeriod:   *statsCollectProcPeriod,
		StopHandler:              *stopHandler,
		TCPConfigMapName:         *tcpConfigMapName,
		TrackOldInstances:        *trackOldInstances,
		UpdateStatus:             *updateStatus,
		UpdateStatusOnShutdown:   *updateStatusOnShutdown,
		UseNodeInternalIP:        *useNodeInternalIP,
		ValidateConfig:           *validateConfig,
		VerifyHostname:           *verifyHostname,
		VersionInfo:              versionInfo,
		WaitBeforeUpdate:         *waitBeforeUpdate,
		WatchIngressWithoutClass: *watchIngressWithoutClass,
		WatchNamespace:           *watchNamespace,
	}, nil
}

func newZapLogger(logDev bool, logLevel int, logCaller, logEnableStacktrace bool, logEncoder, logEncodeTime string) logr.Logger {
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
		klog.Exitf("invalid encode name: %s", logEncoder)
	}

	klogEncoderName := "klog"
	if err := zap.RegisterEncoder(klogEncoderName, func(ec zapcore.EncoderConfig) (zapcore.Encoder, error) {
		return klogEncoder{baseEncoder(ec)}, nil
	}); err != nil {
		klog.Exitf("error registering log encoder: %v", err)
	}

	zc.Encoding = klogEncoderName
	zc.Level = zap.NewAtomicLevelAt(zapcore.Level(1 - logLevel))
	zc.DisableStacktrace = !logEnableStacktrace
	zc.EncoderConfig.EncodeTime.UnmarshalText([]byte(encodeTime))

	zl, err := zc.Build(
		zap.WithCaller(logCaller),
		zap.AddCallerSkip(0),
	)
	if err != nil {
		klog.Exitf("error configuring zap logger: %v", err)
	}
	return zapr.NewLogger(zl)
}

type klogEncoder struct {
	zapcore.Encoder
}

func (e klogEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	// klog always add a hardcoded line break that mess the zap output
	entry.Message = strings.TrimRight(entry.Message, "\n")
	return e.Encoder.EncodeEntry(entry, fields)
}

func createRootContext(rootLogger logr.Logger, waitShutdown time.Duration) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 3)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
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

type float64SliceValue []float64

func flagFloat64(name string, value []float64, usage string) *float64SliceValue {
	p := new(float64SliceValue)
	*p = value
	flag.Var(p, name, usage)
	return p
}

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
	Election                 bool
	ElectionID               string
	ElectionNamespace        string
	EnableEndpointSliceAPI   bool
	ForceNamespaceIsolation  bool
	HasGatewayA2             bool
	HasGatewayB1             bool
	HealthzAddr              string
	HealthzURL               string
	IngressClass             string
	IngressClassPrecedence   bool
	KubeConfig               *rest.Config
	LocalFSPrefix            string
	MasterSocket             string
	MasterWorker             bool
	MaxOldConfigFiles        int
	PodName                  string
	PodNamespace             string
	Profiling                bool
	PublishAddressHostnames  []string
	PublishAddressIPs        []string
	PublishService           string
	RateLimitUpdate          float64
	ReadyzURL                string
	ReloadInterval           time.Duration
	ReloadStrategy           string
	ResyncPeriod             *time.Duration
	RootContext              context.Context
	Scheme                   *runtime.Scheme
	ShutdownTimeout          *time.Duration
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
