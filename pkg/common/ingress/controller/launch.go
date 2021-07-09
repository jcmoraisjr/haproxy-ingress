package controller

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/k8s"
)

// NewIngressController returns a configured Ingress controller
func NewIngressController(backend ingress.Controller) *GenericController {
	var (
		flags = pflag.NewFlagSet("", pflag.ExitOnError)

		apiserverHost = flags.String("apiserver-host", "", "The address of the Kubernetes Apiserver "+
			"to connect to in the format of protocol://address:port, e.g., "+
			"http://localhost:8080. If not specified, the assumption is that the binary runs inside a "+
			"Kubernetes cluster and local discovery is attempted.")
		kubeConfigFile = flags.String("kubeconfig", "", "Path to kubeconfig file with authorization and master location information.")

		defaultSvc = flags.String("default-backend-service", "",
			`Service used to serve a 404 page for the default backend. Takes the form
    	namespace/name. The controller uses the first node port of this Service for
    	the default backend.`)

		ingressClass = flags.String("ingress-class", "",
			`Name of the ingress class to route through this controller.`)

		configMap = flags.String("configmap", "",
			`Name of the ConfigMap that contains the custom configuration to use`)

		acmeServer = flags.Bool("acme-server", false,
			`Enables acme server. This server is used to receive and answer challenges from
		Lets Encrypt or other acme implementations.`)

		acmeCheckPeriod = flags.Duration("acme-check-period", 24*time.Hour,
			`Time between checks of invalid or expiring certificates`)

		acmeElectionID = flags.String("acme-election-id", "acme-leader",
			`Prefix of the election ID used to choose the acme leader`)

		acmeFailInitialDuration = flags.Duration("acme-fail-initial-duration", 5*time.Minute,
			`The initial time to wait to retry sign a new certificate after a failure.
		The time between retries will grow exponentially until 'acme-fail-max-duration'`)

		acmeFailMaxDuration = flags.Duration("acme-fail-max-duration", 8*time.Hour,
			`The maximum time to wait after failing to sign a new certificate`)

		acmeSecretKeyName = flags.String("acme-secret-key-name", "acme-private-key",
			`Name and an optional namespace of the secret which will store the acme account
		private key. If a namespace is not provided, the secret will be created in the same
		namespace of the controller pod`)

		acmeTokenConfigmapName = flags.String("acme-token-configmap-name", "acme-validation-tokens",
			`Name and an optional namespace of the configmap which will store acme tokens
		used to answer the acme challenges. If a namespace is not provided, the secret will be created
		in the same namespace of the controller pod`)

		acmeTrackTLSAnn = flags.Bool("acme-track-tls-annotation", false,
			`Enable tracking of ingress objects annotated with 'kubernetes.io/tls-acme'`)

		bucketsResponseTime = flags.Float64Slice("buckets-response-time",
			[]float64{.0005, .001, .002, .005, .01},
			`Configures the buckets of the histogram used to compute the response time of the haproxy's admin socket.
		The response time unit is in seconds.`)

		publishSvc = flags.String("publish-service", "",
			`Service fronting the ingress controllers. Takes the form
 		namespace/name. The controller will set the endpoint records on the
 		ingress objects to reflect those on the service.`)

		tcpConfigMapName = flags.String("tcp-services-configmap", "",
			`Name of the ConfigMap that contains the definition of the TCP services to expose.
		The key in the map indicates the external port to be used. The value is the name of the
		service with the format namespace/serviceName and the port of the service could be a
		number of the name of the port.
		The ports 80 and 443 are not allowed as external ports. This ports are reserved for the backend`)

		annPrefix = flags.String("annotations-prefix", "ingress.kubernetes.io",
			`Defines the prefix of ingress and service annotations`)

		rateLimitUpdate = flags.Float32("rate-limit-update", 0.5,
			`Maximum of updates per second this controller should perform.
		Default is 0.5, which means wait 2 seconds between Ingress updates in order
		to add more changes in a single reload`)

		waitBeforeUpdate = flags.Duration("wait-before-update", 200*time.Millisecond,
			`Amount of time to wait before start a reconciliation and update haproxy,
		giving the time to receive all/most of the changes of a batch update.`)

		resyncPeriod = flags.Duration("sync-period", 600*time.Second,
			`Relist and confirm cloud resources this often. Default is 10 minutes`)

		watchNamespace = flags.String("watch-namespace", apiv1.NamespaceAll,
			`Namespace to watch for Ingress. Default is to watch all namespaces`)

		healthzPort = flags.Int("healthz-port", 10254, "port for healthz endpoint.")

		statsCollectProcPeriod = flags.Duration("stats-collect-processing-period", 500*time.Millisecond,
			`Defines the interval between two consecutive readings of haproxy's Idle_pct. haproxy
		updates Idle_pct every 500ms, which makes that the best configuration value.
		Change to 0 (zero) to disable this metric.`)

		profiling = flags.Bool("profiling", true, `Enable profiling via web interface host:port/debug/pprof/`)

		defSSLCertificate = flags.String("default-ssl-certificate", "", `Name of the secret
		that contains a SSL certificate to be used as default for a HTTPS catch-all server`)

		verifyHostname = flags.Bool("verify-hostname", true,
			`Defines if the controller should verify if the provided certificate is valid, ie, it's
		SAN extension has the hostname. Default is true`)

		defHealthzURL = flags.String("health-check-path", "/healthz", `Defines
		the URL to be used as health check inside in the default server.`)

		updateStatus = flags.Bool("update-status", true, `Indicates if the
		ingress controller should update the Ingress status IP/hostname. Default is true`)

		electionID = flags.String("election-id", "ingress-controller-leader", `Election id to use for status update.`)

		forceIsolation = flags.Bool("force-namespace-isolation", false,
			`Force namespace isolation. This flag is required to avoid the reference of secrets,
		configmaps or the default backend service located in a different namespace than the specified
		in the flag --watch-namespace.`)

		waitBeforeShutdown = flags.Int("wait-before-shutdown", 0, `Define time controller waits until it shuts down
		when SIGTERM signal was received`)

		allowCrossNamespace = flags.Bool("allow-cross-namespace", false,
			`Defines if the ingress controller can reference resources of another namespaces.
		Cannot be used if force-namespace-isolation is true`)

		disableNodeList = flags.Bool("disable-node-list", false,
			`Disable querying nodes. If --force-namespace-isolation is true, this should also be set.`)

		disablePodList = flags.Bool("disable-pod-list", false,
			`Defines if HAProxy Ingress should disable pod watch and in memory list. Pod list is
		mandatory for drain-support (should not be disabled) and optional for blue/green.`)

		disableExternalName = flags.Bool("disable-external-name", false,
			`Disables services of type ExternalName`)

		disableConfigKeywords = flags.String("disable-config-keywords", "",
			`Defines a comma-separated list of HAProxy keywords that should not be used on
annotation based configuration snippets. Configuration snippets added as a
global config does not follow this option. Use an asterisk * to disable
configuration snippets using annotations.`)

		updateStatusOnShutdown = flags.Bool("update-status-on-shutdown", true, `Indicates if the
		ingress controller should update the Ingress status IP/hostname when the controller
		is being stopped. Default is true`)

		backendShards = flags.Int("backend-shards", 0,
			`Defines how much files should be used to configure the haproxy backends`)

		sortBackends = flags.Bool("sort-backends", false,
			`Defines if backend's endpoints should be sorted by name. This option has less precedence than
		--sort-endpoints-by if both are declared.`)

		sortEndpointsBy = flags.String("sort-endpoints-by", "",
			`Defines how to sort backend's endpoints. Allowed values are: 'endpoint' - same k8s endpoint order (default);
		'name' - server/endpoint name; 'ip' - server/endpoint IP and port; 'random' - shuffle endpoints on every haproxy reload`)

		useNodeInternalIP = flags.Bool("report-node-internal-ip-address", false,
			`Defines if the nodes IP address to be returned in the ingress status should be the internal instead of the external IP address`)

		showVersion = flags.Bool("version", false,
			`Shows release information about the Ingress controller`)

		ignoreIngressWithoutClass = flags.Bool("ignore-ingress-without-class", false,
			`Defines if the ingress without the ingress.class annotation will be considered or not. If true then 
			only the ingresses with the matching ingress.class annotation will be considered, ingresses with missing 
			or different ingress.class annotation will not be considered. Default is false`)
	)

	flags.AddGoFlagSet(flag.CommandLine)
	backend.ConfigureFlags(flags)
	flags.Parse(os.Args)
	// Workaround for this issue:
	// https://github.com/kubernetes/kubernetes/issues/17162
	flag.CommandLine.Parse([]string{})

	if *showVersion {
		fmt.Println(backend.Info().String())
		os.Exit(0)
	}

	backend.OverrideFlags(flags)

	flag.Set("logtostderr", "true")

	glog.Info(backend.Info())

	if *ingressClass != "" {
		glog.Infof("Watching for ingress class: %s", *ingressClass)
	}

	kubeClient, err := createApiserverClient(*apiserverHost, *kubeConfigFile)
	if err != nil {
		handleFatalInitError(err)
	}

	ctx := context.Background()

	if *configMap != "" {
		ns, name, err := k8s.ParseNameNS(*configMap)
		if err != nil {
			glog.Errorf("invalid format for configmap %s: %v", *configMap, err)
		}

		_, err = kubeClient.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			glog.Errorf("error reading configmap '%s': %v", *configMap, err)
		}
		glog.Infof("watching for global config options from configmap '%s' - --configmap was defined", *configMap)
	}

	if *defaultSvc != "" {
		ns, name, err := k8s.ParseNameNS(*defaultSvc)
		if err != nil {
			glog.Fatalf("invalid format for service %v: %v", *defaultSvc, err)
		}

		_, err = kubeClient.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "cannot get services in the namespace") {
				glog.Fatalf("✖ It seems the cluster it is running with Authorization enabled (like RBAC) and there is no permissions for the ingress controller. Please check the configuration")
			}
			glog.Fatalf("no service with name %v found: %v", *defaultSvc, err)
		}
		glog.Infof("validated %v as the default backend", *defaultSvc)
	}

	if *publishSvc != "" {
		ns, name, err := k8s.ParseNameNS(*publishSvc)
		if err != nil {
			glog.Fatalf("invalid service format: %v", err)
		}

		svc, err := kubeClient.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			glog.Fatalf("unexpected error getting information about service %v: %v", *publishSvc, err)
		}

		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			if len(svc.Spec.ExternalIPs) > 0 {
				glog.Infof("service %v validated as assigned with externalIP", *publishSvc)
			} else {
				// We could poll here, but we instead just exit and rely on k8s to restart us
				glog.Fatalf("service %s does not (yet) have ingress points", *publishSvc)
			}
		} else {
			glog.Infof("service %v validated as source of Ingress status", *publishSvc)
		}
	}

	if *watchNamespace != "" {
		_, err = kubeClient.NetworkingV1beta1().Ingresses(*watchNamespace).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			glog.Fatalf("no watchNamespace with name %v found: %v", *watchNamespace, err)
		}
	} else {
		_, err = kubeClient.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
		if err != nil {
			glog.Fatalf("error connecting to the apiserver: %v", err)
		}
	}

	if *rateLimitUpdate <= 0 {
		glog.Fatalf("rate limit must be greater than zero")
	}

	if *rateLimitUpdate < 0.05 {
		glog.Fatalf("rate limit update (%v) is too low: %v seconds between Ingress reloads. Use at least 0.05, which means 20 seconds between reloads",
			*rateLimitUpdate, 1.0 / *rateLimitUpdate)
	}

	if *rateLimitUpdate > 10 {
		glog.Fatalf("rate limit update is too high: up to %v Ingress reloads per second (max is 10)", *rateLimitUpdate)
	}

	if resyncPeriod.Seconds() < 10 {
		glog.Fatalf("resync period (%vs) is too low", resyncPeriod.Seconds())
	}

	for _, dir := range []string{
		ingress.DefaultCrtDirectory,
		ingress.DefaultDHParamDirectory,
		ingress.DefaultCACertsDirectory,
		ingress.DefaultCrlDirectory,
		ingress.DefaultMapsDirectory,
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			glog.Fatalf("Failed to mkdir %s: %v", dir, err)
		}
	}

	if *forceIsolation && *allowCrossNamespace {
		glog.Fatal("Cannot use --allow-cross-namespace if --force-namespace-isolation is true")
	}

	sortEndpoints := strings.ToLower(*sortEndpointsBy)
	if sortEndpoints == "" {
		if *sortBackends {
			sortEndpoints = "name"
		} else {
			sortEndpoints = "endpoint"
		}
	}
	if !stringInSlice(sortEndpoints, []string{"ep", "endpoint", "ip", "name", "random"}) {
		glog.Fatalf("Unsupported --sort-endpoint-by option: %s", sortEndpoints)
	}

	config := &Configuration{
		UpdateStatus:              *updateStatus,
		ElectionID:                *electionID,
		Client:                    kubeClient,
		AcmeServer:                *acmeServer,
		AcmeCheckPeriod:           *acmeCheckPeriod,
		AcmeElectionID:            *acmeElectionID,
		AcmeFailInitialDuration:   *acmeFailInitialDuration,
		AcmeFailMaxDuration:       *acmeFailMaxDuration,
		AcmeSecretKeyName:         *acmeSecretKeyName,
		AcmeTokenConfigmapName:    *acmeTokenConfigmapName,
		AcmeTrackTLSAnn:           *acmeTrackTLSAnn,
		BucketsResponseTime:       *bucketsResponseTime,
		RateLimitUpdate:           *rateLimitUpdate,
		ResyncPeriod:              *resyncPeriod,
		WaitBeforeUpdate:          *waitBeforeUpdate,
		DefaultService:            *defaultSvc,
		IngressClass:              *ingressClass,
		WatchNamespace:            *watchNamespace,
		ConfigMapName:             *configMap,
		TCPConfigMapName:          *tcpConfigMapName,
		AnnPrefix:                 *annPrefix,
		DefaultSSLCertificate:     *defSSLCertificate,
		VerifyHostname:            *verifyHostname,
		DefaultHealthzURL:         *defHealthzURL,
		StatsCollectProcPeriod:    *statsCollectProcPeriod,
		PublishService:            *publishSvc,
		Backend:                   backend,
		ForceNamespaceIsolation:   *forceIsolation,
		WaitBeforeShutdown:        *waitBeforeShutdown,
		AllowCrossNamespace:       *allowCrossNamespace,
		DisableNodeList:           *disableNodeList,
		DisablePodList:            *disablePodList,
		DisableExternalName:       *disableExternalName,
		DisableConfigKeywords:     *disableConfigKeywords,
		UpdateStatusOnShutdown:    *updateStatusOnShutdown,
		BackendShards:             *backendShards,
		SortEndpointsBy:           sortEndpoints,
		UseNodeInternalIP:         *useNodeInternalIP,
		IgnoreIngressWithoutClass: *ignoreIngressWithoutClass,
	}

	ic := newIngressController(config)
	go registerHandlers(*profiling, *healthzPort, ic)
	return ic
}

func registerHandlers(enableProfiling bool, port int, ic *GenericController) {
	mux := http.NewServeMux()
	// expose health check endpoint (/healthz)
	healthz.InstallPathHandler(mux,
		ic.cfg.DefaultHealthzURL,
		healthz.PingHealthz,
		ic.cfg.Backend,
	)

	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/acme/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var out string
		count, err := ic.cfg.Backend.AcmeCheck()
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			out = fmt.Sprintf("Error starting the certificate check: %v.\nSee further information in the controller log.\n", err)
		} else {
			w.WriteHeader(http.StatusOK)
			if count > 0 {
				out = fmt.Sprintf("Acme check successfully started. Added %d certificate(s) in the processing queue.\n", count)
			} else {
				out = fmt.Sprintf("Acme certificate list is empty.\n")
			}
		}
		w.Write([]byte(out))
	})

	mux.HandleFunc("/build", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		b, _ := json.Marshal(ic.Info())
		w.Write(b)
	})

	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		if err != nil {
			glog.Errorf("unexpected error: %v", err)
		}
	})

	if enableProfiling {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%v", port),
		Handler: mux,
	}
	glog.Fatal(server.ListenAndServe())
}

const (
	// High enough QPS to fit all expected use cases. QPS=0 is not set here, because
	// client code is overriding it.
	defaultQPS = 1e6
	// High enough Burst to fit all expected use cases. Burst=0 is not set here, because
	// client code is overriding it.
	defaultBurst = 1e6
)

// buildConfigFromFlags builds REST config based on master URL and kubeconfig path.
// If both of them are empty then in cluster config is used.
func buildConfigFromFlags(masterURL, kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" && masterURL == "" {
		kubeconfig, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}

		return kubeconfig, nil
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{
			ClusterInfo: clientcmdapi.Cluster{
				Server: masterURL,
			},
		}).ClientConfig()
}

// createApiserverClient creates new Kubernetes Apiserver client. When kubeconfig or apiserverHost param is empty
// the function assumes that it is running inside a Kubernetes cluster and attempts to
// discover the Apiserver. Otherwise, it connects to the Apiserver specified.
//
// apiserverHost param is in the format of protocol://address:port/pathPrefix, e.g.http://localhost:8001.
// kubeConfig location of kubeconfig file
func createApiserverClient(apiserverHost string, kubeConfig string) (*kubernetes.Clientset, error) {
	cfg, err := buildConfigFromFlags(apiserverHost, kubeConfig)
	if err != nil {
		return nil, err
	}

	cfg.QPS = defaultQPS
	cfg.Burst = defaultBurst
	cfg.ContentType = "application/vnd.kubernetes.protobuf"

	glog.Infof("Creating API client for %s", cfg.Host)

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	v, err := client.Discovery().ServerVersion()
	if err != nil {
		return nil, err
	}

	glog.Infof("Running in Kubernetes Cluster version v%v.%v (%v) - git (%v) commit %v - platform %v",
		v.Major, v.Minor, v.GitVersion, v.GitTreeState, v.GitCommit, v.Platform)

	return client, nil
}

/**
 * Handles fatal init error that prevents server from doing any work. Prints verbose error
 * message and quits the server.
 */
func handleFatalInitError(err error) {
	glog.Fatalf("Error while initializing connection to Kubernetes apiserver. "+
		"This most likely means that the cluster is misconfigured (e.g., it has "+
		"invalid apiserver certificates or service accounts configuration). Reason: %s", err)
}
