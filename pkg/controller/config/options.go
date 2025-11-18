package config

import (
	"flag"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func NewOptions() *Options {
	return &Options{
		KubeConfig:              StringValue(""),
		IngressClass:            "haproxy",
		ReloadStrategy:          "reusesocket",
		WatchGateway:            true,
		MasterWorker:            true,
		AcmeCheckPeriod:         24 * time.Hour,
		AcmeFailInitialDuration: 5 * time.Minute,
		AcmeFailMaxDuration:     8 * time.Hour,
		AcmeSecretKeyName:       "acme-private-key",
		AcmeTokenConfigMapName:  "acme-validation-tokens",
		BucketsResponseTime:     []float64{.0005, .001, .002, .005, .01},
		AnnPrefix:               "haproxy-ingress.github.io,ingress.kubernetes.io",
		RateLimitUpdate:         0.5,
		WaitBeforeUpdate:        200 * time.Millisecond,
		ReloadRetry:             30 * time.Second,
		ResyncPeriod:            10 * time.Hour,
		WatchNamespace:          corev1.NamespaceAll,
		StatsCollectProcPeriod:  500 * time.Millisecond,
		HealthzAddr:             ":10254",
		HealthzURL:              "/healthz",
		ReadyzURL:               "/readyz",
		Profiling:               true,
		VerifyHostname:          true,
		UpdateStatus:            true,
		ElectionID:              "class-%s.haproxy-ingress.github.io",
		ShutdownTimeout:         25 * time.Second,
		HAProxyGracePeriod:      20 * time.Second,
		UpdateStatusOnShutdown:  true,
		EnableEndpointSlicesAPI: true,
		LogLevel:                2,
	}
}

type Options struct {
	KubeConfig               flag.Value
	ApiserverHost            string
	LocalFSPrefix            string
	DisableAPIWarnings       bool
	DefaultSvc               string
	IngressClass             string
	IngressClassPrecedence   bool
	DisableIngressClassAPI   bool
	ReloadStrategy           string
	MaxOldConfigFiles        int
	ValidateConfig           bool
	ControllerClass          string
	WatchIngressWithoutClass bool
	WatchGateway             bool
	MasterWorker             bool
	MasterSocket             string
	ConfigMap                string
	AcmeServer               bool
	AcmeCheckPeriod          time.Duration
	AcmeFailInitialDuration  time.Duration
	AcmeFailMaxDuration      time.Duration
	AcmeSecretKeyName        string
	AcmeTokenConfigMapName   string
	AcmeTrackTLSAnn          bool
	BucketsResponseTime      []float64
	PublishService           string
	PublishAddress           string
	TCPConfigMapName         string
	AnnPrefix                string
	RateLimitUpdate          float64
	ReloadInterval           time.Duration
	ReloadRetry              time.Duration
	WaitBeforeUpdate         time.Duration
	ResyncPeriod             time.Duration
	WatchNamespace           string
	StatsCollectProcPeriod   time.Duration
	HealthzAddr              string
	HealthzURL               string
	ReadyzURL                string
	Profiling                bool
	StopHandler              bool
	DefSSLCertificate        string
	VerifyHostname           bool
	UpdateStatus             bool
	ElectionID               string
	WaitBeforeShutdown       string
	ShutdownTimeout          time.Duration
	HAProxyGracePeriod       time.Duration
	AllowCrossNamespace      bool
	DisableExternalName      bool
	DisableConfigKeywords    string
	UpdateStatusOnShutdown   bool
	BackendShards            int
	SortBackends             bool
	SortEndpointsBy          string
	TrackOldInstances        bool
	UseNodeInternalIP        bool
	LogZap                   bool
	LogDev                   bool
	LogCaller                bool
	LogLevel                 int
	LogEnableStacktrace      bool
	LogEncoder               string
	LogEncodeTime            string

	// Deprecated option
	AcmeElectionID string
	// Deprecated option
	HealthzPort int
	// Deprecated option
	DisableNodeList bool
	// Deprecated option
	DisablePodList bool
	// Deprecated option
	ForceIsolation bool
	// Deprecated option
	IgnoreIngressWithoutClass bool
	// Deprecated option
	EnableEndpointSlicesAPI bool

	//
	Version bool
}

func (o *Options) AddFlags(fs *flag.FlagSet) {

	// `""+` in the end of the first line makes gofmt generate a better output

	config.RegisterFlags(fs)
	o.KubeConfig = fs.Lookup("kubeconfig").Value

	fs.StringVar(&o.ApiserverHost, "apiserver-host", o.ApiserverHost, ""+
		"The address of the Kubernetes API server to connect to, in the format of "+
		"protocol://address:port, e.g., http://localhost:8080. If not specified, the "+
		"default value from in cluster discovery or from a provided kubeconfig is used. "+
		"A valid kubeconfig must be provided if used.",
	)

	fs.StringVar(&o.LocalFSPrefix, "local-filesystem-prefix", o.LocalFSPrefix, ""+
		"Defines the prefix of a temporary directory HAProxy Ingress should create and "+
		"maintain all the configuration files. Useful for local deployment.",
	)

	fs.BoolVar(&o.DisableAPIWarnings, "disable-api-warnings", o.DisableAPIWarnings, ""+
		"Disable warnings from the API server.",
	)

	fs.StringVar(&o.DefaultSvc, "default-backend-service", o.DefaultSvc, ""+
		"Service used to serve a 404 page for the default backend. Takes the form "+
		"namespace/name. The controller uses the first node port of this Service for the "+
		"default backend.`",
	)

	fs.StringVar(&o.IngressClass, "ingress-class", o.IngressClass, ""+
		"Name of the IngressClass to route through this controller.",
	)

	fs.BoolVar(&o.IngressClassPrecedence, "ingress-class-precedence", o.IngressClassPrecedence, ""+
		"Defines if IngressClass resource should take precedence over "+
		"kubernetes.io/ingress.class annotation if both are defined and conflicting.",
	)

	fs.StringVar(&o.ReloadStrategy, "reload-strategy", o.ReloadStrategy, ""+
		"Name of the reload strategy. Options are: native or reusesocket",
	)

	fs.IntVar(&o.MaxOldConfigFiles, "max-old-config-files", o.MaxOldConfigFiles, ""+
		"Maximum number of old HAProxy timestamped config files to retain. Older files "+
		"are cleaned up. A value <= 0 indicates only a single non-timestamped config "+
		"file will be retained.",
	)

	fs.BoolVar(&o.ValidateConfig, "validate-config", o.ValidateConfig, ""+
		"Define if the resulting configuration files should be validated when a dynamic "+
		"update was applied. Default value is false, which means the validation will "+
		"only happen when HAProxy needs to be reloaded. If validation fails, HAProxy "+
		"Ingress will log the error and set the metric 'haproxyingress_update_success' "+
		"as failed (zero)",
	)

	fs.StringVar(&o.ControllerClass, "controller-class", o.ControllerClass, ""+
		"Defines an alternative controller name this controller should listen to. If "+
		"empty, this controller will listen to ingress resources whose controller's "+
		"IngressClass is 'haproxy-ingress.github.io/controller'. Non-empty values add a "+
		"new /path, e.g., controller-class=staging will make this controller look for "+
		"'haproxy-ingress.github.io/controller/staging'",
	)

	fs.BoolVar(&o.DisableIngressClassAPI, "disable-ingress-class-api", o.DisableIngressClassAPI, ""+
		"Configures controller to not list or watch IngressClass API, useful on "+
		"deployments that cannot allow controller to have cluster permission. If "+
		"configured, the only way to configure ingress resources is using "+
		"kubernetes.io/ingress.class annotation or enabling --watch-ingress-without-class",
	)

	fs.BoolVar(&o.WatchIngressWithoutClass, "watch-ingress-without-class", o.WatchIngressWithoutClass, ""+
		"Defines if this controller should also listen to ingress resources that don't "+
		"declare neither the kubernetes.io/ingress.class annotation nor the "+
		"<ingress>.spec.ingressClassName field. Defaults to false.",
	)

	fs.BoolVar(&o.WatchGateway, "watch-gateway", o.WatchGateway, ""+
		"Watch and parse resources from the Gateway API.",
	)

	fs.BoolVar(&o.MasterWorker, "master-worker", o.MasterWorker, ""+
		"Defines if haproxy should be configured in master-worker mode. If 'false', one "+
		"single process is forked in the background. If 'true', a master process is "+
		"started in the foreground and can be used to manage current and old worker "+
		"processes.",
	)

	fs.StringVar(&o.MasterSocket, "master-socket", o.MasterSocket, ""+
		"Defines the master CLI unix socket of an external HAProxy running in "+
		"master-worker mode. Defaults to use the embedded HAProxy if not declared.",
	)

	fs.StringVar(&o.ConfigMap, "configmap", o.ConfigMap, ""+
		"Name of the ConfigMap that contains the custom configuration to use",
	)

	fs.BoolVar(&o.AcmeServer, "acme-server", o.AcmeServer, ""+
		"Enables ACME server. This server is used to receive and answer challenges from "+
		"Let's Encrypt or other ACME implementations.",
	)

	fs.DurationVar(&o.AcmeCheckPeriod, "acme-check-period", o.AcmeCheckPeriod, ""+
		"Time between checks of invalid or expiring certificates",
	)

	fs.DurationVar(&o.AcmeFailInitialDuration, "acme-fail-initial-duration", o.AcmeFailInitialDuration, ""+
		"The initial time to wait to retry sign a new certificate after a failure. The "+
		"time between retries will grow exponentially until 'acme-fail-max-duration'",
	)

	fs.DurationVar(&o.AcmeFailMaxDuration, "acme-fail-max-duration", o.AcmeFailMaxDuration, ""+
		"The maximum time to wait after failing to sign a new certificate",
	)

	fs.StringVar(&o.AcmeSecretKeyName, "acme-secret-key-name", o.AcmeSecretKeyName, ""+
		"Name and an optional namespace of the secret which will store the acme account "+
		"private key. If a namespace is not provided, the secret will be created in the "+
		"same namespace of the controller pod.",
	)

	fs.StringVar(&o.AcmeTokenConfigMapName, "acme-token-configmap-name", o.AcmeTokenConfigMapName, ""+
		"Name and an optional namespace of the configmap which will store acme tokens "+
		"used to answer the acme challenges. If a namespace is not provided, the secret "+
		"will be created in the same namespace of the controller pod.",
	)

	fs.BoolVar(&o.AcmeTrackTLSAnn, "acme-track-tls-annotation", o.AcmeTrackTLSAnn, ""+
		"Enable tracking of ingress objects annotated with 'kubernetes.io/tls-acme'",
	)

	FlagFloat64SliceVar(fs, &o.BucketsResponseTime, "buckets-response-time", o.BucketsResponseTime, ""+
		"Configures the buckets of the histogram used to compute the response time of "+
		"the haproxy's admin socket. The response time unit is in seconds.",
	)

	fs.StringVar(&o.PublishService, "publish-service", o.PublishService, ""+
		"Service fronting the ingress controllers. Takes the form namespace/name. The "+
		"controller will set the endpoint records on the ingress objects to reflect "+
		"those on the service.",
	)

	fs.StringVar(&o.PublishAddress, "publish-address", o.PublishAddress, ""+
		"Comma separated list of hostname/IP addresses that should be used to configure "+
		"ingress status. This option cannot be used if --publish-service is configured.",
	)

	fs.StringVar(&o.TCPConfigMapName, "tcp-services-configmap", o.TCPConfigMapName, ""+
		"Name of the ConfigMap that contains the definition of the TCP services to "+
		"expose. The key in the map indicates the external port to be used. The value is "+
		"the name of the service with the format namespace/serviceName and the port of "+
		"the service could be a number of the name of the port. The ports 80 and 443 are "+
		"not allowed as external ports. This ports are reserved for the backend.",
	)

	fs.StringVar(&o.AnnPrefix, "annotations-prefix", o.AnnPrefix, ""+
		"Defines a comma-separated list of annotation prefix for ingress and service",
	)

	fs.Float64Var(&o.RateLimitUpdate, "rate-limit-update", o.RateLimitUpdate, ""+
		"Maximum of updates per second this controller should perform. Default is 0.5, "+
		"which means wait 2 seconds between Ingress updates in order to add more changes "+
		"in a single reload.",
	)

	fs.DurationVar(&o.ReloadInterval, "reload-interval", o.ReloadInterval, ""+
		"Minimal time between two consecutive HAProxy reloads. The default value is 0, "+
		"which means to always reload HAProxy just after a configuration change enforces "+
		"a reload. The interval should be configured with a time suffix, eg 30s means "+
		"that if two distinct and consecutive configuration changes enforce a reload, "+
		"the second reload will be enqueued until 30 seconds have passed from the first "+
		"one, applying every new configuration changes made between this interval.",
	)

	fs.DurationVar(&o.ReloadRetry, "reload-retry", o.ReloadRetry, ""+
		"How long HAProxy Ingress should wait before trying to reload HAProxy if an error "+
		"happens.")

	fs.DurationVar(&o.WaitBeforeUpdate, "wait-before-update", o.WaitBeforeUpdate, ""+
		"Amount of time to wait before start a reconciliation and update haproxy, giving "+
		"the time to receive all/most of the changes of a batch update.",
	)

	fs.DurationVar(&o.ResyncPeriod, "sync-period", o.ResyncPeriod, ""+
		"Configures the default resync period of Kubernetes' informer factory.",
	)

	fs.StringVar(&o.WatchNamespace, "watch-namespace", o.WatchNamespace, ""+
		"Namespace to watch for Ingress. Default is to watch all namespaces.",
	)

	fs.DurationVar(&o.StatsCollectProcPeriod, "stats-collect-processing-period", o.StatsCollectProcPeriod, ""+
		"Defines the interval between two consecutive readings of haproxy's Idle_pct. "+
		"haproxy updates Idle_pct every 500ms, which makes that the best configuration "+
		"value. Change to 0 (zero) to disable this metric.",
	)

	fs.StringVar(&o.HealthzAddr, "healthz-addr", o.HealthzAddr, ""+
		"The address the healthz service should bind to. Configure with an empty string "+
		"to disable it.",
	)

	fs.StringVar(&o.HealthzURL, "health-check-path", o.HealthzURL, ""+
		"Defines the URL to be used as health check.",
	)

	fs.StringVar(&o.ReadyzURL, "ready-check-path", o.ReadyzURL, ""+
		"Defines the URL to be used as readiness check.",
	)

	fs.BoolVar(&o.Profiling, "profiling", o.Profiling, ""+
		"Enable profiling via web interface host:healthzport/debug/pprof/",
	)

	fs.BoolVar(&o.StopHandler, "stop-handler", o.StopHandler, ""+
		"Allows to stop the controller via a POST request to host:healthzport/stop "+
		"endpoint.",
	)

	fs.StringVar(&o.DefSSLCertificate, "default-ssl-certificate", o.DefSSLCertificate, ""+
		"Name of the secret that contains a SSL certificate to be used as "+
		"default for a HTTPS catch-all server.",
	)

	fs.BoolVar(&o.VerifyHostname, "verify-hostname", o.VerifyHostname, ""+
		"Defines if the controller should verify if the provided certificate is valid, "+
		"ie, it's SAN extension has the hostname.",
	)

	fs.BoolVar(&o.UpdateStatus, "update-status", o.UpdateStatus, ""+
		"Indicates if the controller should update the 'status' attribute of all the "+
		"Ingress resources that this controller is tracking.",
	)

	fs.StringVar(&o.ElectionID, "election-id", o.ElectionID, ""+
		"Election ID to be used for status update and certificate signing. An optional "+
		"%s is used as a placeholder for the IngressClass name, and if not provided, the "+
		"IngressClass is concatenated in the end of the provided value to compose the "+
		"real Election ID, for backward compatibility.",
	)

	fs.StringVar(&o.WaitBeforeShutdown, "wait-before-shutdown", o.WaitBeforeShutdown, ""+
		"Defines the amount of time the controller should wait between receiving a "+
		"SIGINT or SIGTERM signal, and notifying the controller manager to gracefully "+
		"stops the controller. Use with a time suffix.",
	)

	fs.DurationVar(&o.ShutdownTimeout, "shutdown-timeout", o.ShutdownTimeout, ""+
		"Defines the amount of time the controller should wait, after receiving a "+
		"SIGINT or a SIGTERM, for all of its internal services to gracefully stop before "+
		"shutting down the process. It starts to count after --wait-before-shutdown has "+
		"been passed, if configured.",
	)

	fs.DurationVar(&o.HAProxyGracePeriod, "haproxy-grace-period", o.HAProxyGracePeriod, ""+
		"Configures the amount of time HAProxy should wait for all the active connections "+
		"to finish, after HAProxy Ingress receives the signal from Kubernetes to "+
		"terminate. This option is only used on embedded HAProxy configured as "+
		"master-worker.",
	)

	fs.BoolVar(&o.AllowCrossNamespace, "allow-cross-namespace", o.AllowCrossNamespace, ""+
		"Defines if the ingress controller can reference resources of another "+
		"namespaces. Cannot be used if force-namespace-isolation is true.",
	)

	fs.BoolVar(&o.DisableExternalName, "disable-external-name", o.DisableExternalName, ""+
		"Disables services of type ExternalName",
	)

	fs.StringVar(&o.DisableConfigKeywords, "disable-config-keywords", o.DisableConfigKeywords, ""+
		"Defines a comma-separated list of HAProxy keywords that should not be used on "+
		"annotation based configuration snippets. Configuration snippets added as a "+
		"global config does not follow this option. Use an asterisk * to disable "+
		"configuration snippets using annotations.",
	)

	fs.BoolVar(&o.UpdateStatusOnShutdown, "update-status-on-shutdown", o.UpdateStatusOnShutdown, ""+
		"Indicates if the ingress controller should update the Ingress status "+
		"IP/hostname when the controller is being stopped.",
	)

	fs.IntVar(&o.BackendShards, "backend-shards", o.BackendShards, ""+
		"Defines how much files should be used to configure the haproxy backends",
	)

	fs.BoolVar(&o.SortBackends, "sort-backends", o.SortBackends, ""+
		"Defines if backend's endpoints should be sorted by name. This option has less "+
		"precedence than --sort-endpoints-by if both are declared.",
	)

	fs.StringVar(&o.SortEndpointsBy, "sort-endpoints-by", o.SortEndpointsBy, ""+
		"Defines how to sort backend's endpoints. Allowed values are: 'endpoint' - same "+
		"k8s endpoint order (default); 'name' - server/endpoint name; "+
		"'ip' - server/endpoint IP and port; 'random' - shuffle endpoints on every "+
		"haproxy reload.",
	)

	fs.BoolVar(&o.TrackOldInstances, "track-old-instances", o.TrackOldInstances, ""+
		"Creates an internal list of connections to old HAProxy instances. These "+
		"connections are used to read or send data to stopping instances, which is "+
		"usually serving long lived connections like TCP services or websockets.",
	)

	fs.BoolVar(&o.UseNodeInternalIP, "report-node-internal-ip-address", o.UseNodeInternalIP, ""+
		"Defines if the nodes IP address to be returned in the ingress status should be "+
		"the internal instead of the external IP address.",
	)

	fs.BoolVar(&o.LogZap, "log-zap", o.LogZap, ""+
		"Enables zap as the log sink for all the logging outputs.",
	)

	fs.BoolVar(&o.LogDev, "log-dev", o.LogDev, ""+
		"Defines if development style logging should be used. Needs --log-zap enabled.",
	)

	fs.BoolVar(&o.LogCaller, "log-caller", o.LogCaller, ""+
		"Defines if the log output should add a reference of the caller with file name "+
		"and line number. Needs --log-zap enabled.",
	)

	fs.IntVar(&o.LogLevel, "v", o.LogLevel, ""+
		"Number for the log level verbosity. 1: info; 2: add low verbosity debug.",
	)

	fs.BoolVar(&o.LogEnableStacktrace, "log-enable-stacktrace", o.LogEnableStacktrace, ""+
		"Defines if error output should add stracktraces. Needs --log-zap enabled.",
	)

	fs.StringVar(&o.LogEncoder, "log-encoder", o.LogEncoder, ""+
		"Defines the log encoder. Options are: 'console' or 'json'. Defaults to 'json' if "+
		"--log-dev is false and 'console' if --log-dev is true. Needs --log-zap enabled.",
	)

	fs.StringVar(&o.LogEncodeTime, "log-encode-time", o.LogEncodeTime, ""+
		"Configures the encode time used in the logs. Options are: rfc3339nano, rfc3339, "+
		"iso8601, millis, nanos. Defaults to 'rfc3339nano' if --log-dev is false and "+
		"'iso8601' if --log-dev is true. Needs --log-zap enabled.",
	)

	//
	// Deprecated options
	//

	fs.StringVar(&o.AcmeElectionID, "acme-election-id", o.AcmeElectionID, ""+
		"DEPRECATED: acme and status update leader uses the same ID from --election-id "+
		"command-line option.",
	)

	fs.IntVar(&o.HealthzPort, "healthz-port", o.HealthzPort, ""+
		"DEPRECATED: Use --healthz-addr instead.",
	)

	fs.BoolVar(&o.DisableNodeList, "disable-node-list", o.DisableNodeList, ""+
		"DEPRECATED: This flag used to disable node listing due to missing permissions. "+
		"Actually node listing isn't needed and it is always disabled.",
	)

	fs.BoolVar(&o.DisablePodList, "disable-pod-list", o.DisablePodList, ""+
		"DEPRECATED: used to define if HAProxy Ingress should disable pod watch and in "+
		"memory list. This configuration is now ignored, controller-runtime takes care "+
		"of it.",
	)

	fs.BoolVar(&o.ForceIsolation, "force-namespace-isolation", o.ForceIsolation, ""+
		"DEPRECATED: this flag used to enforce that one namespace cannot read secrets "+
		"and services from other namespaces, actually implemented by "+
		"allow-cross-namespace command line option and cross-namespace configuration "+
		"keys.",
	)

	fs.BoolVar(&o.IgnoreIngressWithoutClass, "ignore-ingress-without-class", o.IgnoreIngressWithoutClass, ""+
		"DEPRECATED: Use --watch-ingress-without-class command-line option instead to "+
		"define if ingress without class should be tracked.",
	)

	fs.BoolVar(&o.EnableEndpointSlicesAPI, "enable-endpointslices-api", o.EnableEndpointSlicesAPI, ""+
		"DEPRECATED: Enables EndpointSlices API and disables watching Endpoints API. "+
		"Endpoints is deprecated since 1.33, so endpointslices is always enabled and "+
		"this option is ignored.",
	)

	//

	fs.BoolVar(&o.Version, "version", o.Version, ""+
		"Shows release information about the Ingress controller and exit",
	)
}
