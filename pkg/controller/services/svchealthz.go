package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apiserver/pkg/server/healthz"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
)

func initSvcHealthz(ctx context.Context, cfg *config.Config, metrics *metrics, acmeCheck svcAcmeCheckFnc) *svcHealthz {
	if cfg.HealthzAddr == "" {
		return nil
	}
	s := &svcHealthz{
		log: logr.FromContextOrDiscard(ctx).WithName("healthz"),
		cfg: cfg,
	}
	mux := http.NewServeMux()
	healthz.InstallPathHandler(mux, cfg.HealthzURL)
	healthz.InstallPathHandler(mux, cfg.ReadyzURL)
	mux.Handle("/", s.createRootHealthzHandler())
	mux.Handle("/acme/check", s.createAcmeHandler(acmeCheck))
	mux.Handle("/build", s.createBuildHandler(cfg))
	if cfg.Profiling {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	mux.Handle("/metrics", s.createMetricsHandler(metrics))
	if cfg.StopHandler {
		mux.Handle("/stop", s.createStopHandler())
	}
	s.server = &http.Server{
		Addr:    cfg.HealthzAddr,
		Handler: mux,
	}
	return s
}

type svcHealthz struct {
	log    logr.Logger
	cfg    *config.Config
	server *http.Server
}

func (s *svcHealthz) createRootHealthzHandler() http.HandlerFunc {
	var pprofDisabled, stopDisabled string
	if !s.cfg.Profiling {
		pprofDisabled = " (DISABLED)"
	}
	if !s.cfg.StopHandler {
		stopDisabled = " (DISABLED)"
	}

	// TODO build a html index
	contentType := "text/plain"
	page := `/acme/check (only POST): starts a new check for certificates that need to be issued
/build : build info
/debug/pprof/ : pprof index` + pprofDisabled + `
/metrics : HAProxy Ingress metrics in Prometheus format
/stop : stops the controller process` + stopDisabled + `
`

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			handle404(w)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write([]byte(page))
	}
}

func (s *svcHealthz) createAcmeHandler(acmeCheck func() (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var out string
		count, err := acmeCheck()
		w.Header().Set("Content-Type", "text/plain")
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			out = fmt.Sprintf("Error starting the certificate check: %s.\nSee further information in the controller log.\n", err)
		} else {
			w.WriteHeader(http.StatusOK)
			if count > 0 {
				out = fmt.Sprintf("Acme check successfully started. Added %d certificate(s) in the processing queue.\n", count)
			} else {
				out = "Acme certificate list is empty.\n"
			}
		}
		w.Write([]byte(out))
	}
}

func (s *svcHealthz) createBuildHandler(cfg *config.Config) http.HandlerFunc {
	build, _ := json.Marshal(cfg.VersionInfo)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(build)
	}
}

func (s *svcHealthz) createMetricsHandler(metrics *metrics) http.Handler {
	registry := prometheus.NewRegistry()
	registry.Register(collectors.NewGoCollector())
	metrics.register(registry)
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func (s *svcHealthz) createStopHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			handle404(w)
			return
		}
		err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("failed to stop process: %s\n", err)))
		} else {
			w.Write([]byte("controller process is stopping now\n"))
		}
	}
}

func handle404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 page not found\n"))
}

func (s *svcHealthz) Start(ctx context.Context) error {
	s.log.Info("starting", "address", s.server.Addr)
	go s.server.ListenAndServe()
	<-ctx.Done()
	stopctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.server.Shutdown(stopctx)
	s.log.Info("stopped")
	return err
}
