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

package services

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	responseTime       *prometheus.HistogramVec
	ctlProcTimeSum     *prometheus.CounterVec
	ctlProcCount       *prometheus.CounterVec
	procSecondsCounter *prometheus.CounterVec
	updatesCounter     *prometheus.CounterVec
	updateSuccessGauge *prometheus.GaugeVec
	certExpireGauge    *prometheus.GaugeVec
	certSigningCounter *prometheus.CounterVec
	lastTrack          time.Time
}

func (m *metrics) register(reg prometheus.Registerer) {
	reg.MustRegister(
		m.responseTime,
		m.ctlProcTimeSum,
		m.ctlProcCount,
		m.procSecondsCounter,
		m.updatesCounter,
		m.updateSuccessGauge,
		m.certExpireGauge,
		m.certSigningCounter,
	)
}

func createMetrics(bucketsResponseTime []float64) *metrics {
	namespace := "haproxyingress"
	metrics := &metrics{
		responseTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "haproxy_response_time_seconds",
				Help:      "Response time to commands sent via admin socket",
				Buckets:   bucketsResponseTime,
			},
			[]string{"command"},
		),
		ctlProcTimeSum: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "controller_processing_time_seconds_sum",
				Help:      "Cumulative time in seconds spent on haproxy-ingress tasks",
			},
			[]string{"task"},
		),
		ctlProcCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "controller_processing_count",
				Help:      "Cumulative number of haproxy-ingress tasks executed",
			},
			[]string{"task"},
		),
		procSecondsCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "haproxy_processing_seconds_total",
				Help:      "Cumulative time in seconds a single thread spent processing requests, based on Idle_pct.",
			},
			[]string{},
		),
		updatesCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "updates_total",
				Help:      "Cumulative number of Ingress controller updates. Status can be noop, dynamic, full.",
			},
			[]string{"status"},
		),
		updateSuccessGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "update_success",
				Help:      "Whether the last haproxy update was successful.",
			},
			[]string{},
		),
		certExpireGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "cert_expire_date_epoch",
				Help:      "The SSL certificate expiration date in unix epoch time.",
			},
			[]string{"domain", "cn"},
		),
		certSigningCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cert_signing_count",
				Help:      "Cumulative number of certificate signing.",
			},
			[]string{"domains", "reason", "success"},
		),
	}
	return metrics
}

func (m *metrics) HAProxyShowInfoResponseTime(duration time.Duration) {
	m.responseTime.WithLabelValues("show_info").Observe(duration.Seconds())
}

func (m *metrics) HAProxySetServerResponseTime(duration time.Duration) {
	m.responseTime.WithLabelValues("set_server").Observe(duration.Seconds())
}

func (m *metrics) HAProxySetSSLCertResponseTime(duration time.Duration) {
	m.responseTime.WithLabelValues("set_ssl_cert").Observe(duration.Seconds())
}

func (m *metrics) ControllerProcTime(task string, duration time.Duration) {
	m.ctlProcTimeSum.WithLabelValues(task).Add(duration.Seconds())
	m.ctlProcCount.WithLabelValues(task).Inc()
}

func (m *metrics) AddIdleFactor(idle int) {
	now := time.Now()
	if m.lastTrack.IsZero() {
		m.lastTrack = now
		return
	}
	totalTime := now.Sub(m.lastTrack).Seconds()
	m.lastTrack = now
	m.procSecondsCounter.WithLabelValues().Add(float64(100-idle) * totalTime / 100)
}

func (m *metrics) IncUpdateNoop() {
	m.updatesCounter.WithLabelValues("noop").Inc()
}

func (m *metrics) IncUpdateDynamic() {
	m.updatesCounter.WithLabelValues("dynamic").Inc()
}

func (m *metrics) IncUpdateFull() {
	m.updatesCounter.WithLabelValues("full").Inc()
}

func (m *metrics) UpdateSuccessful(success bool) {
	value := map[bool]float64{false: 0, true: 1}
	m.updateSuccessGauge.WithLabelValues().Set(value[success])
}

func (m *metrics) SetCertExpireDate(domain, cn string, notAfter *time.Time) {
	if notAfter == nil {
		m.certExpireGauge.DeleteLabelValues(domain, cn)
		return
	}
	m.certExpireGauge.WithLabelValues(domain, cn).Set(float64(notAfter.Unix()))
}

func (m *metrics) ClearCertExpire() {
	m.certExpireGauge.Reset()
}

func (m *metrics) IncCertSigningMissing(domains string, success bool) {
	m.certSigningCounter.WithLabelValues(domains, "missing", strconv.FormatBool(success)).Inc()
}

func (m *metrics) IncCertSigningExpiring(domains string, success bool) {
	m.certSigningCounter.WithLabelValues(domains, "expiring", strconv.FormatBool(success)).Inc()
}

func (m *metrics) IncCertSigningOutdated(domains string, success bool) {
	m.certSigningCounter.WithLabelValues(domains, "outdated", strconv.FormatBool(success)).Inc()
}
