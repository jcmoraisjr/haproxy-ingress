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

package controller

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	responseTime       *prometheus.HistogramVec
	ctlProcTimeSum     *prometheus.CounterVec
	ctlProcTimeCount   *prometheus.CounterVec
	procSecondsCounter *prometheus.CounterVec
	updatesCounter     *prometheus.CounterVec
	updateSuccessGauge *prometheus.GaugeVec
	certExpireGauge    *prometheus.GaugeVec
	lastTrack          time.Time
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
		ctlProcTimeCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "controller_processing_time_seconds_count",
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
	}
	prometheus.MustRegister(metrics.responseTime)
	prometheus.MustRegister(metrics.ctlProcTimeSum)
	prometheus.MustRegister(metrics.ctlProcTimeCount)
	prometheus.MustRegister(metrics.procSecondsCounter)
	prometheus.MustRegister(metrics.updatesCounter)
	prometheus.MustRegister(metrics.updateSuccessGauge)
	prometheus.MustRegister(metrics.certExpireGauge)
	return metrics
}

func (m *metrics) HAProxyShowInfoResponseTime(duration time.Duration) {
	m.responseTime.WithLabelValues("show_info").Observe(duration.Seconds())
}

func (m *metrics) HAProxySetServerResponseTime(duration time.Duration) {
	m.responseTime.WithLabelValues("set_server").Observe(duration.Seconds())
}

func (m *metrics) ControllerProcTime(task string, duration time.Duration) {
	m.ctlProcTimeSum.WithLabelValues(task).Add(duration.Seconds())
	m.ctlProcTimeCount.WithLabelValues(task).Inc()
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
