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
	procSecondsCounter *prometheus.CounterVec
	lastTrack          time.Time
}

func createMetrics() *metrics {
	namespace := "haproxyingress"
	metrics := &metrics{
		responseTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "haproxy_response_time_seconds",
				Help:      "Response time to commands sent via admin socket",
				Buckets:   []float64{.0005, .001, .002, .005, .01},
			},
			[]string{"command"},
		),
		procSecondsCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "haproxy_processing_seconds_total",
				Help:      "Cumulative time in seconds a single thread spent processing requests, based on Idle_pct.",
			},
			[]string{},
		),
	}
	prometheus.MustRegister(metrics.responseTime)
	prometheus.MustRegister(metrics.procSecondsCounter)
	return metrics
}

func (m *metrics) HAProxyShowInfoResponseTime(duration time.Duration) {
	m.responseTime.WithLabelValues("show_info").Observe(duration.Seconds())
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
