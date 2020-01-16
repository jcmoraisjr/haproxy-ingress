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

package helper_test

import (
	"testing"
	"time"
)

// MetricsMock ...
type MetricsMock struct {
	Logging []string
	T       *testing.T
}

// NewMetricsMock ...
func NewMetricsMock() *MetricsMock {
	return &MetricsMock{}
}

// HAProxyShowInfoResponseTime ...
func (m *MetricsMock) HAProxyShowInfoResponseTime(duration time.Duration) {
}

// HAProxySetServerResponseTime ...
func (m *MetricsMock) HAProxySetServerResponseTime(duration time.Duration) {
}

// ControllerProcTime ...
func (m *MetricsMock) ControllerProcTime(task string, duration time.Duration) {

}

// AddIdleFactor ...
func (m *MetricsMock) AddIdleFactor(idle int) {
}

// IncUpdateNoop ...
func (m *MetricsMock) IncUpdateNoop() {
}

// IncUpdateDynamic ...
func (m *MetricsMock) IncUpdateDynamic() {
}

// IncUpdateFull ...
func (m *MetricsMock) IncUpdateFull() {
}

// UpdateSuccessful ...
func (m *MetricsMock) UpdateSuccessful(success bool) {
}

// SetCertExpireDate ...
func (m *MetricsMock) SetCertExpireDate(domain, cn string, notAfter time.Time) {
}
