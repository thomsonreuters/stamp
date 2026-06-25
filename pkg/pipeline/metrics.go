// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipeline

import "time"

// Metrics tracks pipeline execution statistics.
type Metrics struct {
	StartTime            time.Time
	EndTime              time.Time
	AttestorExecutions   int
	SuccessfulExecutions int
	FailedExecutions     int
	SigningDuration      time.Duration
	DestinationDuration  time.Duration
	RekorUploadDuration  time.Duration
}

// NewMetrics creates a new metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{
		StartTime: time.Now(),
	}
}

// Duration returns total pipeline execution time.
func (m *Metrics) Duration() time.Duration {
	if m.EndTime.IsZero() {
		return time.Since(m.StartTime)
	}
	return m.EndTime.Sub(m.StartTime)
}

// Finalize marks the pipeline as completed.
func (m *Metrics) Finalize() {
	if m.EndTime.IsZero() {
		m.EndTime = time.Now()
	}
}

// Merge combines metrics from another pipeline execution.
func (m *Metrics) Merge(other *Metrics) {
	if other == nil {
		return
	}
	m.AttestorExecutions += other.AttestorExecutions
	m.SuccessfulExecutions += other.SuccessfulExecutions
	m.FailedExecutions += other.FailedExecutions
	m.SigningDuration += other.SigningDuration
	m.DestinationDuration += other.DestinationDuration
	m.RekorUploadDuration += other.RekorUploadDuration
	if !other.StartTime.IsZero() && (m.StartTime.IsZero() || other.StartTime.Before(m.StartTime)) {
		m.StartTime = other.StartTime
	}
	if other.EndTime.After(m.EndTime) {
		m.EndTime = other.EndTime
	}
}
