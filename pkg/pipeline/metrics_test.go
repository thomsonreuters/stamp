// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipeline

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewMetrics(t *testing.T) {
	before := time.Now()
	m := NewMetrics()
	after := time.Now()

	assert.NotNil(t, m)
	assert.True(t, m.StartTime.After(before) || m.StartTime.Equal(before))
	assert.True(t, m.StartTime.Before(after) || m.StartTime.Equal(after))
	assert.True(t, m.EndTime.IsZero())
	assert.Equal(t, 0, m.AttestorExecutions)
	assert.Equal(t, 0, m.SuccessfulExecutions)
	assert.Equal(t, 0, m.FailedExecutions)
	assert.Equal(t, time.Duration(0), m.SigningDuration)
	assert.Equal(t, time.Duration(0), m.RekorUploadDuration)
}

func TestMetrics_Duration_NotFinalized(t *testing.T) {
	m := NewMetrics()
	time.Sleep(10 * time.Millisecond)

	duration := m.Duration()
	assert.GreaterOrEqual(t, duration, 10*time.Millisecond)
}

func TestMetrics_Duration_Finalized(t *testing.T) {
	m := NewMetrics()
	time.Sleep(10 * time.Millisecond)
	m.Finalize()

	duration1 := m.Duration()
	time.Sleep(10 * time.Millisecond)
	duration2 := m.Duration()

	// Duration should be fixed after finalization
	assert.Equal(t, duration1, duration2)
}

func TestMetrics_Finalize(t *testing.T) {
	m := NewMetrics()
	assert.True(t, m.EndTime.IsZero())

	m.Finalize()
	assert.False(t, m.EndTime.IsZero())
	assert.True(t, m.EndTime.After(m.StartTime) || m.EndTime.Equal(m.StartTime))
}

func TestMetrics_Finalize_Idempotent(t *testing.T) {
	m := NewMetrics()
	time.Sleep(5 * time.Millisecond)

	m.Finalize()
	firstEndTime := m.EndTime

	time.Sleep(5 * time.Millisecond)
	m.Finalize()

	// Should not update EndTime on second call
	assert.Equal(t, firstEndTime, m.EndTime)
}

func TestMetrics_ManualFields(t *testing.T) {
	m := NewMetrics()

	m.AttestorExecutions = 5
	m.SuccessfulExecutions = 3
	m.FailedExecutions = 2
	m.SigningDuration = 100 * time.Millisecond
	m.RekorUploadDuration = 200 * time.Millisecond

	assert.Equal(t, 5, m.AttestorExecutions)
	assert.Equal(t, 3, m.SuccessfulExecutions)
	assert.Equal(t, 2, m.FailedExecutions)
	assert.Equal(t, 100*time.Millisecond, m.SigningDuration)
	assert.Equal(t, 200*time.Millisecond, m.RekorUploadDuration)
}
