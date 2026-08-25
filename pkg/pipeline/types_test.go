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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:dupl // Table-driven tests have similar structure but test different result types
func TestResult_Successful(t *testing.T) {
	tests := []struct {
		name     string
		results  []EnvelopeResult
		expected int
	}{
		{
			name:     "empty results",
			results:  []EnvelopeResult{},
			expected: 0,
		},
		{
			name: "all successful",
			results: []EnvelopeResult{
				{BundleJSON: []byte("{}"), Error: nil},
				{BundleJSON: []byte("{}"), Error: nil},
			},
			expected: 2,
		},
		{
			name: "all failed",
			results: []EnvelopeResult{
				{Error: errors.New("error1")},
				{Error: errors.New("error2")},
			},
			expected: 0,
		},
		{
			name: "mixed results",
			results: []EnvelopeResult{
				{BundleJSON: []byte("{}"), Error: nil},
				{Error: errors.New("error")},
				{BundleJSON: []byte("{}"), Error: nil},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Attestations: tt.results}
			successful := r.Successful()
			assert.Len(t, successful, tt.expected)
			for _, s := range successful {
				assert.NoError(t, s.Error)
			}
		})
	}
}

//nolint:dupl // Table-driven tests have similar structure but test different result types
func TestResult_Failed(t *testing.T) {
	tests := []struct {
		name     string
		results  []EnvelopeResult
		expected int
	}{
		{
			name:     "empty results",
			results:  []EnvelopeResult{},
			expected: 0,
		},
		{
			name: "all successful",
			results: []EnvelopeResult{
				{BundleJSON: []byte("{}"), Error: nil},
				{BundleJSON: []byte("{}"), Error: nil},
			},
			expected: 0,
		},
		{
			name: "all failed",
			results: []EnvelopeResult{
				{Error: errors.New("error1")},
				{Error: errors.New("error2")},
			},
			expected: 2,
		},
		{
			name: "mixed results",
			results: []EnvelopeResult{
				{BundleJSON: []byte("{}"), Error: nil},
				{Error: errors.New("error")},
				{BundleJSON: []byte("{}"), Error: nil},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Attestations: tt.results}
			failed := r.Failed()
			assert.Len(t, failed, tt.expected)
			for _, f := range failed {
				assert.Error(t, f.Error)
			}
		})
	}
}

func TestResult_Bundles(t *testing.T) {
	tests := []struct {
		name     string
		results  []EnvelopeResult
		expected int
	}{
		{
			name:     "empty results",
			results:  []EnvelopeResult{},
			expected: 0,
		},
		{
			name: "all with bundles",
			results: []EnvelopeResult{
				{BundleJSON: []byte(`{"a":1}`), Error: nil},
				{BundleJSON: []byte(`{"b":2}`), Error: nil},
			},
			expected: 2,
		},
		{
			name: "some without bundles",
			results: []EnvelopeResult{
				{BundleJSON: []byte(`{"a":1}`), Error: nil},
				{Error: errors.New("error")},
				{BundleJSON: []byte(`{"c":3}`), Error: nil},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Attestations: tt.results}
			bundles := r.Bundles()
			assert.Len(t, bundles, tt.expected)
			for _, b := range bundles {
				assert.NotEmpty(t, b)
			}
		})
	}
}

func TestResult_Errors(t *testing.T) {
	err1 := errors.New("error1")
	err2 := errors.New("error2")

	tests := []struct {
		name     string
		results  []EnvelopeResult
		expected int
	}{
		{
			name:     "empty results",
			results:  []EnvelopeResult{},
			expected: 0,
		},
		{
			name: "no errors",
			results: []EnvelopeResult{
				{BundleJSON: []byte("{}"), Error: nil},
				{BundleJSON: []byte("{}"), Error: nil},
			},
			expected: 0,
		},
		{
			name: "all errors",
			results: []EnvelopeResult{
				{Error: err1},
				{Error: err2},
			},
			expected: 2,
		},
		{
			name: "mixed",
			results: []EnvelopeResult{
				{BundleJSON: []byte("{}"), Error: nil},
				{Error: err1},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Attestations: tt.results}
			errs := r.Errors()
			assert.Len(t, errs, tt.expected)
			for _, e := range errs {
				assert.Error(t, e)
			}
		})
	}
}
