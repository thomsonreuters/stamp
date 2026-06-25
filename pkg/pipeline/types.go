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

import (
	"context"

	"github.com/thomsonreuters/stamp/pkg/intoto"
)

// Pipeline defines the interface for attestation execution workflows.
type Pipeline interface {
	Execute(ctx context.Context) error
}

// EnvelopeResult represents the outcome of processing a single envelope.
type EnvelopeResult struct {
	Envelope      *intoto.Envelope
	Error         error
	AttestorName  string
	PredicateType string
}

// CollectionResult pairs a collection envelope with the workflow that produced it.
type CollectionResult struct {
	Envelope     *intoto.Envelope
	WorkflowName string
}

// Result represents the outcome of a pipeline execution.
type Result struct {
	Attestations []EnvelopeResult
	Metrics      *Metrics
	Collections  []CollectionResult
}

// HasCollection reports whether any collection envelopes were produced.
func (r *Result) HasCollection() bool {
	return len(r.Collections) > 0
}

// Merge combines another Result into this one. Individual results,
// collection envelopes, and metrics are all accumulated.
func (r *Result) Merge(other *Result) {
	if other == nil {
		return
	}
	r.Attestations = append(r.Attestations, other.Attestations...)
	r.Collections = append(r.Collections, other.Collections...)
	if r.Metrics != nil && other.Metrics != nil {
		r.Metrics.Merge(other.Metrics)
	}
}

// Successful returns envelope results without errors.
func (r *Result) Successful() []EnvelopeResult {
	successful := make([]EnvelopeResult, 0, len(r.Attestations))
	for _, result := range r.Attestations {
		if result.Error == nil {
			successful = append(successful, result)
		}
	}
	return successful
}

// Failed returns envelope results with errors.
func (r *Result) Failed() []EnvelopeResult {
	var failed []EnvelopeResult
	for _, result := range r.Attestations {
		if result.Error != nil {
			failed = append(failed, result)
		}
	}
	return failed
}

// Envelopes returns all non-nil envelopes from the results.
func (r *Result) Envelopes() []*intoto.Envelope {
	envelopes := make([]*intoto.Envelope, 0, len(r.Attestations))
	for _, result := range r.Attestations {
		if result.Envelope != nil {
			envelopes = append(envelopes, result.Envelope)
		}
	}
	return envelopes
}

// Errors returns all non-nil errors from the results.
func (r *Result) Errors() []error {
	var errors []error
	for _, result := range r.Attestations {
		if result.Error != nil {
			errors = append(errors, result.Error)
		}
	}
	return errors
}
