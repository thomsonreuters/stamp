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
)

// Pipeline defines the interface for attestation execution workflows.
type Pipeline interface {
	Execute(ctx context.Context) error
}

// SignedResult represents the outcome of processing a single attestation.
type SignedResult struct {
	// BundleJSON holds the serialized sigstore Bundle v0.3.
	BundleJSON    []byte
	Error         error
	AttestorName  string
	PredicateType string
	// StatementJSON is the raw in-toto Statement payload. Populated even
	// when signing is disabled so callers can render/persist a payload.
	StatementJSON []byte
}

// CollectionResult pairs a collection bundle with the workflow that produced it.
type CollectionResult struct {
	// BundleJSON holds the serialized sigstore Bundle v0.3 for the collection.
	BundleJSON    []byte
	StatementJSON []byte
	WorkflowName  string
}

// Result represents the outcome of a pipeline execution.
type Result struct {
	Attestations []SignedResult
	Metrics      *Metrics
	Collections  []CollectionResult
}

// HasCollection reports whether any collection bundles were produced.
func (r *Result) HasCollection() bool {
	return len(r.Collections) > 0
}

// Merge combines another Result into this one. Individual results,
// collection bundles, and metrics are all accumulated.
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

// Successful returns attestation results without errors.
func (r *Result) Successful() []SignedResult {
	successful := make([]SignedResult, 0, len(r.Attestations))
	for _, result := range r.Attestations {
		if result.Error == nil {
			successful = append(successful, result)
		}
	}
	return successful
}

// Failed returns attestation results with errors.
func (r *Result) Failed() []SignedResult {
	var failed []SignedResult
	for _, result := range r.Attestations {
		if result.Error != nil {
			failed = append(failed, result)
		}
	}
	return failed
}

// Bundles returns the raw bundle JSON payloads from all non-error attestations.
func (r *Result) Bundles() [][]byte {
	bundles := make([][]byte, 0, len(r.Attestations))
	for _, result := range r.Attestations {
		if result.Error != nil {
			continue
		}
		if len(result.BundleJSON) > 0 {
			bundles = append(bundles, result.BundleJSON)
		}
	}
	return bundles
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
