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

// Package v1 provides SLSA Provenance v1.0 predicate definitions.
package v1

import (
	"time"
)

const (
	// ProvenanceV1URI is the predicate type URI for SLSA Provenance v1.0
	// Specification: https://slsa.dev/spec/v1.0/provenance
	ProvenanceV1URI = "https://slsa.dev/provenance/v1"
)

type ProvenanceV1 struct {
	BuildDefinition BuildDefinition `json:"build_definition"`
	RunDetails      RunDetails      `json:"run_details"`
}

// BuildDefinition represents the build definition in SLSA provenance.
type BuildDefinition struct {
	BuildType            string               `json:"build_type"`
	ExternalParameters   map[string]any       `json:"external_parameters"`
	InternalParameters   map[string]any       `json:"internal_parameters"`
	ResolvedDependencies []ResourceDescriptor `json:"resolved_dependencies,omitempty"`
}

// RunDetails represents the run details in SLSA provenance.
type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   BuilderMetadata      `json:"metadata"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder represents the builder information.
type Builder struct {
	ID                  string               `json:"id"`
	Version             map[string]string    `json:"version,omitempty"`
	BuilderDependencies []ResourceDescriptor `json:"builder_dependencies,omitempty"`
}

// BuilderMetadata represents metadata about the build execution.
type BuilderMetadata struct {
	InvocationID string    `json:"invocation_id"`
	StartedOn    time.Time `json:"started_on"`
	FinishedOn   time.Time `json:"finished_on,omitzero"`
}

// ResourceDescriptor describes the identity and location of a resource.
// This type is used for resolved dependencies, byproducts, and builder dependencies.
// Specification: https://slsa.dev/spec/v1.0/provenance
type ResourceDescriptor struct {
	URI              string            `json:"uri"`
	Digest           map[string]string `json:"digest,omitempty"`
	Name             string            `json:"name,omitempty"`
	DownloadLocation string            `json:"download_location,omitempty"`
	MediaType        string            `json:"media_type,omitempty"`
	Content          []byte            `json:"content,omitempty"`
	Annotations      map[string]any    `json:"annotations,omitempty"`
}
