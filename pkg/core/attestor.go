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

// Package core provides the fundamental interfaces and types for the attestation framework.
// It defines the Attestor interface that all attestor implementations must satisfy,
// configuration helpers for type-safe parameter handling, and the global attestor registry
// for registering and discovering available attestors.

package core

import (
	"context"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

// Attestor defines the core interface that all attestors must implement.
// Implementations must be thread-safe as they may be called concurrently.
type Attestor interface {
	// ID returns the unique identifier for this attestor.
	// This must be unique across all registered attestors.
	// Example: "git", "jwt", "sbom"
	ID() string

	// PredicateURI returns the SLSA predicate URI for this attestor.
	// Multiple attestors may share the same predicate URI.
	// Example: "https://slsa.dev/provenance/v1"
	PredicateURI() string

	// Name returns a human-readable name for this attestor.
	// Example: "Git Repository Attestor"
	Name() string

	// Description returns a detailed description of what this attestor does.
	// Example: "Captures Git repository state including commits, branches, and tags"
	Description() string

	// ConfigSchema returns the configuration schema for this attestor.
	// The schema defines required and optional fields with their types and defaults.
	ConfigSchema() []ConfigField

	// ValidateConfig validates the provided configuration against this attestor's schema.
	// Returns an error if the configuration is invalid.
	ValidateConfig(Config) error

	// PreAttest runs before the attestation process.
	// Use this for setup, validation, and preparation tasks.
	// Receives the full configuration and a context for cancellation.
	PreAttest(ctx context.Context, config Config) error

	// Attest performs the actual attestation work.
	// This is where the main attestation logic runs.
	// Receives the full configuration and a context for cancellation.
	Attest(ctx context.Context, config Config) error

	// PostAttest runs after the attestation process.
	// Use this for cleanup, reporting, and post-processing tasks.
	// Receives the full configuration and a context for cancellation.
	PostAttest(ctx context.Context, config Config) error

	// GeneratePredicate generates the predicate data for the attestation.
	// The returned value will be serialized as the "predicate" field
	// in the in-toto statement.
	GeneratePredicate(config Config) (any, error)

	// Subjects returns the in-toto subjects for the attestation.
	// Subjects identify what the attestation is about (files, artifacts, etc.).
	Subjects(config Config) []intoto.Subject

	// Schema returns the JSON schema for the predicate.
	// This is used for validation and documentation.
	Schema() *jsonschema.Schema
}
