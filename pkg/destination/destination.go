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

// Package destination provides a unified, pluggable system for outputting attestations
// to various backends including files, object storage, APIs, and more.
//
// The destination system provides a consistent, extensible framework that treats all
// output mechanisms as first-class destinations. Each destination type implements the
// Destination interface and registers itself via the Registry pattern for automatic
// discovery and instantiation.
//
// Key Features:
//   - Pluggable architecture for easy extension
//   - Template-based path/key naming with variable substitution
//   - Parallel and sequential write operations
//   - Comprehensive error handling with retry logic
//   - Health checks and graceful shutdown support
//   - Thread-safe implementations
package destination

import (
	"context"
	"time"
)

// Destination represents an output backend for attestations.
// Implementations must be thread-safe and handle retries internally.
//
// All methods must be safe for concurrent use. Implementations should
// handle temporary failures internally with retry logic before returning
// an error to the caller. Health checks should be lightweight operations
// that validate connectivity without performing expensive operations.
//
// The lifecycle of a Destination is:
//  1. Creation via factory function
//  2. Configuration validation with ValidateConfig
//  3. Configuration application with Configure
//  4. Optional health check with HealthCheck
//  5. Write operations with Write/WriteBatch
//  6. Resource cleanup with Close
type Destination interface {
	// Type returns the destination type identifier (e.g., "file", "s3").
	// This is used for registration and CLI display. Must be unique across
	// all registered destination types and should follow kebab-case naming.
	Type() string

	// Name returns the human-readable name of this destination type.
	// This is used for CLI help and documentation display.
	Name() string

	// Description returns a brief description of what this destination does.
	// Should be a single sentence explaining the destination's purpose.
	Description() string

	// Write sends an attestation to the destination.
	// The context is used for timeout control and cancellation.
	// Implementations should handle retries internally and return meaningful
	// errors wrapped with destination context. The attestation must not be nil.
	// Returns WriteResult with details about the successful write operation.
	Write(ctx context.Context, attestation *Attestation) (*WriteResult, error)

	// WriteBatch sends multiple attestations to the destination.
	// Implementations can optimize for bulk operations or fall back to
	// individual Write calls. The context applies to the entire batch operation.
	// The opts parameter provides pipeline context (e.g., specification name) needed
	// for path template resolution and other destination-specific behavior.
	// Returns one WriteResult per attestation in the same order as input.
	// If any write fails, the error is returned and partial results may be included.
	WriteBatch(ctx context.Context, attestations []*Attestation, opts WriteOptions) ([]*WriteResult, error)

	// ValidateConfig validates destination-specific configuration.
	// This is called before Configure and should check all required fields
	// and validate their values without applying them. Returns detailed
	// validation errors that can guide users in fixing configuration issues.
	ValidateConfig(config map[string]any) error

	// Configure applies the validated configuration to the destination.
	// This should only be called after ValidateConfig succeeds.
	// The destination should update its internal state to use the new
	// configuration. This method may be called multiple times to reconfigure.
	Configure(config map[string]any) error

	// HealthCheck verifies the destination is accessible and functional.
	// This should be a lightweight operation that validates connectivity
	// and basic functionality without performing expensive operations.
	// The context timeout should be respected for network operations.
	HealthCheck(ctx context.Context) error

	// GetConfigSchema returns the configuration schema for this destination.
	// This is used for validation, CLI documentation, and help generation.
	// The schema should include all configuration fields with their types,
	// requirements, defaults, and example values.
	GetConfigSchema() []ConfigField

	// Close releases any resources held by the destination.
	// This is called during graceful shutdown and should clean up connections,
	// file handles, and other resources. Should respect context timeout
	// for graceful shutdown operations.
	Close(ctx context.Context) error

	// SupportsAggregate indicates whether this destination can write multiple
	// items as a single aggregated output.
	// When true, the destination can handle aggregate mode (combining multiple
	// attestations into one file/object/request).
	// When false, aggregate mode configuration will be rejected during validation.
	SupportsAggregate() bool
}

// Attestation contains the data to be written to a destination.
// This structure provides all the information a destination might need
// for naming, tagging, or organizing the output. All fields are populated
// by the pipeline before passing to destinations.
type Attestation struct {
	// ID is a unique identifier for this attestation (UUID v4)
	ID string

	// AttestorID identifies the attestor that generated this attestation.
	// For individual attestations, this is the attestor name (e.g., "git", "command-run").
	// For collection attestations, this is the collection name.
	// Used for path template resolution (${attestor} variable).
	AttestorID string

	// PredicateType is the URI identifying the predicate type
	PredicateType string

	// Bundle holds the serialized sigstore Bundle v0.3. Destinations
	// persist these bytes verbatim.
	Bundle []byte

	// Timestamp is when the attestation was generated
	Timestamp time.Time

	// SHA256 is the hash of the bundle content
	SHA256 string

	// Size is the size of the serialized bundle in bytes
	Size int64

	// IsCollection indicates if this is a collection attestation
	IsCollection bool

	// CollectionName is the name of the collection (for collection attestations)
	CollectionName string

	// CollectionMembers lists the attestation IDs in this collection
	CollectionMembers []string

	// WorkflowName is the name of the workflow that generated this attestation.
	// Used for path template resolution (${workflow} variable).
	// Empty for attestations generated outside of a workflow context.
	WorkflowName string
}

// WriteResult contains the result of a successful write operation.
// This structure provides information about where the attestation was
// written and includes destination-specific metadata for tracking and
// verification purposes.
type WriteResult struct {
	// Location is where the attestation was written (path, URL, etc.)
	Location string

	// ID is a destination-specific identifier (e.g., S3 ETag, database ID)
	ID string

	// Timestamp is when the write completed
	Timestamp time.Time

	// Metadata contains destination-specific metadata
	Metadata map[string]string

	// Size is the actual size written (may differ due to compression)
	Size int64
}

// WriteOptions controls write behavior for batch operations.
type WriteOptions struct {
	// Parallel enables parallel writes to all destinations
	Parallel bool

	// FailurePolicy defines how to handle destination failures
	FailurePolicy FailurePolicy

	// QuorumCount is the minimum successful writes required (for QuorumPolicy)
	QuorumCount int

	// Destinations specifies which destinations to write to (empty = all)
	Destinations []string

	// Timeout overrides the default timeout
	Timeout time.Duration

	// OutputMode controls what gets written (for batch operations)
	OutputMode OutputMode

	// WorkflowName is the name of the workflow being executed
	// This provides pipeline context for path template resolution (e.g., ${workflow})
	WorkflowName string
}

// FailurePolicy defines how to handle partial failures.
type FailurePolicy string

const (
	// FailurePolicyIgnore continues and logs errors.
	FailurePolicyIgnore FailurePolicy = "ignore"

	// FailurePolicyWarn continues but warns prominently.
	FailurePolicyWarn FailurePolicy = "warn"

	// FailurePolicyFailFast stops on first error.
	FailurePolicyFailFast FailurePolicy = "fail-fast"

	// FailurePolicyQuorum requires N successful writes.
	FailurePolicyQuorum FailurePolicy = "quorum"
)

// OutputMode defines what attestations to write.
type OutputMode string

const (
	// OutputModeIndividual writes only individual attestations.
	OutputModeIndividual OutputMode = "individual"

	// OutputModeCollection writes only collection attestation.
	OutputModeCollection OutputMode = "collection"

	// OutputModeBoth writes both individual and collection.
	OutputModeBoth OutputMode = "both"
)

// ConfigField describes a configuration parameter for a destination.
// This is used for validation, CLI help, and documentation generation.
// Each field defines the structure, constraints, and documentation for
// a single configuration parameter that users can set.
type ConfigField struct {
	// Name is the configuration key name
	Name string

	// Type is the data type (string, int, bool, []string, map[string]string)
	Type string

	// Required indicates if this field must be provided
	Required bool

	// Default is the default value if not specified
	Default any

	// Description explains what this configuration does
	Description string

	// EnvVar is an optional environment variable that can provide the value
	EnvVar string

	// Sensitive indicates if this contains secrets (for masking in logs)
	Sensitive bool

	// Validator is an optional function to validate the value
	Validator func(any) error

	// Examples are example values for documentation
	Examples []string
}
