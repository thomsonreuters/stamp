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

// Package v1 provides version 1 predicate definitions for GitHub Actions workflow attestations.
package v1

import (
	"encoding/json"
)

const (
	// PredicateURI is the custom predicate type URI for GitHub Actions workflow attestations.
	// Following in-toto specification for custom predicate types.
	PredicateURI = "https://github.com/thomsonreuters/stamp/github-workflow/v1"
)

type Predicate struct {
	Workflow   WorkflowInfo   `json:"workflow"`
	Runner     RunnerInfo     `json:"runner"`
	Trigger    TriggerInfo    `json:"trigger"`
	Repository RepositoryInfo `json:"repository"`
	Metadata   MetadataInfo   `json:"metadata"`
	OIDC       *OIDCInfo      `json:"oidc,omitempty"` // OIDC token information and verification
}

// WorkflowInfo contains workflow identification and execution details.
type WorkflowInfo struct {
	Name           string `json:"name"`                       // OIDC claim: workflow
	Ref            string `json:"ref"`                        // OIDC claim: workflow_ref
	SHA            string `json:"sha"`                        // OIDC claim: workflow_sha
	JobWorkflowRef string `json:"job_workflow_ref,omitempty"` // OIDC claim: job_workflow_ref
	RunID          string `json:"run_id"`                     // OIDC claim: run_id
	RunNumber      int    `json:"run_number"`                 // OIDC claim: run_number
	RunAttempt     int    `json:"run_attempt"`                // OIDC claim: run_attempt
	Job            string `json:"job"`                        // Reference: GITHUB_JOB (not in OIDC)
	Action         string `json:"action,omitempty"`           // Reference: GITHUB_ACTION (not in OIDC)
	ActionPath     string `json:"action_path,omitempty"`      // Reference: GITHUB_ACTION_PATH (not in OIDC)
}

// RunnerInfo represents the GitHub Actions runner environment.
type RunnerInfo struct {
	Name        string            `json:"name"`                  // Reference: RUNNER_NAME (not in OIDC)
	OS          string            `json:"os"`                    // Reference: RUNNER_OS (not in OIDC)
	Arch        string            `json:"arch"`                  // Reference: RUNNER_ARCH (not in OIDC)
	HostedType  string            `json:"hosted_type,omitempty"` // OIDC claim: runner_environment
	Environment map[string]string `json:"environment,omitempty"` // Filtered environment variables (not in OIDC)
}

// TriggerInfo contains workflow trigger event information.
type TriggerInfo struct {
	EventName        string          `json:"event_name"`                   // OIDC claim: event_name
	Actor            string          `json:"actor"`                        // OIDC claim: actor
	ActorID          string          `json:"actor_id"`                     // OIDC claim: actor_id
	EventPayload     json.RawMessage `json:"event_payload,omitempty"`      // Reference: GITHUB_EVENT_PATH (not in OIDC)
	EventPayloadSize int64           `json:"event_payload_size,omitempty"` // Derived - Event payload file size (not in OIDC)
	HeadRef          string          `json:"head_ref,omitempty"`           // OIDC claim: head_ref - Source branch for PR
	BaseRef          string          `json:"base_ref,omitempty"`           // OIDC claim: base_ref - Target branch for PR
}

// RepositoryInfo contains repository context information.
type RepositoryInfo struct {
	FullName   string `json:"full_name"`            // OIDC claim: repository
	Owner      string `json:"owner"`                // OIDC claim: repository_owner
	OwnerID    string `json:"owner_id"`             // OIDC claim: repository_owner_id
	ID         string `json:"id"`                   // OIDC claim: repository_id
	Visibility string `json:"visibility,omitempty"` // OIDC claim: repository_visibility
	SHA        string `json:"sha"`                  // OIDC claim: sha
	Ref        string `json:"ref"`                  // OIDC claim: ref
	RefName    string `json:"ref_name"`             // Reference: GITHUB_REF_NAME (not in OIDC)
	RefType    string `json:"ref_type"`             // OIDC claim: ref_type
}

// MetadataInfo contains workflow execution metadata.
type MetadataInfo struct {
	ServerURL string `json:"server_url,omitempty"` // Reference: GITHUB_SERVER_URL - GitHub server URL
}

// OIDCInfo contains OIDC token information from GitHub Actions.
type OIDCInfo struct {
	// Token metadata
	TokenHash string `json:"token_hash"` // SHA256 hash of the OIDC token

	// Standard claims (RFC 7519)
	Issuer    string `json:"issuer"`               // iss - Token issuer (e.g., https://token.actions.githubusercontent.com)
	Subject   string `json:"subject"`              // sub - Subject identifier
	Audience  any    `json:"audience"`             // aud - Intended audience (string or array)
	ExpiresAt int64  `json:"expires_at,omitempty"` // exp - Expiration timestamp
	IssuedAt  int64  `json:"issued_at,omitempty"`  // iat - Issued at timestamp
	NotBefore int64  `json:"not_before,omitempty"` // nbf - Not before timestamp
	JWTID     string `json:"jwt_id,omitempty"`     // jti - JWT ID

	// Verification metadata
	Verified     bool   `json:"verified"`                // Whether token signature was verified
	VerifiedAt   int64  `json:"verified_at,omitempty"`   // Timestamp of verification
	VerifyMethod string `json:"verify_method,omitempty"` // Method used for verification (e.g., "oidc-discovery")
	VerifySource string `json:"verify_source,omitempty"` // Source of verification keys (JWKS URL)
	KeyAlgorithm string `json:"key_algorithm,omitempty"` // Algorithm used for signature
	KeyID        string `json:"key_id,omitempty"`        // Key ID from token header
	DiscoveryURL string `json:"discovery_url,omitempty"` // OIDC discovery URL used
	FetchedAt    int64  `json:"fetched_at,omitempty"`    // Timestamp when token was fetched
}
