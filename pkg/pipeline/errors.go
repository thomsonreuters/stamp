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

import "errors"

// Signer errors.
var (
	// ErrUnsupportedSigningBackend indicates the signing backend is not supported.
	ErrUnsupportedSigningBackend = errors.New("unsupported signing backend")

	// ErrSignerInitFailed indicates signer initialization failed.
	ErrSignerInitFailed = errors.New("failed to initialize signer")

	// ErrSigningFailed indicates envelope signing failed.
	ErrSigningFailed = errors.New("failed to sign envelope")

	// ErrGetSignerFailed indicates failed to get signer.
	ErrGetSignerFailed = errors.New("failed to get signer")
)

// Attestor errors.
var (
	// ErrAttestorNotFound indicates attestor was not found in registry.
	ErrAttestorNotFound = errors.New("attestor not found")

	// ErrAttestorConfigFailed indicates failed to get attestor configuration.
	ErrAttestorConfigFailed = errors.New("failed to get attestor configuration")

	// ErrAttestorConfigUnmarshalFailed indicates failed to unmarshal attestor configuration.
	ErrAttestorConfigUnmarshalFailed = errors.New("failed to unmarshal attestor configuration")

	// ErrAttestorConfigValidationFailed indicates attestor configuration validation failed.
	ErrAttestorConfigValidationFailed = errors.New("attestor configuration validation failed")

	// ErrSetFlagsParsingFailed indicates --set flags parsing failed.
	ErrSetFlagsParsingFailed = errors.New("failed to parse --set flags")

	// ErrPreAttestFailed indicates pre-attest phase failed.
	ErrPreAttestFailed = errors.New("pre-attest phase failed")

	// ErrAttestFailed indicates attest phase failed.
	ErrAttestFailed = errors.New("attest phase failed")

	// ErrPostAttestFailed indicates post-attest phase failed.
	ErrPostAttestFailed = errors.New("post-attest phase failed")

	// ErrPredicateGenerationFailed indicates predicate generation failed.
	ErrPredicateGenerationFailed = errors.New("predicate generation failed")
)

// Envelope errors.
var (
	// ErrStatementCreateFailed indicates in-toto statement creation failed.
	ErrStatementCreateFailed = errors.New("failed to create statement")

	// ErrEnvelopeCreateFailed indicates DSSE envelope creation failed.
	ErrEnvelopeCreateFailed = errors.New("failed to create envelope")

	// ErrEnvelopeConvertFailed indicates envelope conversion failed.
	ErrEnvelopeConvertFailed = errors.New("failed to convert envelope")
)

// Output errors.
var (
	// ErrStdoutWriteFailed indicates stdout write failed.
	ErrStdoutWriteFailed = errors.New("failed to write to stdout")

	// ErrInvalidOutputMode indicates invalid output mode.
	ErrInvalidOutputMode = errors.New("invalid output mode")
)

// Workflow errors.
var (
	// ErrWorkflowLoadFailed indicates failed to load workflows.
	ErrWorkflowLoadFailed = errors.New("failed to load workflows")

	// ErrWorkflowNotFound indicates workflow was not found.
	ErrWorkflowNotFound = errors.New("workflow not found")

	// ErrWorkflowExecutionFailed indicates workflow execution failed.
	ErrWorkflowExecutionFailed = errors.New("workflow execution failed")
)

// Collection errors.
var (
	// ErrCollectionCreateFailed indicates failed to create collection.
	ErrCollectionCreateFailed = errors.New("failed to create collection")

	// ErrCollectionSignFailed indicates failed to sign collection.
	ErrCollectionSignFailed = errors.New("failed to sign collection")

	// ErrNoAttestationsForCollection indicates no attestations available for collection.
	ErrNoAttestationsForCollection = errors.New("no attestations available for collection")
)
