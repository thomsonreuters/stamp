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

package v1

import "errors"

// HTTP response errors.
var (
	// ErrNonSuccessfulResponse is returned when the server responds with a non-2xx status code.
	ErrNonSuccessfulResponse = errors.New("rekor: non-successful HTTP response")

	// ErrUnauthorized is returned when authentication fails (HTTP 401).
	ErrUnauthorized = errors.New("rekor: unauthorized request")

	// ErrForbidden is returned when access is denied (HTTP 403).
	ErrForbidden = errors.New("rekor: access forbidden")

	// ErrBadRequest is returned when the request is malformed (HTTP 400).
	ErrBadRequest = errors.New("rekor: bad request")

	// ErrServerError is returned when the server encounters an internal error (HTTP 5xx).
	ErrServerError = errors.New("rekor: server error")
)

// Entry errors.
var (
	// ErrEntryNotFound is returned when the requested log entry does not exist.
	ErrEntryNotFound = errors.New("rekor: entry not found in transparency log")

	// ErrEntryAlreadyExists is returned when attempting to create a duplicate entry (HTTP 409).
	ErrEntryAlreadyExists = errors.New("rekor: entry already exists in transparency log")

	// ErrInvalidEntryFormat is returned when the entry format is invalid or cannot be parsed.
	ErrInvalidEntryFormat = errors.New("rekor: invalid entry format")
)

// Verification errors.
var (
	// ErrNoVerificationData is returned when an entry lacks verification metadata.
	ErrNoVerificationData = errors.New("rekor: entry missing verification data")

	// ErrNoInclusionProof is returned when an entry lacks an inclusion proof.
	ErrNoInclusionProof = errors.New("rekor: entry missing inclusion proof")

	// ErrInvalidInclusionProof is returned when the inclusion proof is malformed.
	ErrInvalidInclusionProof = errors.New("rekor: invalid inclusion proof")

	// ErrInclusionProofMismatch is returned when the inclusion proof verification fails.
	ErrInclusionProofMismatch = errors.New("rekor: inclusion proof does not match expected root hash")
)

// Retry errors.
var (
	// ErrMaxRetriesExceeded is returned when all retry attempts have been exhausted.
	ErrMaxRetriesExceeded = errors.New("rekor: maximum retry attempts exceeded")

	// ErrContextCanceled is returned when the operation is canceled via context.
	ErrContextCanceled = errors.New("rekor: operation canceled")
)

// Validation errors.
var (
	// ErrMissingHash is returned when hash is required but not provided.
	ErrMissingHash = errors.New("rekor: hash is required")

	// ErrMissingUUID is returned when UUID is required but not provided.
	ErrMissingUUID = errors.New("rekor: UUID is required")

	// ErrInvalidLogIndex is returned when the log index is invalid.
	ErrInvalidLogIndex = errors.New("rekor: invalid log index")
)
