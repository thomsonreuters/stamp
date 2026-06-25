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

package transparency

import "errors"

// Upload errors.
var (
	// ErrNoVerifiers indicates no verifiers found for upload.
	ErrNoVerifiers = errors.New("no verifiers found")
)

// Verify errors.
var (
	// ErrAttestationNotInLog indicates attestation was not found in transparency log.
	ErrAttestationNotInLog = errors.New("attestation not found in log")

	// ErrDuplicateEntries indicates multiple entries found for same attestation.
	ErrDuplicateEntries = errors.New("duplicate entries found")

	// ErrNoVerificationData indicates entry has no verification data.
	ErrNoVerificationData = errors.New("no verification data")

	// ErrNoInclusionProof indicates entry has no inclusion proof.
	ErrNoInclusionProof = errors.New("no inclusion proof")

	// ErrMissingProofFields indicates required proof fields are missing.
	ErrMissingProofFields = errors.New("missing proof fields")

	// ErrProofTreeSizeExceeds indicates proof tree size exceeds current log size.
	ErrProofTreeSizeExceeds = errors.New("proof tree size exceeds current tree size")

	// ErrNoBodyInEntry indicates entry has no body.
	ErrNoBodyInEntry = errors.New("no body in entry")
)

// Fetch errors.
var (
	// ErrNoEntryFound indicates no entry was found for the given search.
	ErrNoEntryFound = errors.New("no entry found")
)

// Temporal validation errors.
var (
	// ErrNoTimestamp indicates entry has no timestamp.
	ErrNoTimestamp = errors.New("no timestamp in entry")

	// ErrCertExpiredBeforeEntry indicates entry was added after certificate expired.
	ErrCertExpiredBeforeEntry = errors.New("entry added after certificate expired")

	// ErrCertNotYetValid indicates entry was added before certificate was valid.
	ErrCertNotYetValid = errors.New("entry added before certificate valid")
)
