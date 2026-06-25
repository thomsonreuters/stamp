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

package verification

import (
	"context"

	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/types"
)

type VerifierIface interface {
	Verify(ctx context.Context, envelope *intoto.Envelope) (*VerificationResult, error)
}

// VerificationResult represents the result of attestation verification.
type VerificationResult struct {
	Valid            bool     `json:"valid"`
	SignatureValid   bool     `json:"signature_valid"`
	CertificateValid bool     `json:"certificate_valid,omitempty"`
	RekorValid       bool     `json:"rekor_valid,omitempty"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`

	// Attestation metadata
	AttestationPath string `json:"attestation_path,omitempty"`
	AttestationHash string `json:"attestation_hash,omitempty"`
	RekorEntryUUID  string `json:"rekor_entry_uuid,omitempty"`
}

// VerificationConfig holds configuration for verification.
type VerificationConfig struct {
	// Signature verification
	PublicKeyPath string

	// Rekor verification
	RekorURL    string
	VerifyRekor bool

	// Fulcio configuration
	FulcioURL string

	// Temporal validation policy for Rekor entries
	RekorTemporalPolicy types.TemporalPolicy

	// Security settings
	Insecure bool
}
