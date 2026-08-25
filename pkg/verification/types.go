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

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// VerifierIface is the public verifier interface.
type VerifierIface interface {
	Verify(ctx context.Context, b *bundle.Bundle) (*VerificationResult, error)
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

	VerifiedSAN    string `json:"verified_san,omitempty"`
	VerifiedIssuer string `json:"verified_issuer,omitempty"`
}

// VerificationConfig holds configuration for verification.
type VerificationConfig struct {
	// VerifyRekor requires the bundle to include a Rekor tlog inclusion proof.
	VerifyRekor bool

	// RequireSCT enforces embedded SignedCertificateTimestamp on the leaf.
	RequireSCT bool

	// Identity policy: exact-match value or regexp for the leaf cert's SAN
	// and OIDC issuer. When all four are empty, identity checking is left
	// unenforced.
	ExpectedSAN         string
	ExpectedSANRegex    string
	ExpectedIssuer      string
	ExpectedIssuerRegex string

	// AllowUnverifiedIdentity opts out of identity verification (unsafe).
	AllowUnverifiedIdentity bool
}
