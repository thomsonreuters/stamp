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
	"fmt"

	"github.com/thomsonreuters/stamp/pkg/crypto/dsse"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Verifier handles attestation verification.
type Verifier struct {
	logger logger.Logger
	config VerificationConfig
}

// Verify performs comprehensive verification of an attestation envelope.
func (v *Verifier) Verify(ctx context.Context, envelope *intoto.Envelope) (*VerificationResult, error) {
	result := &VerificationResult{}

	// Step 1: Verify DSSE signature
	sigValid, err := v.verifySignature(ctx, envelope)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", err))
		result.SignatureValid = false
	} else {
		result.SignatureValid = sigValid
	}

	// Step 2: Verify certificate (Fulcio certificates)
	if envelope.HasCertificate() {
		certValid, err := v.verifyCertificate(ctx, envelope)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("certificate verification failed: %v", err))
			result.CertificateValid = false
		} else {
			result.CertificateValid = certValid
		}
	}

	// Step 3: Verify Rekor inclusion
	if v.config.VerifyRekor {
		rekorValid, rekorWarnings, rekorUUID, err := v.verifyRekor(ctx, envelope)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("rekor verification failed: %v", err))
		}

		if rekorUUID != "" {
			result.RekorEntryUUID = rekorUUID
		}

		if len(rekorWarnings) > 0 {
			result.Warnings = append(result.Warnings, rekorWarnings...)
		}

		result.RekorValid = rekorValid
	}

	// Overall validity: only consider verifications that were actually performed
	result.Valid = result.SignatureValid
	if envelope.HasCertificate() {
		result.Valid = result.Valid && result.CertificateValid
	}
	if v.config.VerifyRekor {
		result.Valid = result.Valid && result.RekorValid
	}

	return result, nil
}

// verifySignature verifies the DSSE signature.
func (v *Verifier) verifySignature(ctx context.Context, envelope *intoto.Envelope) (bool, error) {
	valid, err := dsse.VerifyDSSESignature(ctx, envelope, v.config.PublicKeyPath)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// verifyCertificate verifies certificate validity and trust.
func (v *Verifier) verifyCertificate(ctx context.Context, envelope *intoto.Envelope) (bool, error) {
	if v.config.FulcioURL == "" {
		return false, ErrFulcioURLRequired
	}

	return v.verifyFulcioCertificate(ctx, envelope)
}

// New creates a new attestation verifier.
func New(config VerificationConfig, logger logger.Logger) VerifierIface {
	return &Verifier{
		config: config,
		logger: logger,
	}
}
