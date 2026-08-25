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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// MaxCertValidityDuration bounds the leaf certificate lifetime accepted by
// stamp's post-verify hook. Fulcio issues short-lived (10 minute) certs by
// default; anything > 24 h is suspect.
const MaxCertValidityDuration = 24 * time.Hour

// deniedExtKeyUsages lists ExtKeyUsage OIDs that must never appear on the
// leaf certificate of a code-signing bundle. sigstore-go already requires
// CodeSigning, but does not enforce the absence of other usages.
var deniedExtKeyUsages = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "ServerAuth",
	x509.ExtKeyUsageClientAuth:      "ClientAuth",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
	x509.ExtKeyUsageEmailProtection: "EmailProtection",
}

// Verifier verifies a sigstore Bundle v0.3 against trust material and
// stamp-specific policy hooks.
type Verifier struct {
	logger          logger.Logger
	config          VerificationConfig
	trustedMaterial root.TrustedMaterial
}

// New creates a new attestation verifier bound to the given trusted material.
func New(config VerificationConfig, tm root.TrustedMaterial, log logger.Logger) VerifierIface {
	return &Verifier{
		config:          config,
		trustedMaterial: tm,
		logger:          log,
	}
}

// Verify verifies the given sigstore Bundle v0.3 and applies stamp-specific
// post-verify hooks (24h cert validity ceiling + ExtKeyUsage denylist).
func (v *Verifier) Verify(ctx context.Context, b *bundle.Bundle) (*VerificationResult, error) {
	result := &VerificationResult{}

	if v.trustedMaterial == nil {
		result.Errors = append(result.Errors, "no trusted material available")
		return result, nil
	}

	verifierOpts, err := v.buildVerifierOptions()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to build verifier config: %v", err))
		return result, nil
	}

	sv, err := verify.NewVerifier(v.trustedMaterial, verifierOpts...)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to init sigstore verifier: %v", err))
		return result, nil
	}

	policy, err := v.buildPolicy(b)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to build verification policy: %v", err))
		return result, nil
	}

	sigRes, err := sv.Verify(b, policy)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("sigstore verification failed: %v", err))
		return result, nil
	}

	result.SignatureValid = true
	if v.config.VerifyRekor {
		result.RekorValid = true
	}

	if certErr := v.applyPostVerifyHooks(b, result); certErr != nil {
		result.Errors = append(result.Errors, certErr.Error())
		result.CertificateValid = false
		return result, nil
	}

	if sigRes.VerifiedIdentity != nil {
		result.VerifiedSAN = sigRes.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
		result.VerifiedIssuer = sigRes.VerifiedIdentity.Issuer.Issuer
	}
	if sigRes.Signature != nil && sigRes.Signature.Certificate != nil {
		result.CertificateValid = true
	}
	if len(sigRes.VerifiedTimestamps) > 0 {
		for _, ts := range sigRes.VerifiedTimestamps {
			if ts.Type == "Tlog" {
				result.RekorEntryUUID = hex.EncodeToString([]byte(ts.URI))
				break
			}
		}
	}

	result.Valid = true
	return result, nil
}

func (v *Verifier) buildVerifierOptions() ([]verify.VerifierOption, error) {
	// sigstore-go requires at least one timestamp source; observer-timestamp
	// with threshold 1 accepts either tlog-integrated OR TSA.
	opts := []verify.VerifierOption{
		verify.WithObserverTimestamps(1),
	}
	if v.config.VerifyRekor {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	if v.config.RequireSCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	return opts, nil
}

// buildPolicy assembles the verification policy from the bundle's own
// statement subject digest plus any configured identity constraints.
//
// The subject digest is the authoritative binding between signature and
// payload for DSSE-shaped bundles, so we pass it to sigstore-go via
// WithArtifactDigest rather than re-hashing the on-disk file.
func (v *Verifier) buildPolicy(b *bundle.Bundle) (verify.PolicyBuilder, error) {
	sigContent, err := b.SignatureContent()
	if err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("bundle: signature content: %w", err)
	}
	envContent := sigContent.EnvelopeContent()
	if envContent == nil {
		return verify.PolicyBuilder{}, errors.New("bundle: only DSSE-envelope bundles are supported")
	}
	stmt, err := envContent.Statement()
	if err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("bundle: parse statement: %w", err)
	}
	if len(stmt.Subject) == 0 {
		return verify.PolicyBuilder{}, errors.New("bundle: statement has no subjects")
	}

	var artifactOpt verify.ArtifactPolicyOption
	for _, subj := range stmt.Subject {
		for algo, hex := range subj.Digest {
			raw, decodeErr := decodeHex(hex)
			if decodeErr != nil {
				return verify.PolicyBuilder{}, fmt.Errorf("bundle: decode subject digest: %w", decodeErr)
			}
			artifactOpt = verify.WithArtifactDigest(algo, raw)
			break
		}
		if artifactOpt != nil {
			break
		}
	}
	if artifactOpt == nil {
		return verify.PolicyBuilder{}, errors.New("bundle: no subject digest to bind policy to")
	}

	var policyOpts []verify.PolicyOption
	switch {
	case v.config.AllowUnverifiedIdentity:
		policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
	case identityConfigured(v.config):
		id, err := verify.NewShortCertificateIdentity(
			v.config.ExpectedIssuer, v.config.ExpectedIssuerRegex,
			v.config.ExpectedSAN, v.config.ExpectedSANRegex,
		)
		if err != nil {
			return verify.PolicyBuilder{}, fmt.Errorf("build certificate identity: %w", err)
		}
		policyOpts = append(policyOpts, verify.WithCertificateIdentity(id))
	default:
		policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
	}

	return verify.NewPolicy(artifactOpt, policyOpts...), nil
}

// applyPostVerifyHooks enforces stamp-specific certificate policies:
//  1. cert validity must be <= MaxCertValidityDuration
//  2. leaf ExtKeyUsage must not include ServerAuth / ClientAuth /
//     OCSPSigning / EmailProtection.
//
// sigstore-go already enforces the positive requirements (chain, CodeSigning
// EKU, KeyUsage DigitalSignature, SAN presence). These hooks defend against
// mis-issued Fulcio certs — even if the trust root somehow signs one, stamp
// still refuses to accept it.
func (v *Verifier) applyPostVerifyHooks(b *bundle.Bundle, _ *VerificationResult) error {
	vc, err := b.VerificationContent()
	if err != nil {
		return fmt.Errorf("bundle: verification content: %w", err)
	}
	cert := vc.Certificate()
	if cert == nil {
		return nil
	}

	if delta := cert.NotAfter.Sub(cert.NotBefore); delta > MaxCertValidityDuration {
		return fmt.Errorf("certificate validity too long: %s > %s (stamp policy)",
			delta, MaxCertValidityDuration)
	}

	var offending []string
	for _, eku := range cert.ExtKeyUsage {
		if name, denied := deniedExtKeyUsages[eku]; denied {
			offending = append(offending, name)
		}
	}
	if len(offending) > 0 {
		return fmt.Errorf("certificate extkeyusage includes forbidden usage(s): %s (stamp policy)",
			strings.Join(offending, ", "))
	}
	return nil
}

func identityConfigured(cfg VerificationConfig) bool {
	return cfg.ExpectedSAN != "" || cfg.ExpectedSANRegex != "" ||
		cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerRegex != ""
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
