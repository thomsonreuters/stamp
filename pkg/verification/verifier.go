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
	"encoding/hex"
	"errors"
	"fmt"
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
// post-verify hooks (24h cert validity ceiling).
func (v *Verifier) Verify(ctx context.Context, b *bundle.Bundle) (*VerificationResult, error) {
	result := &VerificationResult{}

	if v.trustedMaterial == nil {
		result.Errors = append(result.Errors, "no trusted material available")
		return result, nil
	}

	verifierOpts := v.buildVerifierOptions(b)

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

func (v *Verifier) buildVerifierOptions(b *bundle.Bundle) []verify.VerifierOption {
	var opts []verify.VerifierOption

	// Long-lived key with no timestamp source: opt in to the no-timestamp
	// path. sigstore-go accepts this only when the bundle has no cert; cert
	// validity requires a signing time to bind to.
	if hasCert, _ := bundleHasCertificate(b); !hasCert && !bundleHasTimestamp(b) {
		opts = append(opts, verify.WithNoObserverTimestamps())
	} else {
		opts = append(opts, verify.WithObserverTimestamps(1))
	}

	if v.config.VerifyRekor {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	if v.config.RequireSCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	return opts
}

func bundleHasCertificate(b *bundle.Bundle) (bool, error) {
	vc, err := b.VerificationContent()
	if err != nil {
		return false, err
	}
	return vc.Certificate() != nil, nil
}

func bundleHasTimestamp(b *bundle.Bundle) bool {
	pb := b.Bundle
	if pb == nil {
		return false
	}
	if vm := pb.GetVerificationMaterial(); vm != nil {
		if len(vm.GetTlogEntries()) > 0 {
			return true
		}
		if ts := vm.GetTimestampVerificationData(); ts != nil && len(ts.GetRfc3161Timestamps()) > 0 {
			return true
		}
	}
	return false
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
	if len(stmt.GetSubject()) == 0 {
		return verify.PolicyBuilder{}, errors.New("bundle: statement has no subjects")
	}

	var artifactOpt verify.ArtifactPolicyOption
	for _, subj := range stmt.GetSubject() {
		for algo, hex := range subj.GetDigest() {
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

	hasCert, err := bundleHasCertificate(b)
	if err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("bundle: verification content: %w", err)
	}

	var policyOpts []verify.PolicyOption
	if !hasCert {
		// Key-signed bundle: WithKey requires the bundle be key-signed
		// (rejects a mis-labeled cert bundle) and disables identity checks.
		policyOpts = append(policyOpts, verify.WithKey())
	} else {
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
			return verify.PolicyBuilder{}, errors.New(
				"cert-signed bundle requires identity policy: pass --expected-san / --expected-issuer, or --allow-unverified-identity to skip")
		}
	}

	return verify.NewPolicy(artifactOpt, policyOpts...), nil
}

// applyPostVerifyHooks enforces stamp-specific certificate policies. Today
// this is a single rule: cert validity must be <= MaxCertValidityDuration.
// Fulcio issues short-lived certs (10 min default); anything > 24 h is
// suspect and rejected here even though sigstore-go accepted the chain.
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
	return nil
}

func identityConfigured(cfg VerificationConfig) bool {
	return cfg.ExpectedSAN != "" || cfg.ExpectedSANRegex != "" ||
		cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerRegex != ""
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
