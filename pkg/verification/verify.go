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

// Package verification wraps sigstore-go's verify pipeline with stamp's
// identity policy plus a single defense-in-depth check (24h cert-validity
// ceiling). The public API is one function — Verify — that returns
// sigstore-go's own VerificationResult; operational metadata (path, hash)
// is the caller's concern. Mirrors cosign's VerifyNewBundle shape.
package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// MaxCertValidityDuration bounds the leaf certificate lifetime accepted by
// stamp's post-verify hook. Fulcio issues short-lived (10 minute) certs by
// default; anything > 24 h is suspect.
const MaxCertValidityDuration = 24 * time.Hour

// Config holds the caller's verification policy inputs.
type Config struct {
	// VerifyRekor requires the bundle to include a Rekor tlog inclusion proof.
	VerifyRekor bool

	// Identity policy: exact-match value or regexp for the leaf cert's SAN
	// and OIDC issuer. At least one of these must be set for a Fulcio-signed
	// bundle; otherwise Verify returns an error.
	ExpectedSAN         string
	ExpectedSANRegex    string
	ExpectedIssuer      string
	ExpectedIssuerRegex string
}

// Verify runs sigstore-go's verification pipeline against b, applying cfg's
// identity policy plus stamp's 24h cert-validity check. Returns sigstore-go's
// own VerificationResult on success; operational metadata (path, hash) is
// the caller's concern.
func Verify(_ context.Context, tm root.TrustedMaterial, b *bundle.Bundle, cfg Config) (*verify.VerificationResult, error) {
	if tm == nil {
		return nil, errors.New("no trusted material available for verification")
	}
	if b == nil {
		return nil, errors.New("bundle is nil")
	}

	verifierOpts, policyOpts, err := cfg.options(b)
	if err != nil {
		return nil, err
	}

	sv, err := verify.NewVerifier(tm, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("init sigstore verifier: %w", err)
	}

	result, err := sv.Verify(b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), policyOpts...))
	if err != nil {
		return nil, fmt.Errorf("sigstore verification failed: %w", err)
	}

	if err := checkMaxCertValidity(b); err != nil {
		return nil, err
	}

	return result, nil
}

// options returns sigstore-go's verifier + policy options for the given
// bundle and config. Mirrors cosign's CheckOpts.verificationOptions.
func (cfg Config) options(b *bundle.Bundle) ([]verify.VerifierOption, []verify.PolicyOption, error) {
	hasCert, err := bundleHasCertificate(b)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: verification content: %w", err)
	}

	var verifierOpts []verify.VerifierOption
	// No cert AND no timestamp source → long-lived-key path. sigstore-go
	// accepts this only when the bundle has no cert; cert validity requires
	// a signing time to bind to.
	if !hasCert && !bundleHasTimestamp(b) {
		verifierOpts = append(verifierOpts, verify.WithNoObserverTimestamps())
	} else {
		verifierOpts = append(verifierOpts, verify.WithObserverTimestamps(1))
	}
	if cfg.VerifyRekor {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	var policyOpts []verify.PolicyOption
	if !hasCert {
		// Key-signed bundle: WithKey requires the bundle be key-signed
		// (rejects a mis-labeled cert bundle) and disables identity checks.
		policyOpts = append(policyOpts, verify.WithKey())
	} else {
		if !identityConfigured(cfg) {
			return nil, nil, errors.New(
				"cert-signed bundle requires identity policy: pass --expected-san / --expected-issuer")
		}
		id, err := verify.NewShortCertificateIdentity(
			cfg.ExpectedIssuer, cfg.ExpectedIssuerRegex,
			cfg.ExpectedSAN, cfg.ExpectedSANRegex,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build certificate identity: %w", err)
		}
		policyOpts = append(policyOpts, verify.WithCertificateIdentity(id))
	}

	return verifierOpts, policyOpts, nil
}

// checkMaxCertValidity enforces stamp's ceiling on leaf-cert lifetime.
// Fulcio issues short-lived certs (10 min default); anything > 24 h is
// suspect and rejected here even though sigstore-go accepted the chain.
func checkMaxCertValidity(b *bundle.Bundle) error {
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
	vm := pb.GetVerificationMaterial()
	if vm == nil {
		return false
	}
	if len(vm.GetTlogEntries()) > 0 {
		return true
	}
	if ts := vm.GetTimestampVerificationData(); ts != nil && len(ts.GetRfc3161Timestamps()) > 0 {
		return true
	}
	return false
}

func identityConfigured(cfg Config) bool {
	return cfg.ExpectedSAN != "" || cfg.ExpectedSANRegex != "" ||
		cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerRegex != ""
}
