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

package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/signing/sigstore"
	"github.com/thomsonreuters/stamp/pkg/trust"
	"github.com/thomsonreuters/stamp/pkg/validation"
	"github.com/thomsonreuters/stamp/pkg/verification"
)

// VerifyOp verifies a sigstore Bundle v0.3 attestation.
type VerifyOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
}

// VerifyOutcome is the CLI-facing outcome of stamp verify. Wraps sigstore-go's
// VerificationResult with operational metadata (path, hash) and flat booleans
// suitable for JSON output. The field shape is stable across the C3 refactor
// — external scripts that parsed the pre-C3 JSON output continue to work.
type VerifyOutcome struct {
	Valid            bool     `json:"valid"`
	SignatureValid   bool     `json:"signature_valid"`
	CertificateValid bool     `json:"certificate_valid,omitempty"`
	RekorValid       bool     `json:"rekor_valid,omitempty"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`

	AttestationPath string `json:"attestation_path,omitempty"`
	AttestationHash string `json:"attestation_hash,omitempty"`
	RekorEntryUUID  string `json:"rekor_entry_uuid,omitempty"`

	VerifiedSAN    string `json:"verified_san,omitempty"`
	VerifiedIssuer string `json:"verified_issuer,omitempty"`
}

// Validate checks that the verify operation has valid input parameters.
func (o *VerifyOp) Validate(attestationPath string) error {
	validator := pkgerrors.NewValidator()

	if attestationPath == "" {
		validator.AddError("arguments", "attestation file path is required")
	} else {
		opts := validation.FileValidationOptions{
			MaxSize:       MaxAttestationFileSize,
			AllowEmpty:    false,
			RequireExists: true,
			FileType:      "attestation",
		}
		if err := validation.ValidateFile(attestationPath, opts); err != nil {
			validator.AddError("file", fmt.Sprintf("invalid attestation file: %v", err))
		}
	}

	outputPath := o.config.GetString(flags.VerifyOutputFile)
	if outputPath != "" {
		if fileInfo, err := os.Stat(outputPath); err == nil {
			if fileInfo.IsDir() {
				validator.AddError("output-verification", fmt.Sprintf("output path is a directory: %s", outputPath))
			}
		}
	}

	if validator.HasErrors() {
		_ = validator.Suggest(
			"Specify path to a .sigstore.json attestation file as first argument",
			"Example: stamp verify attestation.sigstore.json --rekor",
			"Use --rekor to require transparency-log inclusion",
			"Use --expected-san / --expected-issuer to enforce identity policy",
		)
		return validator
	}

	return nil
}

// Execute performs the verification operation on the attestation file.
func (o *VerifyOp) Execute(ctx context.Context, attestationPath string) error {
	o.logger.InfoContext(ctx, "starting attestation verification", "attestation_path", attestationPath)
	o.output.Progress("Verifying attestation: %s", attestationPath)

	attestationData, err := os.ReadFile(attestationPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "file", "read", "failed to read attestation file")
	}
	hash := sha256.Sum256(attestationData)
	hashHex := hex.EncodeToString(hash[:])

	b, err := sgbundle.LoadJSONFromPath(attestationPath)
	if err != nil {
		parseErr := pkgerrors.WrapWithContext(err, "parse", "attestation",
			"failed to parse attestation file")
		_ = parseErr.Suggest(
			"stamp verify only accepts .sigstore.json files",
			"Re-generate the attestation with `stamp run`",
		)
		return parseErr
	}

	tm, err := o.resolveTrustMaterial(ctx)
	if err != nil {
		return err
	}

	verifyRekor := o.config.GetBool(flags.TransparencyEnable)
	cfg := verification.Config{
		VerifyRekor:         verifyRekor,
		ExpectedSAN:         o.config.GetString(flags.VerifyExpectedSAN),
		ExpectedSANRegex:    o.config.GetString(flags.VerifyExpectedSANRegex),
		ExpectedIssuer:      o.config.GetString(flags.VerifyExpectedIssuer),
		ExpectedIssuerRegex: o.config.GetString(flags.VerifyExpectedIssuerRegex),
	}

	o.logger = o.logger.With(
		"verify_rekor", verifyRekor,
		"expected_san", cfg.ExpectedSAN,
		"expected_issuer", cfg.ExpectedIssuer,
	)
	o.logger.DebugContext(ctx, "verification configuration built")

	if verifyRekor {
		o.output.Progress("Verifying signature and Rekor inclusion...")
	} else {
		o.output.Progress("Verifying signature...")
	}

	sigRes, verifyErr := verification.Verify(ctx, tm, b, cfg)
	if verifyErr != nil {
		return o.handleVerificationFailure(ctx, verifyErr, attestationPath, hashHex)
	}

	outcome := outcomeFromResult(sigRes, attestationPath, hashHex, verifyRekor)

	o.logger.InfoContext(ctx, "verification completed",
		"valid", outcome.Valid,
		"signature_valid", outcome.SignatureValid,
		"certificate_valid", outcome.CertificateValid,
		"rekor_valid", outcome.RekorValid,
	)

	o.renderVerificationSuccess(outcome)

	if outputErr := o.output.Data(o.logger, "verification result", outcome); outputErr != nil {
		o.logger.WarnContext(ctx, "failed to output verification result", "error", outputErr.Error())
	}

	if err := o.maybeWriteResultFile(ctx, outcome); err != nil {
		return err
	}

	o.logger.InfoContext(ctx, "verify command completed successfully")
	return nil
}

// resolveTrustMaterial returns the TrustedMaterial the verifier should use.
// For --public-key invocations, wraps the base trust anchor so the caller's
// pubkey answers TrustedMaterial.PublicKeyVerifier(hint) — required for
// user-key bundles that carry only a fingerprint. Fulcio-signed bundles skip
// the wrap: the cert carries identity inline.
func (o *VerifyOp) resolveTrustMaterial(ctx context.Context) (sgroot.TrustedMaterial, error) {
	trustedRoot, err := trust.ResolveTrustedRoot(ctx, o.config, o.logger)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "verify", "trust_resolve",
			"failed to resolve trusted root")
	}
	var tm sgroot.TrustedMaterial = trustedRoot

	pubKeyPath := o.config.GetString(flags.VerifyPublicKey)
	if pubKeyPath == "" {
		return tm, nil
	}
	pubKey, err := keys.LoadPublicKeyFromFile(pubKeyPath)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "verify", "load_public_key",
			fmt.Sprintf("failed to load public key: %s", pubKeyPath))
	}
	wrapped, err := sigstore.NewSignerKeyTrustedMaterial(tm, pubKey)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "verify", "wrap_public_key",
			"failed to wrap public key into trusted material")
	}
	return wrapped, nil
}

func (o *VerifyOp) handleVerificationFailure(ctx context.Context, verifyErr error, path, hashHex string) error {
	outcome := VerifyOutcome{
		Valid:           false,
		AttestationPath: path,
		AttestationHash: hashHex,
		Errors:          []string{verifyErr.Error()},
	}

	o.logger.ErrorContext(ctx, "verification failed", "error", verifyErr.Error())
	o.output.Error("Attestation verification failed")
	o.output.List("%s", verifyErr.Error())
	if outErr := o.output.Data(o.logger, "verification result", outcome); outErr != nil {
		o.logger.WarnContext(ctx, "failed to output verification result", "error", outErr.Error())
	}
	if writeErr := o.maybeWriteResultFile(ctx, outcome); writeErr != nil {
		return writeErr
	}

	wrap := pkgerrors.WrapWithContext(verifyErr, "verify", "verification", "verification failed")
	_ = wrap.Suggest(
		"Check trust configuration (--tuf-url / --trusted-root)",
		"Ensure network connectivity to Rekor if --rekor is enabled",
		"Verify the bundle was produced against the expected sigstore deployment",
	)
	return wrap
}

func (o *VerifyOp) maybeWriteResultFile(ctx context.Context, outcome VerifyOutcome) error {
	outputPath := o.config.GetString(flags.VerifyOutputFile)
	if outputPath == "" {
		return nil
	}
	jsonData, err := json.Marshal(outcome)
	if err != nil {
		return pkgerrors.Wrap(err, "failed to marshal verification result to JSON")
	}
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		fileErr := pkgerrors.WrapWithContext(err, "file", "write",
			fmt.Sprintf("failed to write output file: %s", outputPath))
		_ = fileErr.Suggest(
			"Check file permissions and directory exists",
			"Ensure path is not a directory",
			"Verify sufficient disk space",
		)
		return fileErr
	}
	o.logger.InfoContext(ctx, "verification result saved to file",
		"output_path", outputPath, "size_bytes", len(jsonData))
	o.output.Success("Verification result also saved to: %s", outputPath)
	return nil
}

func (o *VerifyOp) renderVerificationSuccess(oc VerifyOutcome) {
	o.output.Success("Attestation verification passed")
	o.output.List("Signature valid")
	if oc.CertificateValid {
		o.output.List("Certificate valid")
	}
	if oc.RekorValid {
		o.output.List("Rekor inclusion verified")
	}
	if oc.VerifiedSAN != "" {
		o.output.List("SAN: %s", oc.VerifiedSAN)
	}
	if oc.VerifiedIssuer != "" {
		o.output.List("Issuer: %s", oc.VerifiedIssuer)
	}
}

// outcomeFromResult flattens sigstore-go's VerificationResult into the
// CLI-facing shape. All boolean fields are true (Valid, SignatureValid) or
// derived (CertificateValid) — verification.Verify returned success, so we're
// past every crypto check.
func outcomeFromResult(sigRes *sgverify.VerificationResult, path, hash string, rekorRequested bool) VerifyOutcome {
	o := VerifyOutcome{
		Valid:           true,
		SignatureValid:  true,
		RekorValid:      rekorRequested,
		AttestationPath: path,
		AttestationHash: hash,
	}
	if sigRes.Signature != nil && sigRes.Signature.Certificate != nil {
		o.CertificateValid = true
	}
	if sigRes.VerifiedIdentity != nil {
		o.VerifiedSAN = sigRes.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
		o.VerifiedIssuer = sigRes.VerifiedIdentity.Issuer.Issuer
	}
	for _, ts := range sigRes.VerifiedTimestamps {
		if ts.Type == "Tlog" {
			o.RekorEntryUUID = hex.EncodeToString([]byte(ts.URI))
			break
		}
	}
	return o
}

// NewVerifyOp creates a new VerifyOp instance with the provided configuration, logger, and output handler.
func NewVerifyOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *VerifyOp {
	return &VerifyOp{
		config: config,
		logger: logger,
		output: output,
	}
}
