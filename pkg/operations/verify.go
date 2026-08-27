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
			"Specify path to attestation bundle (.sigstore.json) as first argument",
			"Example: stamp verify attestation.sigstore.json --rekor",
			"Ensure attestation file exists and is readable",
			"Use --rekor to require tlog inclusion verification",
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

	b, err := sgbundle.LoadJSONFromPath(attestationPath)
	if err != nil {
		parseErr := pkgerrors.WrapWithContext(err, "parse", "attestation",
			"failed to parse attestation as sigstore Bundle v0.3")
		_ = parseErr.Suggest(
			"stamp verify accepts only .sigstore.json (Bundle v0.3) inputs",
			"Re-generate the attestation with `stamp run`/`stamp attest` on this branch",
			"For legacy DSSE envelopes, use an older stamp binary",
		)
		return parseErr
	}

	trustedRoot, err := trust.ResolveTrustedRoot(ctx, o.config, o.logger)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "verify", "trust_resolve",
			"failed to resolve trusted root")
	}
	var tm sgroot.TrustedMaterial = trustedRoot

	// Bundles signed with a long-lived user key need the pubkey injected
	// into the trusted material so hint-based lookup and Rekor CompareKey
	// resolve. Fulcio-signed bundles do not use this path.
	if pubKeyPath := o.config.GetString(flags.VerifyPublicKey); pubKeyPath != "" {
		pubKey, keyErr := keys.LoadPublicKeyFromFile(pubKeyPath)
		if keyErr != nil {
			return pkgerrors.WrapWithContext(keyErr, "verify", "load_public_key",
				fmt.Sprintf("failed to load public key: %s", pubKeyPath))
		}
		wrapped, wrapErr := sigstore.NewSignerKeyTrustedMaterial(tm, pubKey)
		if wrapErr != nil {
			return pkgerrors.WrapWithContext(wrapErr, "verify", "wrap_public_key",
				"failed to wrap public key into trusted material")
		}
		tm = wrapped
	}

	verifyRekor := o.config.GetBool(flags.TransparencyEnable)

	verificationConfig := verification.VerificationConfig{
		VerifyRekor:             verifyRekor,
		RequireSCT:              false,
		ExpectedSAN:             o.config.GetString(flags.VerifyExpectedSAN),
		ExpectedSANRegex:        o.config.GetString(flags.VerifyExpectedSANRegex),
		ExpectedIssuer:          o.config.GetString(flags.VerifyExpectedIssuer),
		ExpectedIssuerRegex:     o.config.GetString(flags.VerifyExpectedIssuerRegex),
		AllowUnverifiedIdentity: o.config.GetBool(flags.VerifyAllowUnverifiedIdentity),
	}

	o.logger = o.logger.With(
		"verify_rekor", verifyRekor,
		"expected_san", verificationConfig.ExpectedSAN,
		"expected_issuer", verificationConfig.ExpectedIssuer,
	)
	o.logger.DebugContext(ctx, "verification configuration built")

	verifier := verification.New(verificationConfig, tm, o.logger)

	if verifyRekor {
		o.output.Progress("Verifying signature and Rekor inclusion...")
	} else {
		o.output.Progress("Verifying signature...")
	}

	result, err := verifier.Verify(ctx, b)
	if err != nil {
		o.logger.ErrorContext(ctx, "verification failed", "error", err.Error())
		verifyErr := pkgerrors.WrapWithContext(err, "verify", "verification",
			"verification failed")
		_ = verifyErr.Suggest(
			"Check trust configuration (--tuf-url / --trusted-root)",
			"Ensure network connectivity to Rekor if --rekor is enabled",
			"Verify the bundle was produced against the expected sigstore deployment",
		)
		return verifyErr
	}

	result.AttestationPath = attestationPath
	hash := sha256.Sum256(attestationData)
	result.AttestationHash = hex.EncodeToString(hash[:])

	o.logger.InfoContext(ctx, "verification completed",
		"valid", result.Valid,
		"signature_valid", result.SignatureValid,
		"certificate_valid", result.CertificateValid,
		"rekor_valid", result.RekorValid,
		"errors_count", len(result.Errors),
		"warnings_count", len(result.Warnings),
	)

	if result.Valid {
		o.renderVerificationSuccess(result)
	} else {
		o.output.Error("Attestation verification failed")
		for _, errMsg := range result.Errors {
			o.output.List("%s", errMsg)
		}
	}

	for _, warning := range result.Warnings {
		o.output.Warning("%s", warning)
	}

	if outputErr := o.output.Data(o.logger, "verification result", result); outputErr != nil {
		o.logger.WarnContext(ctx, "failed to output verification result", "error", outputErr.Error())
	}

	outputPath := o.config.GetString(flags.VerifyOutputFile)
	if outputPath != "" {
		jsonData, err := json.Marshal(result)
		if err != nil {
			return pkgerrors.Wrap(err, "failed to marshal verification result to JSON")
		}
		if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
			fileErr := pkgerrors.WrapWithContext(err, "file", "write",
				fmt.Sprintf("failed to write output file: %s", outputPath))
			_ = fileErr.Suggest(
				"Check file permissions and directory exists",
				"Ensure path is not a directory",
				"Verify sufficient disk space")
			return fileErr
		}
		o.logger.InfoContext(ctx, "verification result saved to file",
			"output_path", outputPath, "size_bytes", len(jsonData))
		o.output.Success("Verification result also saved to: %s", outputPath)
	}

	if !result.Valid {
		return pkgerrors.NewWithContext("verify", "verification_failed",
			"attestation verification failed")
	}

	o.logger.InfoContext(ctx, "verify command completed successfully")
	return nil
}

func (o *VerifyOp) renderVerificationSuccess(result *verification.VerificationResult) {
	o.output.Success("Attestation verification passed")
	o.output.List("Signature valid")
	if result.CertificateValid {
		o.output.List("Certificate valid")
	}
	if result.RekorValid {
		o.output.List("Rekor inclusion verified")
	}
	if result.VerifiedSAN != "" {
		o.output.List("SAN: %s", result.VerifiedSAN)
	}
	if result.VerifiedIssuer != "" {
		o.output.List("Issuer: %s", result.VerifiedIssuer)
	}
}

// NewVerifyOp creates a new VerifyOp instance with the provided configuration, logger, and output handler.
func NewVerifyOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *VerifyOp {
	return &VerifyOp{
		config: config,
		logger: logger,
		output: output,
	}
}
