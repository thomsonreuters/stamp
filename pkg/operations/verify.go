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

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/thomsonreuters/stamp/pkg/validation"
	"github.com/thomsonreuters/stamp/pkg/verification"
)

// VerifyOp implements the operation for verifying attestation signatures and transparency log inclusion.
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
		// Validate the attestation file
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

	publicKeyPath := o.config.GetString(flags.VerifyPublicKey)
	if publicKeyPath != "" {
		opts := validation.FileValidationOptions{
			MaxSize:       MaxPublicKeyFileSize,
			AllowEmpty:    false,
			RequireExists: true,
			FileType:      "public key",
		}
		if err := validation.ValidateFile(publicKeyPath, opts); err != nil {
			validator.AddError("public-key", fmt.Sprintf("invalid public key file: %v", err))
		}
	}

	fulcioURL := o.config.GetString(flags.FulcioURL)
	insecure := o.config.GetBool(flags.Insecure)
	if err := validation.ValidateURLFormat(fulcioURL, insecure, "Fulcio URL"); err != nil {
		validator.AddError("fulcio-url", fmt.Sprintf("invalid Fulcio URL: %v", err))
	}

	rekorURL := o.config.GetString(flags.RekorURL)
	if err := validation.ValidateURLFormat(rekorURL, insecure, "Rekor URL"); err != nil {
		validator.AddError("rekor-url", fmt.Sprintf("invalid Rekor URL: %v", err))
	}

	temporalPolicy := o.config.GetString(flags.RekorTemporalPolicy)
	if temporalPolicy != "" && !types.IsValidTemporalPolicy(temporalPolicy) {
		validator.AddError(
			"rekor-temporal-policy",
			fmt.Sprintf("invalid temporal policy %q: must be one of %v", temporalPolicy, types.ValidTemporalPolicies),
		)
	}

	if !o.config.GetBool(flags.TransparencyEnable) && temporalPolicy != "" {
		o.output.Warning("--rekor-temporal-policy specified but --rekor not enabled (policy will be ignored)")
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
			"Specify path to attestation file as first argument",
			"Example: stamp verify attestation.json",
			"Ensure attestation file exists and is readable",
			"Use --public-key for key-based signatures (certificates auto-detected)",
			"Use --rekor to enable transparency log verification",
			"Use --insecure for HTTP URLs if needed")
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

	var envelope intoto.Envelope
	if unmarshalErr := json.Unmarshal(attestationData, &envelope); unmarshalErr != nil {
		parseErr := pkgerrors.WrapWithContext(unmarshalErr, "parse", "attestation", "failed to parse attestation file")
		_ = parseErr.Suggest(
			"Check that the file contains valid JSON in attestation format",
			"Verify the file is a properly formatted in-toto attestation")
		return parseErr
	}

	o.logger.DebugContext(ctx, "attestation parsed successfully",
		"signature_count", len(envelope.Signatures),
		"payload_type", envelope.PayloadType)

	verifyRekor := o.config.GetBool(flags.TransparencyEnable)
	rekorURL := o.config.GetString(flags.RekorURL)
	fulcioURL := o.config.GetString(flags.FulcioURL)
	insecure := o.config.GetBool(flags.Insecure)

	verificationConfig := verification.VerificationConfig{
		PublicKeyPath:       o.config.GetString(flags.VerifyPublicKey),
		FulcioURL:           fulcioURL,
		VerifyRekor:         verifyRekor,
		RekorURL:            rekorURL,
		RekorTemporalPolicy: resolveTemporalPolicy(o.config.GetString(flags.RekorTemporalPolicy)),
		Insecure:            insecure,
	}

	o.logger = o.logger.With(
		"verify_rekor", verifyRekor,
		"rekor_url", rekorURL,
		"fulcio_url", fulcioURL,
		"temporal_policy", verificationConfig.RekorTemporalPolicy,
		"insecure", insecure)

	o.logger.DebugContext(ctx, "verification configuration built")

	verifier := verification.New(verificationConfig, o.logger)

	if verifyRekor {
		o.output.Progress("Verifying signature and Rekor inclusion...")
	} else {
		o.output.Progress("Verifying signature...")
	}

	result, err := verifier.Verify(ctx, &envelope)
	if err != nil {
		o.logger.ErrorContext(ctx, "verification failed",
			"error", err.Error())
		verifyErr := pkgerrors.WrapWithContext(err, "verify", "verification",
			fmt.Sprintf("verification failed (fulcio-url: %s, rekor-url: %s)", fulcioURL, rekorURL))
		_ = verifyErr.Suggest(
			"Check the verification configuration",
			"Ensure network connectivity to Fulcio/Rekor services",
			"Verify the attestation format and signatures are valid",
			"Use --insecure if connecting to HTTP servers for testing")
		return verifyErr
	}

	result.AttestationPath = attestationPath
	hash := sha256.Sum256(attestationData)
	result.AttestationHash = hex.EncodeToString(hash[:])

	o.logger.DebugContext(ctx, "attestation metadata added to result",
		"path", result.AttestationPath,
		"hash", result.AttestationHash,
		"rekor_uuid", result.RekorEntryUUID)

	o.logger.InfoContext(ctx, "verification completed",
		"valid", result.Valid,
		"signature_valid", result.SignatureValid,
		"certificate_valid", result.CertificateValid,
		"rekor_valid", result.RekorValid,
		"errors_count", len(result.Errors),
		"warnings_count", len(result.Warnings),
	)

	if result.Valid {
		o.output.Success("Attestation verification passed")
		o.output.List("✓ Signature valid")
		if result.CertificateValid {
			o.output.List("✓ Certificate valid")
		}
		if result.RekorValid {
			o.output.List("✓ Rekor inclusion verified")
		}
	} else {
		o.output.Error("Attestation verification failed")
		for _, errMsg := range result.Errors {
			o.output.List("✗ %s", errMsg)
		}
	}

	if len(result.Warnings) > 0 {
		for _, warning := range result.Warnings {
			o.output.Warning("%s", warning)
		}
	}

	if outputErr := o.output.Data(o.logger, "verification result", result); outputErr != nil {
		o.logger.WarnContext(ctx, "failed to output verification result", "error", outputErr.Error())
		// Non-fatal: verification succeeded, just data output failed
	}

	outputPath := o.config.GetString(flags.VerifyOutputFile)
	if outputPath != "" {
		var jsonData []byte
		jsonData, err = json.Marshal(result)

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
			"output_path", outputPath,
			"size_bytes", len(jsonData))

		o.output.Success("Verification result also saved to: %s", outputPath)
	}

	if !result.Valid {
		return pkgerrors.NewWithContext("verify", "verification_failed",
			"attestation verification failed")
	}

	o.logger.InfoContext(ctx, "verify command completed successfully")
	return nil
}

// NewVerifyOp creates a new VerifyOp instance with the provided configuration, logger, and output handler.
func NewVerifyOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *VerifyOp {
	return &VerifyOp{
		config: config,
		logger: logger,
		output: output,
	}
}

func resolveTemporalPolicy(value string) types.TemporalPolicy {
	if value == "" {
		return types.TemporalPolicyWarn
	}
	return types.TemporalPolicy(value)
}
