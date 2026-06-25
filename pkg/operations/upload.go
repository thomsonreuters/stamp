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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/transparency"
	"github.com/thomsonreuters/stamp/pkg/validation"
)

// UploadOp implements the operation for uploading attestations to the Rekor transparency log.
type UploadOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
}

// Validate checks that the upload operation has valid input parameters.
func (o *UploadOp) Validate(attestationPath string) error {
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

	rekorURL := o.config.GetString(flags.RekorURL)
	insecure := o.config.GetBool(flags.Insecure)
	if err := validation.ValidateURLFormat(rekorURL, insecure, "Rekor URL"); err != nil {
		validator.AddError("rekor-url", fmt.Sprintf("invalid Rekor URL: %v", err))
	}

	publicKeyPath := o.config.GetString(flags.UploadPublicKey)
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

	if validator.HasErrors() {
		_ = validator.Suggest(
			"Specify path to signed attestation file as first argument",
			"Ensure Rekor URL is properly formatted",
			"Use --insecure for HTTP URLs if needed",
			"Provide --public-key for file-based signatures (not needed for certificate-based)")
		return validator
	}

	return nil
}

// determinePublicKeyPath determines the public key path for verification based on attestation content and configuration.
func (o *UploadOp) determinePublicKeyPath(ctx context.Context, envelope *intoto.Envelope) (string, error) {
	// Priority 1: Check if attestation has certificates (preferred method)
	hasCertificates := false
	for _, sig := range envelope.Signatures {
		if sig.Certificate != "" {
			hasCertificates = true
			break
		}
	}

	if hasCertificates {
		o.logger.DebugContext(ctx, "attestation contains certificates, no public key path needed")
		o.output.Progress("Using certificates from attestation for verification")
		return "", nil // Empty string signals: use certificates from attestation
	}

	// Priority 2: Try explicit --public-key flag
	publicKeyPath := o.config.GetString(flags.UploadPublicKey)
	if publicKeyPath != "" {
		o.logger.DebugContext(ctx, "using explicit public key from upload flag", "path", publicKeyPath)
		o.output.Progress("Using explicit public key: %s", publicKeyPath)
		return publicKeyPath, nil
	}

	// Priority 3: Fallback to general config public key
	publicKeyPath = o.config.GetString(flags.PublicKey)
	if publicKeyPath != "" {
		o.logger.DebugContext(ctx, "using public key from general config", "path", publicKeyPath)
		o.output.Progress("Using public key from configuration: %s", publicKeyPath)
		return publicKeyPath, nil
	}

	return "", pkgerrors.NewUsageError(
		"no public key or certificates found - Rekor requires verification material",
		"Use --public-key for key-based signatures or --signer fulcio for certificate-based")
}

// Execute performs the upload operation to publish attestations to the Rekor transparency log.
func (o *UploadOp) Execute(ctx context.Context, attestationPath string) error {
	o.logger.InfoContext(ctx, "starting attestation upload to Rekor", "attestation_path", attestationPath)

	o.output.Progress("Uploading attestation to Rekor: %s", attestationPath)

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

	rekorURL := o.config.GetString(flags.RekorURL)
	insecure := o.config.GetBool(flags.Insecure)

	publicKeyPath, err := o.determinePublicKeyPath(ctx, &envelope)
	if err != nil {
		return err
	}

	o.logger = o.logger.With("rekor_url", rekorURL, "insecure", insecure)
	if publicKeyPath != "" {
		o.logger = o.logger.With("public_key_path", publicKeyPath)
		o.logger.DebugContext(ctx, "using explicit public key for verification")
	} else {
		o.logger.DebugContext(ctx, "using certificates from attestation for verification")
	}

	rekorClient, err := transparency.NewClient(rekorURL, insecure, o.logger)
	if err != nil {
		return pkgerrors.Wrap(err, "failed to create Rekor client")
	}

	o.output.Progress("Uploading to Rekor at %s...", rekorURL)
	uploadStart := time.Now()

	entry, err := rekorClient.Upload(ctx, &envelope, publicKeyPath, nil)
	if err != nil {
		o.logger.ErrorContext(ctx, "failed to upload attestation to Rekor",
			"error", err.Error(),
			"duration_ms", time.Since(uploadStart).Milliseconds())

		uploadErr := pkgerrors.WrapWithContext(err, "upload", "rekor_upload",
			fmt.Sprintf("failed to upload to Rekor (url: %s)", rekorURL))
		_ = uploadErr.Suggest(
			"Check network connectivity to Rekor server",
			"Verify the attestation format and signatures are valid",
			"Ensure the correct public key is provided for file-based signatures",
			"Check if attestation contains valid certificates for certificate-based signatures")
		return uploadErr
	}

	o.logger.InfoContext(ctx, "attestation uploaded successfully to Rekor",
		"uuid", entry.UUID,
		"log_index", entry.LogIndex,
		"log_id", entry.LogID,
		"integrated_time", entry.IntegratedTime,
		"upload_duration_ms", time.Since(uploadStart).Milliseconds(),
	)

	o.output.Success("Attestation uploaded to Rekor")
	o.output.List("UUID: %s", entry.UUID)
	o.output.List("Log Index: %d", entry.LogIndex)
	o.output.List("Integrated Time: %s", time.Unix(entry.IntegratedTime, 0).Format(time.RFC3339))
	o.output.List("Rekor URL: %s", rekorURL)

	entryData := map[string]any{
		"uuid":            entry.UUID,
		"log_index":       entry.LogIndex,
		"log_id":          entry.LogID,
		"integrated_time": entry.IntegratedTime,
		"rekor_url":       rekorURL,
		"timestamp":       time.Unix(entry.IntegratedTime, 0).Format(time.RFC3339),
	}

	if err := o.output.Data(o.logger, "rekor entry created", entryData); err != nil {
		o.logger.WarnContext(ctx, "failed to output entry data", "error", err.Error())
		// Non-fatal: upload succeeded, just data output failed
	}

	return nil
}

// NewUploadOp creates a new UploadOp instance with the provided configuration, logger, and output handler.
func NewUploadOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *UploadOp {
	return &UploadOp{
		config: config,
		logger: logger,
		output: output,
	}
}
