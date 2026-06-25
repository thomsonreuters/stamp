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
	"regexp"
	"strconv"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/transparency"
	"github.com/thomsonreuters/stamp/pkg/validation"
)

// FetchOp implements the operation for fetching attestation entries from the Rekor transparency log.
type FetchOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
}

// isValidRekorUUID validates that a UUID matches the expected Rekor format.
func (o *FetchOp) isValidRekorUUID(uuid string) bool {
	// Rekor UUIDs are 80 hex characters: 16 (tree ID) + 64 (entry hash)
	matched, _ := regexp.MatchString("^[a-fA-F0-9]{80}$", uuid)
	return matched
}

// Validate checks that the fetch operation has valid input parameters.
func (o *FetchOp) Validate(args []string) error {
	validator := pkgerrors.NewValidator()

	filePath := o.config.GetString(flags.FetchFile)
	if filePath != "" {
		opts := validation.FileValidationOptions{
			MaxSize:       MaxAttestationFileSize,
			AllowEmpty:    false,
			RequireExists: true,
			FileType:      "attestation",
		}
		if err := validation.ValidateFile(filePath, opts); err != nil {
			validator.AddError("file", fmt.Sprintf("invalid attestation file: %v", err))
		}
	}

	uuid := o.config.GetString(flags.FetchUUID)
	if uuid != "" {
		if !o.isValidRekorUUID(uuid) {
			validator.AddError("uuid", fmt.Sprintf("invalid Rekor UUID format (expected 80 hex characters): %s", uuid))
		}
	}

	logIndex := o.config.GetString(flags.FetchLogIndex)
	if logIndex != "" {
		if _, err := strconv.ParseUint(logIndex, 10, 64); err != nil {
			validator.AddError("log-index", fmt.Sprintf("invalid log index (must be a positive integer): %s", logIndex))
		}
	}

	rekorURL := o.config.GetString(flags.RekorURL)
	insecure := o.config.GetBool(flags.Insecure)
	if err := validation.ValidateURLFormat(rekorURL, insecure, "Rekor URL"); err != nil {
		validator.AddError("rekor-url", fmt.Sprintf("invalid Rekor URL: %v", err))
	}

	outputPath := o.config.GetString(flags.FetchOutputFile)
	if outputPath != "" {
		if fileInfo, err := os.Stat(outputPath); err == nil {
			if fileInfo.IsDir() {
				validator.AddError("output", fmt.Sprintf("output path is a directory: %s", outputPath))
			}
		}
	}

	if validator.HasErrors() {
		_ = validator.Suggest(
			"Use exactly one input method: --file, --uuid, or --log-index",
			"Example: stamp fetch --file attestation.json",
			"Ensure Rekor UUID is 64 hexadecimal characters",
			"Ensure log index is a positive integer",
			"Use --insecure for HTTP URLs if needed")
		return validator
	}

	return nil
}

// Execute performs the fetch operation to retrieve entries from the Rekor transparency log.
func (o *FetchOp) Execute(ctx context.Context, args []string) error {
	filePath := o.config.GetString(flags.FetchFile)
	uuid := o.config.GetString(flags.FetchUUID)
	logIndex := o.config.GetString(flags.FetchLogIndex)
	outputPath := o.config.GetString(flags.FetchOutputFile)
	rawOutput := o.config.GetBool(flags.FetchRaw)
	rekorURL := o.config.GetString(flags.RekorURL)
	insecure := o.config.GetBool(flags.Insecure)

	switch {
	case filePath != "":
		o.logger.InfoContext(ctx, "starting Rekor entry fetch", "rekor_url", rekorURL, "file_path", filePath, "raw_output", rawOutput)
		o.output.Progress("Fetching Rekor entry for attestation: %s", filePath)
	case uuid != "":
		o.logger.InfoContext(ctx, "starting Rekor entry fetch", "rekor_url", rekorURL, "uuid", uuid, "raw_output", rawOutput)
		o.output.Progress("Fetching Rekor entry by UUID: %s", uuid)
	case logIndex != "":
		o.logger.InfoContext(ctx, "starting Rekor entry fetch", "rekor_url", rekorURL, "log_index", logIndex, "raw_output", rawOutput)
		o.output.Progress("Fetching Rekor entry by log index: %s", logIndex)
	}

	transparencyClient, err := transparency.NewClient(rekorURL, insecure, o.logger)
	if err != nil {
		return pkgerrors.Wrap(err, "failed to create Rekor client")
	}

	var result *transparency.FetchResult

	switch {
	case filePath != "":
		result, err = transparencyClient.FetchFromFile(ctx, filePath, rawOutput)
	case uuid != "":
		result, err = transparencyClient.FetchFromUUID(ctx, uuid, rawOutput)
	case logIndex != "":
		result, err = transparencyClient.FetchFromLogIndex(ctx, logIndex, rawOutput)
	default:
		noInputErr := pkgerrors.NewWithContext("fetch", "no_input",
			"no fetch input specified: provide exactly one of --file, --uuid, or --log-index")
		_ = noInputErr.Suggest(
			"Use --file <path> to fetch by attestation file",
			"Use --uuid <rekor-uuid> to fetch by Rekor entry UUID",
			"Use --log-index <index> to fetch by log index")
		return noInputErr
	}

	if err != nil {
		logArgs := []any{
			"rekor_url", rekorURL,
			"error", err.Error(),
		}
		if filePath != "" {
			logArgs = append(logArgs, "file_path", filePath)
		}
		if uuid != "" {
			logArgs = append(logArgs, "uuid", uuid)
		}
		if logIndex != "" {
			logArgs = append(logArgs, "log_index", logIndex)
		}
		o.logger.ErrorContext(ctx, "failed to fetch Rekor entry", logArgs...)

		fetchErr := pkgerrors.WrapWithContext(err, "fetch", "rekor_fetch",
			fmt.Sprintf("failed to fetch from Rekor (url: %s)", rekorURL))
		_ = fetchErr.Suggest(
			"Check network connectivity to Rekor server",
			"Verify the input parameters are correct",
			"Ensure the entry exists in the transparency log",
			"Use --insecure if connecting to HTTP server for testing")
		return fetchErr
	}

	o.logger.InfoContext(ctx, "Rekor entry fetched successfully",
		"rekor_url", rekorURL,
		"uuid", result.UUID,
		"log_index", result.LogIndex,
	)

	o.output.Success("Rekor entry fetched successfully")
	if result.UUID != "" {
		o.output.List("UUID: %s", result.UUID)
	}
	if result.LogIndex != nil {
		o.output.List("Log Index: %d", *result.LogIndex)
	}
	if result.Timestamp != nil {
		o.output.List("Timestamp: %s", *result.Timestamp)
	}
	if result.TreeSize != nil {
		o.output.List("Tree Size: %d", *result.TreeSize)
	}

	var outputData any
	if rawOutput && result.RawResponse != nil {
		outputData = result.RawResponse
	} else {
		outputData = result
	}

	if outputErr := o.output.Data(o.logger, "rekor entry fetched", outputData); outputErr != nil {
		o.logger.WarnContext(ctx, "failed to output entry data",
			"uuid", result.UUID,
			"raw_output", rawOutput,
			"error", outputErr.Error())
		// Non-fatal: fetch succeeded, just data output failed
	}

	if outputPath != "" {
		var jsonData []byte
		if rawOutput && result.RawResponse != nil {
			jsonData, err = json.MarshalIndent(result.RawResponse, "", "  ")
		} else {
			jsonData, err = json.MarshalIndent(result, "", "  ")
		}

		if err != nil {
			return pkgerrors.Wrap(err, "failed to marshal result to JSON")
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

		o.logger.InfoContext(ctx, "Rekor entry saved to file",
			"output_path", outputPath,
			"size_bytes", len(jsonData),
		)

		o.output.Success("Entry also saved to: %s", outputPath)
	}

	o.logger.InfoContext(ctx, "fetch command completed",
		"rekor_url", rekorURL,
		"uuid", result.UUID,
		"output_file", outputPath,
	)

	return nil
}

// NewFetchOp creates a new FetchOp instance with the provided configuration, logger, and output handler.
func NewFetchOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *FetchOp {
	return &FetchOp{
		config: config,
		logger: logger,
		output: output,
	}
}
