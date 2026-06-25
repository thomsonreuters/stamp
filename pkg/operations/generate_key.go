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
	"path/filepath"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// GenerateKeyOp implements the operation for generating cryptographic key pairs for signing attestations.
type GenerateKeyOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
}

// Execute performs the key generation operation.
func (o *GenerateKeyOp) Execute(ctx context.Context, args []string) error {
	keyType := o.config.GetString(flags.GenerateKeyType)
	keyPath := o.config.GetString(flags.GenerateKeyOutput)
	overwrite := o.config.GetBool(flags.GenerateKeyOverwrite)

	absPath, err := filepath.Abs(keyPath)
	if err != nil {
		return pkgerrors.Wrap(err, "failed to resolve output path")
	}

	var finalPassword string

	switch {
	case o.config.GetBool(flags.CryptographyKeyPasswordPrompt):
		promptResult, promptErr := utils.PromptPasswordWithConfirm("Enter password to encrypt private key")
		if promptErr != nil {
			return pkgerrors.Wrap(promptErr, "failed to get encryption password")
		}
		finalPassword = promptResult.Password
		for _, warning := range promptResult.Warnings {
			o.output.Warning("%s", warning)
		}

	case o.config.GetString(flags.CryptographyKeyPassword) != "":
		finalPassword = o.config.GetString(flags.CryptographyKeyPassword)

	case o.config.GetString(flags.CryptographyKeyPasswordFile) != "":
		var readErr error
		finalPassword, readErr = utils.ReadPasswordFromFile(o.config.GetString(flags.CryptographyKeyPasswordFile))
		if readErr != nil {
			return pkgerrors.Wrap(readErr, "failed to read password file")
		}
	}

	if finalPassword != "" {
		o.output.Warning("Encrypting private key with AES-256")
	}

	o.logger.InfoContext(ctx, "starting key pair generation", "key_type", keyType, "output_path", absPath, "encrypted", finalPassword != "")

	o.output.Progress("Generating %s key pair...", keyType)

	_, err = keys.GenerateToFile(absPath, keys.GenerateOptions{
		Algorithm: keyType,
		Overwrite: overwrite,
		Password:  finalPassword,
	})
	if err != nil {
		o.logger.ErrorContext(ctx, "key pair generation failed", "error", err)
		fileErr := pkgerrors.WrapWithContext(err, "file", "write", "failed to generate key pair")
		_ = fileErr.Suggest(
			"Check write permissions for the output directory",
			"Ensure sufficient disk space is available",
			"Verify the key type is supported")
		return fileErr
	}

	baseName := strings.TrimSuffix(absPath, filepath.Ext(absPath))
	privateKeyPath := baseName + ".key"
	publicKeyPath := baseName + ".pub"

	o.logger.InfoContext(ctx, "key pair generation completed successfully",
		"private_key", privateKeyPath,
		"public_key", publicKeyPath)

	secLogger := o.logger.With("security", true, "component", "security")
	if finalPassword == "" {
		secLogger.Info("unencrypted private key generated",
			"key_path", privateKeyPath,
			"key_type", keyType,
		)
	} else {
		secLogger.Info("encrypted private key generated",
			"key_path", privateKeyPath,
			"key_type", keyType,
		)
	}

	o.displaySuccessMessage(keyType, privateKeyPath, publicKeyPath, finalPassword != "")

	return nil
}

// displaySuccessMessage outputs the key generation success details and usage instructions.
func (o *GenerateKeyOp) displaySuccessMessage(keyType, privateKeyPath, publicKeyPath string, encrypted bool) {
	o.output.Success("Key pair generated successfully!")
	o.output.Info("Generated %s key pair:", keyType)
	o.output.Info("  Private key: %s", privateKeyPath)
	o.output.Info("  Public key:  %s", publicKeyPath)

	o.output.Info("\nUsage:")
	if encrypted {
		o.output.Info("  stamp run <attestor> --signer key --private-key %s --prompt", privateKeyPath)
		o.output.Info("  # or with STAMP_PASSWORD environment variable")
	} else {
		o.output.Info("  stamp run <attestor> --signer key --private-key %s", privateKeyPath)
	}

	if !encrypted {
		o.output.NewLine()
		o.output.Warning("Security: Private key is unencrypted. Consider using --prompt for encryption.")
	}
	o.output.Warning("Security: Keep the private key secure and never share it.")
}

// NewGenerateKeyOp creates a new GenerateKeyOp instance with the provided configuration, logger, and output handler.
func NewGenerateKeyOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *GenerateKeyOp {
	return &GenerateKeyOp{
		config: config,
		logger: logger,
		output: output,
	}
}
