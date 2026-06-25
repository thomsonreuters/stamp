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

package validation

import (
	"fmt"
	"os"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// ValidateSignerConfig validates signer configuration with cross-flag logic and environment detection.
func ValidateSignerConfig(cfg config.ConfigurationIface) error {
	signerType := cfg.GetString(flags.Signer)

	switch signerType {
	case "fulcio":
		return validateFulcioSigner(cfg)
	case "key":
		return validateFileSigner(cfg)
	case "":
		validator := pkgerrors.NewValidatorFor("signer-validator")
		validator.AddError("signer", "signer type required")
		_ = validator.Suggest("Use --signer key or --signer fulcio")
		return validator
	default:
		validator := pkgerrors.NewValidatorFor("signer-validator")
		validator.AddError("signer", fmt.Sprintf("invalid signer type: %s", signerType))
		return validator
	}
}

// validateFulcioSigner validates configuration for Fulcio-based signing.
func validateFulcioSigner(cfg config.ConfigurationIface) error {
	validator := pkgerrors.NewValidator()

	// Check Fulcio URL requirement
	if cfg.GetString(flags.FulcioURL) == "" {
		validator.AddError("fulcio-url", "Fulcio server URL required when using Fulcio signer")
	}

	// Check for explicit token sources
	hasTokenSource := cfg.GetString(flags.OIDCToken) != "" ||
		cfg.GetString(flags.OIDCTokenFile) != "" ||
		cfg.GetBool(flags.UseSpire) ||
		cfg.GetString(flags.SPIRESocket) != "" ||
		cfg.GetBool(flags.UseGitHub)

	// Check environment-based auto-detection (fallback)
	canAutoDetect := os.Getenv("SPIFFE_ENDPOINT_SOCKET") != "" ||
		os.Getenv("GITHUB_ACTIONS") == "true"

	if !hasTokenSource && !canAutoDetect {
		validator.AddError("token", "OIDC token source required for Fulcio signer")
	}

	if validator.HasErrors() {
		_ = validator.Suggest(
			"Provide explicit token source: --oidc-token, --oidc-token-file, --socket, --spire, or --github",
			"Use --fulcio-url to specify Fulcio server URL",
			"For auto-detection: set SPIFFE_ENDPOINT_SOCKET for SPIRE or run in GitHub Actions",
		)
		return validator
	}

	return nil
}

// validateFileSigner validates configuration for file-based (key) signing.
func validateFileSigner(cfg config.ConfigurationIface) error {
	privateKey := cfg.GetString(flags.PrivateKey)
	if privateKey == "" {
		validator := pkgerrors.NewValidatorFor("signer-validator")
		validator.AddError("--private-key", "key path required when using file signer")
		_ = validator.Suggest(fmt.Sprintf("Use %s to specify signing key file", "--private-key"))
		return validator
	}

	// Validate key file exists and is readable
	if err := ValidateFileExists(privateKey); err != nil {
		validator := pkgerrors.NewValidatorFor("signer-validator")
		validator.AddError("--private-key", fmt.Sprintf("invalid key file: %v", err))
		_ = validator.Suggest("Ensure key file exists and is readable")
		return validator
	}

	return nil
}
