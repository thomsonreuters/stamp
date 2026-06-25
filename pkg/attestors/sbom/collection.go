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

package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// collectSBOMInformation reads, validates, and parses the SBOM file.
func (a *Attestor) collectSBOMInformation(ctx context.Context, _ core.Config) error {
	start := time.Now()

	a.logger.InfoContext(ctx, "collecting SBOM document information")

	select {
	case <-ctx.Done():
		return pkgerrors.WrapWithContext(ctx.Err(), id, "collect", "operation cancelled")
	default:
	}

	fileInfo, err := os.Stat(a.sbomPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to stat SBOM file")
	}

	content, err := os.ReadFile(a.sbomPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to read SBOM file")
	}

	format, version, err := detectBOMFormatAndVersion(content)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to detect SBOM format")
	}

	if a.config.ValidateSchema {
		if validationErr := validateSBOMFile(content, format); validationErr != nil {
			switch a.config.ValidationBehavior {
			case ValidationBehaviorAllow:
				a.logger.DebugContext(ctx, "SBOM validation failed but allowing (behavior: allow)",
					"error", validationErr.Error(),
					"format", format)
			case ValidationBehaviorWarn:
				a.logger.WarnContext(ctx, "SBOM validation failed but continuing (behavior: warn)",
					"error", validationErr.Error(),
					"format", format,
					"version", version)
			case ValidationBehaviorFail:
				return pkgerrors.WrapWithContext(validationErr, id, "collect",
					fmt.Sprintf("SBOM validation failed for %s %s", format, version))
			default:
				a.logger.WarnContext(ctx, "SBOM validation failed but continuing (behavior: warn)",
					"error", validationErr.Error(),
					"format", format,
					"version", version)
			}
		}
	} else {
		a.logger.DebugContext(ctx, "SBOM validation skipped (validate-schema: false)")
	}

	a.predicate.Format = format
	a.predicate.Version = version

	result, err := a.hasher.HashBytes(ctx, content, a.sbomPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to hash SBOM file")
	}

	a.sbomDigest = result.Digests[hash.AlgorithmSHA256]

	parsedContent := make(map[string]any)
	if err := json.Unmarshal(content, &parsedContent); err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to parse SBOM JSON")
	}

	a.predicate.Content = parsedContent

	a.logger.InfoContext(ctx, "SBOM information collection completed",
		"format", a.predicate.Format,
		"version", a.predicate.Version,
		"file_size_bytes", fileInfo.Size(),
		"duration_ms", time.Since(start).Milliseconds())

	return nil
}
