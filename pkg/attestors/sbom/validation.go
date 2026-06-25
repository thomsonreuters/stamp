// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// ValidateConfig validates configuration and checks SBOM file existence.
func (a *Attestor) ValidateConfig(config core.Config) error {
	a.parseConfig(config)

	if err := config.Validate(a.ConfigSchema()); err != nil {
		return pkgerrors.WrapWithContext(err, id, "validate", "configuration validation failed")
	}

	if a.config.SBOMPath == "" {
		return pkgerrors.NewWithContext(id, "validate",
			"sbom-path must be a non-empty string pointing to an SBOM file")
	}

	absPath, err := filepath.Abs(a.config.SBOMPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "validate", "failed to get absolute path for SBOM file")
	}
	a.sbomPath = absPath

	fileInfo, err := os.Stat(a.sbomPath)
	if err != nil {
		if os.IsNotExist(err) {
			return pkgerrors.NewWithContext(id, "validate",
				fmt.Sprintf("SBOM file does not exist: %s", a.sbomPath))
		}
		return pkgerrors.WrapWithContext(err, id, "validate", "failed to access SBOM file")
	}

	if fileInfo.IsDir() {
		return pkgerrors.NewWithContext(id, "validate",
			fmt.Sprintf("SBOM path is a directory, not a file: %s", a.sbomPath))
	}

	if fileInfo.Size() == 0 {
		return pkgerrors.NewWithContext(id, "validate", "SBOM file is empty")
	}

	if a.config.ValidationBehavior != "" {
		if !slices.Contains(ValidationBehaviorValues, a.config.ValidationBehavior) {
			return pkgerrors.NewWithContext(id, "validate",
				fmt.Sprintf("validation-behavior must be 'allow', 'warn', or 'fail', got '%s'", a.config.ValidationBehavior))
		}
	}

	if !a.config.ValidateSchema && a.config.ValidationBehavior != "" && a.config.ValidationBehavior != ValidationBehaviorWarn {
		a.logger.Warn("validation-behavior is ignored when validate-schema is false",
			"validate_schema", a.config.ValidateSchema,
			"validation_behavior", a.config.ValidationBehavior)
	}

	return nil
}
