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

package scanresult

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

// ValidateConfig validates configuration and checks the report file existence.
func (a *Attestor) ValidateConfig(config core.Config) error {
	a.parseConfig(config)

	if err := config.Validate(a.ConfigSchema()); err != nil {
		return pkgerrors.WrapWithContext(err, id, "validate", "configuration validation failed")
	}

	if a.config.ReportPath == "" {
		return pkgerrors.NewWithContext(id, "validate",
			"report-path must be a non-empty string pointing to a normalized scan-result JSON file")
	}

	absPath, err := filepath.Abs(a.config.ReportPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "validate", "failed to get absolute path for report file")
	}
	a.reportPath = absPath

	fileInfo, err := os.Stat(a.reportPath)
	if err != nil {
		if os.IsNotExist(err) {
			return pkgerrors.NewWithContext(id, "validate",
				fmt.Sprintf("report file does not exist: %s", a.reportPath))
		}
		return pkgerrors.WrapWithContext(err, id, "validate", "failed to access report file")
	}

	if fileInfo.IsDir() {
		return pkgerrors.NewWithContext(id, "validate",
			fmt.Sprintf("report path is a directory, not a file: %s", a.reportPath))
	}

	if fileInfo.Size() == 0 {
		return pkgerrors.NewWithContext(id, "validate", "report file is empty")
	}

	if a.config.ScanClass != "" && !scanpredicate.ScanClass(a.config.ScanClass).IsValid() {
		return pkgerrors.NewWithContext(id, "validate",
			fmt.Sprintf("scan-class must be 'sast' or 'sca', got '%s'", a.config.ScanClass))
	}

	if a.config.SubjectDigest != "" && !isValidSHA256(a.config.SubjectDigest) {
		return pkgerrors.NewWithContext(id, "validate",
			"subject-digest must be a 64-character lowercase hex SHA-256 digest")
	}

	return nil
}

// isValidSHA256 reports whether s is exactly 64 lowercase hexadecimal characters,
// the canonical form of a SHA-256 digest bound as an in-toto subject.
func isValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
