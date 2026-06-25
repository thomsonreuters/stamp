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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	sbompredicate "github.com/thomsonreuters/stamp/pkg/predicates/sbom/v1"
)

func detectBOMFormatAndVersion(content []byte) (sbompredicate.SBOMFormat, string, error) {
	var rawJSON map[string]any
	if err := json.Unmarshal(content, &rawJSON); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal SBOM file: %w", err)
	}

	if bomFormat, ok := rawJSON["bomFormat"].(string); ok {
		if strings.EqualFold(bomFormat, "CycloneDX") {
			if specVersion, ok := rawJSON["specVersion"].(string); ok {
				return sbompredicate.FormatCycloneDX, specVersion, nil
			}
			return "", "", errors.New("CycloneDX SBOM missing 'specVersion' field")
		}
	}

	if spdxVersion, ok := rawJSON["spdxVersion"].(string); ok {
		if strings.HasPrefix(spdxVersion, "SPDX-") {
			return sbompredicate.FormatSPDX, spdxVersion, nil
		}
	}

	return "", "", errors.New("unable to detect SBOM format")
}

func validateCycloneDX(content []byte) error {
	bom := new(cyclonedx.BOM)
	decoder := cyclonedx.NewBOMDecoder(strings.NewReader(string(content)), cyclonedx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return fmt.Errorf("CycloneDX validation failed: %w", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		return fmt.Errorf("invalid bomFormat: expected 'CycloneDX', got '%s'", bom.BOMFormat)
	}

	specVersionStr := bom.SpecVersion.String()
	if specVersionStr == "" || specVersionStr == "Unknown" {
		return errors.New("missing or invalid required field: specVersion")
	}

	return nil
}

func validateSPDX(content []byte) error {
	doc, err := spdxjson.Read(strings.NewReader(string(content)))
	if err != nil {
		return fmt.Errorf("SPDX validation failed: %w", err)
	}

	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		return fmt.Errorf("invalid SPDX version: expected 'SPDX-', got '%s'", doc.SPDXVersion)
	}

	return nil
}

func validateSBOMFile(content []byte, format sbompredicate.SBOMFormat) error {
	switch format {
	case sbompredicate.FormatCycloneDX:
		return validateCycloneDX(content)
	case sbompredicate.FormatSPDX:
		return validateSPDX(content)
	default:
		return fmt.Errorf("unsupported SBOM format: %s", format)
	}
}
