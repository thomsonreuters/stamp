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

// Package v1 provides SBOM attestation predicate types for CycloneDX and SPDX formats.
package v1

const (
	PredicateURI = "https://github.com/thomsonreuters/stamp/sbom/v1"
)

type SBOMFormat string

const (
	FormatCycloneDX SBOMFormat = "cyclonedx"
	FormatSPDX      SBOMFormat = "spdx"
)

func (f SBOMFormat) String() string {
	return string(f)
}

func (f SBOMFormat) IsValid() bool {
	switch f {
	case FormatCycloneDX, FormatSPDX:
		return true
	default:
		return false
	}
}

// Predicate represents the SBOM attestation predicate with format, version, and content.
type Predicate struct {
	Format  SBOMFormat     `json:"format"`
	Version string         `json:"version"`
	Content map[string]any `json:"content"`
}
