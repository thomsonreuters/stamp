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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sbompredicate "github.com/thomsonreuters/stamp/pkg/predicates/sbom/v1"
)

func TestDetectBOMFormatAndVersion_CycloneDX(t *testing.T) {
	tests := []struct {
		name            string
		sbomContent     string
		expectedFormat  sbompredicate.SBOMFormat
		expectedVersion string
		expectError     bool
		errorMsg        string
	}{
		{
			name: "Valid CycloneDX 1.4",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"version": 1
			}`,
			expectedFormat:  sbompredicate.FormatCycloneDX,
			expectedVersion: "1.4",
			expectError:     false,
		},
		{
			name: "Valid CycloneDX 1.5",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1
			}`,
			expectedFormat:  sbompredicate.FormatCycloneDX,
			expectedVersion: "1.5",
			expectError:     false,
		},
		{
			name: "Valid CycloneDX 1.6",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"version": 1
			}`,
			expectedFormat:  sbompredicate.FormatCycloneDX,
			expectedVersion: "1.6",
			expectError:     false,
		},
		{
			name: "CycloneDX missing specVersion",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"version": 1
			}`,
			expectError: true,
			errorMsg:    "missing 'specVersion' field",
		},
		{
			name: "CycloneDX with case variations",
			sbomContent: `{
				"bomFormat": "cyclonedx",
				"specVersion": "1.5",
				"version": 1
			}`,
			expectedFormat:  sbompredicate.FormatCycloneDX,
			expectedVersion: "1.5",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, version, err := detectBOMFormatAndVersion([]byte(tt.sbomContent))

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedFormat, format)
				assert.Equal(t, tt.expectedVersion, version)
			}
		})
	}
}

func TestDetectBOMFormatAndVersion_SPDX(t *testing.T) {
	tests := []struct {
		name            string
		sbomContent     string
		expectedFormat  sbompredicate.SBOMFormat
		expectedVersion string
		expectError     bool
		errorMsg        string
	}{
		{
			name: "Valid SPDX 2.2",
			sbomContent: `{
				"spdxVersion": "SPDX-2.2",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "test"
			}`,
			expectedFormat:  sbompredicate.FormatSPDX,
			expectedVersion: "SPDX-2.2",
			expectError:     false,
		},
		{
			name: "Valid SPDX 2.3",
			sbomContent: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "test"
			}`,
			expectedFormat:  sbompredicate.FormatSPDX,
			expectedVersion: "SPDX-2.3",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, version, err := detectBOMFormatAndVersion([]byte(tt.sbomContent))

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedFormat, format)
				assert.Equal(t, tt.expectedVersion, version)
			}
		})
	}
}

func TestDetectBOMFormatAndVersion_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		sbomContent string
		errorMsg    string
	}{
		{
			name: "Invalid JSON",
			sbomContent: `{
				"bomFormat": "CycloneDX"
				"specVersion": "1.5"
			}`,
			errorMsg: "failed to unmarshal",
		},
		{
			name: "Unknown format",
			sbomContent: `{
				"unknownField": "value"
			}`,
			errorMsg: "unable to detect SBOM format",
		},
		{
			name:        "Empty JSON",
			sbomContent: `{}`,
			errorMsg:    "unable to detect SBOM format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, version, err := detectBOMFormatAndVersion([]byte(tt.sbomContent))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
			assert.Empty(t, format)
			assert.Empty(t, version)
		})
	}
}

func TestValidateCycloneDX(t *testing.T) {
	tests := []struct {
		name        string
		sbomContent string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid minimal CycloneDX",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1
			}`,
			expectError: false,
		},
		{
			name: "Valid with components",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1,
				"components": [
					{
						"type": "library",
						"name": "example",
						"version": "1.0.0"
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "Invalid bomFormat",
			sbomContent: `{
			"bomFormat": "NotCycloneDX",
			"specVersion": "1.5",
			"version": 1
		}`,
			expectError: true,
			errorMsg:    "invalid bomFormat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCycloneDX([]byte(tt.sbomContent))

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSPDX(t *testing.T) {
	tests := []struct {
		name        string
		sbomContent string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid SPDX 2.3",
			sbomContent: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "test-sbom",
				"documentNamespace": "https://example.com/test",
				"creationInfo": {
					"created": "2025-11-27T10:00:00Z",
					"creators": ["Tool: test"]
				}
			}`,
			expectError: false,
		},
		{
			name: "Valid SPDX 2.2",
			sbomContent: `{
				"spdxVersion": "SPDX-2.2",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "test-sbom",
				"documentNamespace": "https://example.com/test",
				"creationInfo": {
					"created": "2025-11-27T10:00:00Z",
					"creators": ["Tool: test"]
				}
			}`,
			expectError: false,
		},
		{
			name: "Invalid SPDX version format",
			sbomContent: `{
			"spdxVersion": "2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "test"
		}`,
			expectError: true,
			errorMsg:    "unsupported SDPX version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSPDX([]byte(tt.sbomContent))

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSBOMFile(t *testing.T) {
	tests := []struct {
		name        string
		sbomContent string
		format      sbompredicate.SBOMFormat
		expectError bool
	}{
		{
			name: "CycloneDX validation",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1
			}`,
			format:      sbompredicate.FormatCycloneDX,
			expectError: false,
		},
		{
			name: "SPDX validation",
			sbomContent: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "test",
				"documentNamespace": "https://example.com/test",
				"creationInfo": {
					"created": "2025-11-27T10:00:00Z",
					"creators": ["Tool: test"]
				}
			}`,
			format:      sbompredicate.FormatSPDX,
			expectError: false,
		},
		{
			name: "Unsupported format",
			sbomContent: `{
				"test": "data"
			}`,
			format:      "unsupported",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSBOMFile([]byte(tt.sbomContent), tt.format)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
