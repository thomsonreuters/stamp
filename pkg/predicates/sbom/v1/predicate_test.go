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

package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/sbom/v1", PredicateURI)
}

func TestSBOMFormat_String(t *testing.T) {
	tests := []struct {
		name     string
		format   SBOMFormat
		expected string
	}{
		{
			name:     "CycloneDX format",
			format:   FormatCycloneDX,
			expected: "cyclonedx",
		},
		{
			name:     "SPDX format",
			format:   FormatSPDX,
			expected: "spdx",
		},
		{
			name:     "Custom format",
			format:   SBOMFormat("custom"),
			expected: "custom",
		},
		{
			name:     "Empty format",
			format:   SBOMFormat(""),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.format.String()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestSBOMFormat_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		format   SBOMFormat
		expected bool
	}{
		{
			name:     "Valid CycloneDX format",
			format:   FormatCycloneDX,
			expected: true,
		},
		{
			name:     "Valid SPDX format",
			format:   FormatSPDX,
			expected: true,
		},
		{
			name:     "Invalid custom format",
			format:   SBOMFormat("custom"),
			expected: false,
		},
		{
			name:     "Invalid empty format",
			format:   SBOMFormat(""),
			expected: false,
		},
		{
			name:     "Invalid uppercase format",
			format:   SBOMFormat("CycloneDX"),
			expected: false,
		},
		{
			name:     "Invalid mixed case format",
			format:   SBOMFormat("SPDX"),
			expected: false,
		},
		{
			name:     "Invalid random string",
			format:   SBOMFormat("not-a-format"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.format.IsValid()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestPredicate_JSONMarshal_CycloneDX(t *testing.T) {
	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.5",
		Content: map[string]any{
			"bomFormat":    "CycloneDX",
			"specVersion":  "1.5",
			"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
			"version":      1,
			"metadata": map[string]any{
				"timestamp": "2025-11-27T10:00:00Z",
				"component": map[string]any{
					"type": "application",
					"name": "example-app",
				},
			},
			"components": []any{
				map[string]any{
					"type":    "library",
					"name":    "example-lib",
					"version": "1.2.3",
					"purl":    "pkg:golang/github.com/example/lib@1.2.3",
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "format")
	assert.Contains(t, string(data), "version")
	assert.Contains(t, string(data), "content")
	assert.Contains(t, string(data), "cyclonedx")
	assert.Contains(t, string(data), "1.5")
}

func TestPredicate_JSONMarshal_SPDX(t *testing.T) {
	predicate := Predicate{
		Format:  FormatSPDX,
		Version: "SPDX-2.3",
		Content: map[string]any{
			"spdxVersion":       "SPDX-2.3",
			"dataLicense":       "CC0-1.0",
			"SPDXID":            "SPDXRef-DOCUMENT",
			"name":              "example-app-sbom",
			"documentNamespace": "https://example.com/example-app-1.0.0",
			"creationInfo": map[string]any{
				"created": "2025-11-27T10:00:00Z",
				"creators": []string{
					"Tool: attestor",
				},
			},
			"packages": []any{
				map[string]any{
					"SPDXID":           "SPDXRef-Package",
					"name":             "example-lib",
					"versionInfo":      "1.2.3",
					"downloadLocation": "https://github.com/example/lib",
					"filesAnalyzed":    false,
					"licenseConcluded": "NOASSERTION",
					"licenseDeclared":  "MIT",
					"copyrightText":    "NOASSERTION",
					"externalRefs": []any{
						map[string]any{
							"referenceCategory": "PACKAGE-MANAGER",
							"referenceType":     "purl",
							"referenceLocator":  "pkg:golang/github.com/example/lib@1.2.3",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "format")
	assert.Contains(t, string(data), "version")
	assert.Contains(t, string(data), "content")
	assert.Contains(t, string(data), "spdx")
	assert.Contains(t, string(data), "SPDX-2.3")
}

func TestPredicate_JSONUnmarshal_CycloneDX(t *testing.T) {
	jsonData := `{
		"format": "cyclonedx",
		"version": "1.5",
		"content": {
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"serialNumber": "urn:uuid:test-123",
			"version": 1,
			"components": [
				{
					"type": "library",
					"name": "test-lib",
					"version": "1.0.0"
				}
			]
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, FormatCycloneDX, predicate.Format)
	assert.Equal(t, "1.5", predicate.Version)
	assert.NotNil(t, predicate.Content)
	assert.Equal(t, "CycloneDX", predicate.Content["bomFormat"])
	assert.Equal(t, "1.5", predicate.Content["specVersion"])
}

func TestPredicate_JSONUnmarshal_SPDX(t *testing.T) {
	jsonData := `{
		"format": "spdx",
		"version": "SPDX-2.3",
		"content": {
			"spdxVersion": "SPDX-2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "test-sbom",
			"documentNamespace": "https://example.com/test",
			"creationInfo": {
				"created": "2025-11-27T10:00:00Z"
			}
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, FormatSPDX, predicate.Format)
	assert.Equal(t, "SPDX-2.3", predicate.Version)
	assert.NotNil(t, predicate.Content)
	assert.Equal(t, "SPDX-2.3", predicate.Content["spdxVersion"])
	assert.Equal(t, "CC0-1.0", predicate.Content["dataLicense"])
}

func TestPredicate_Complete_CycloneDX(t *testing.T) {
	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.6",
		Content: map[string]any{
			"bomFormat":    "CycloneDX",
			"specVersion":  "1.6",
			"serialNumber": "urn:uuid:complete-test",
			"version":      1,
			"metadata": map[string]any{
				"timestamp": "2025-11-27T10:00:00Z",
				"tools": []any{
					map[string]any{
						"name":    "attestor",
						"version": "1.0.0",
					},
				},
				"component": map[string]any{
					"type":    "application",
					"name":    "complete-app",
					"version": "2.0.0",
				},
			},
			"components": []any{
				map[string]any{
					"type":    "library",
					"name":    "lib-a",
					"version": "1.0.0",
					"purl":    "pkg:golang/example.com/lib-a@1.0.0",
				},
				map[string]any{
					"type":    "library",
					"name":    "lib-b",
					"version": "2.0.0",
					"purl":    "pkg:golang/example.com/lib-b@2.0.0",
				},
			},
			"dependencies": []any{
				map[string]any{
					"ref": "pkg:golang/example.com/lib-a@1.0.0",
					"dependsOn": []string{
						"pkg:golang/example.com/lib-b@2.0.0",
					},
				},
			},
			"vulnerabilities": []any{},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Format, result.Format)
	assert.Equal(t, predicate.Version, result.Version)
	assert.Equal(t, "CycloneDX", result.Content["bomFormat"])
	assert.NotNil(t, result.Content["components"])
	assert.NotNil(t, result.Content["metadata"])
}

func TestPredicate_Complete_SPDX(t *testing.T) {
	predicate := Predicate{
		Format:  FormatSPDX,
		Version: "SPDX-2.3",
		Content: map[string]any{
			"spdxVersion":       "SPDX-2.3",
			"dataLicense":       "CC0-1.0",
			"SPDXID":            "SPDXRef-DOCUMENT",
			"name":              "complete-app-sbom",
			"documentNamespace": "https://example.com/complete-app-1.0.0",
			"creationInfo": map[string]any{
				"created":            "2025-11-27T10:00:00Z",
				"licenseListVersion": "3.20",
				"creators": []string{
					"Tool: attestor-1.0.0",
					"Organization: Example Corp",
				},
			},
			"packages": []any{
				map[string]any{
					"SPDXID":           "SPDXRef-Package-1",
					"name":             "lib-a",
					"versionInfo":      "1.0.0",
					"downloadLocation": "https://github.com/example/lib-a",
					"filesAnalyzed":    false,
					"licenseConcluded": "MIT",
					"licenseDeclared":  "MIT",
					"copyrightText":    "Copyright Example Corp",
				},
				map[string]any{
					"SPDXID":           "SPDXRef-Package-2",
					"name":             "lib-b",
					"versionInfo":      "2.0.0",
					"downloadLocation": "https://github.com/example/lib-b",
					"filesAnalyzed":    false,
					"licenseConcluded": "Apache-2.0",
					"licenseDeclared":  "Apache-2.0",
					"copyrightText":    "NOASSERTION",
				},
			},
			"relationships": []any{
				map[string]any{
					"spdxElementId":      "SPDXRef-DOCUMENT",
					"relationshipType":   "DESCRIBES",
					"relatedSpdxElement": "SPDXRef-Package-1",
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Format, result.Format)
	assert.Equal(t, predicate.Version, result.Version)
	assert.Equal(t, "SPDX-2.3", result.Content["spdxVersion"])
	assert.NotNil(t, result.Content["packages"])
	assert.NotNil(t, result.Content["creationInfo"])
}

func TestPredicate_Minimal(t *testing.T) {
	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.4",
		Content: map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.4",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, FormatCycloneDX, result.Format)
	assert.Equal(t, "1.4", result.Version)
	assert.NotNil(t, result.Content)
	assert.Len(t, result.Content, 2)
}

func TestPredicate_EmptyContent(t *testing.T) {
	predicate := Predicate{
		Format:  FormatSPDX,
		Version: "SPDX-2.2",
		Content: map[string]any{},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, FormatSPDX, result.Format)
	assert.Equal(t, "SPDX-2.2", result.Version)
	assert.NotNil(t, result.Content)
	assert.Empty(t, result.Content)
}

func TestPredicate_DifferentVersions(t *testing.T) {
	tests := []struct {
		name    string
		format  SBOMFormat
		version string
	}{
		{
			name:    "CycloneDX 1.4",
			format:  FormatCycloneDX,
			version: "1.4",
		},
		{
			name:    "CycloneDX 1.5",
			format:  FormatCycloneDX,
			version: "1.5",
		},
		{
			name:    "CycloneDX 1.6",
			format:  FormatCycloneDX,
			version: "1.6",
		},
		{
			name:    "SPDX 2.2",
			format:  FormatSPDX,
			version: "SPDX-2.2",
		},
		{
			name:    "SPDX 2.3",
			format:  FormatSPDX,
			version: "SPDX-2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := Predicate{
				Format:  tt.format,
				Version: tt.version,
				Content: map[string]any{
					"test": "data",
				},
			}

			data, err := json.Marshal(predicate)
			require.NoError(t, err)

			var result Predicate
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.format, result.Format)
			assert.Equal(t, tt.version, result.Version)
		})
	}
}

func TestPredicate_NestedContent(t *testing.T) {
	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.5",
		Content: map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"metadata": map[string]any{
				"component": map[string]any{
					"type": "application",
					"name": "nested-app",
					"licenses": []any{
						map[string]any{
							"license": map[string]any{
								"id": "MIT",
							},
						},
					},
				},
			},
			"components": []any{
				map[string]any{
					"type": "library",
					"name": "lib",
					"properties": []any{
						map[string]any{
							"name":  "custom-prop",
							"value": "custom-value",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Format, result.Format)
	assert.NotNil(t, result.Content["metadata"])
	assert.NotNil(t, result.Content["components"])

	// Verify nested structure preservation
	metadata, ok := result.Content["metadata"].(map[string]any)
	require.True(t, ok)
	component, ok := metadata["component"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "nested-app", component["name"])
}

func TestPredicate_RoundTrip(t *testing.T) {
	original := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.5",
		Content: map[string]any{
			"bomFormat":    "CycloneDX",
			"specVersion":  "1.5",
			"serialNumber": "urn:uuid:roundtrip-test",
			"version":      1,
			"components": []any{
				map[string]any{
					"type":    "library",
					"name":    "roundtrip-lib",
					"version": "1.0.0",
				},
			},
		},
	}

	// Marshal
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	var decoded Predicate
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Marshal again
	data2, err := json.Marshal(decoded)
	require.NoError(t, err)

	// Compare
	assert.JSONEq(t, string(data), string(data2))
}

func TestSBOMFormat_Constants(t *testing.T) {
	assert.Equal(t, FormatCycloneDX, SBOMFormat("cyclonedx"))
	assert.Equal(t, FormatSPDX, SBOMFormat("spdx"))
}

func TestPredicate_JSONFieldNames(t *testing.T) {
	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.5",
		Content: map[string]any{
			"test": "data",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	// Verify JSON uses correct field names
	assert.Contains(t, string(data), `"format"`)
	assert.Contains(t, string(data), `"version"`)
	assert.Contains(t, string(data), `"content"`)

	// Verify no Go field names leak through
	assert.NotContains(t, string(data), "Format")
	assert.NotContains(t, string(data), "Version")
	assert.NotContains(t, string(data), "Content")
}

func TestPredicate_WithNumericValues(t *testing.T) {
	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.5",
		Content: map[string]any{
			"version": 1,
			"metadata": map[string]any{
				"timestamp": "2025-11-27T10:00:00Z",
			},
			"components": []any{
				map[string]any{
					"type":    "library",
					"name":    "lib",
					"version": "1.0.0",
					"hashes": []any{
						map[string]any{
							"alg":     "SHA-256",
							"content": "abc123",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Format, result.Format)
	// Verify numeric version is preserved
	versionNum, ok := result.Content["version"].(float64) // JSON numbers unmarshal as float64
	require.True(t, ok)
	assert.InDelta(t, float64(1), versionNum, 0.0001)
}

func TestPredicate_WithBooleanValues(t *testing.T) {
	predicate := Predicate{
		Format:  FormatSPDX,
		Version: "SPDX-2.3",
		Content: map[string]any{
			"spdxVersion": "SPDX-2.3",
			"packages": []any{
				map[string]any{
					"name":                          "test-package",
					"filesAnalyzed":                 true,
					"verificationCodeExcludedFiles": []string{},
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	packages, ok := result.Content["packages"].([]any)
	require.True(t, ok)
	require.Len(t, packages, 1)

	pkg, ok := packages[0].(map[string]any)
	require.True(t, ok)

	filesAnalyzed, ok := pkg["filesAnalyzed"].(bool)
	require.True(t, ok)
	assert.True(t, filesAnalyzed)
}

func TestPredicate_LargeContent(t *testing.T) {
	// Simulate a large SBOM with many components
	components := make([]any, 100)
	for i := range 100 {
		components[i] = map[string]any{
			"type":    "library",
			"name":    "lib-" + string(rune(i)),
			"version": "1.0.0",
			"purl":    "pkg:golang/example.com/lib-" + string(rune(i)) + "@1.0.0",
		}
	}

	predicate := Predicate{
		Format:  FormatCycloneDX,
		Version: "1.5",
		Content: map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components":  components,
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Format, result.Format)
	resultComponents, ok := result.Content["components"].([]any)
	require.True(t, ok)
	assert.Len(t, resultComponents, 100)
}
