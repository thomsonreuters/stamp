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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/logger"
	sbompredicate "github.com/thomsonreuters/stamp/pkg/predicates/sbom/v1"
)

func TestCollectSBOMInformation_Success(t *testing.T) {
	tests := []struct {
		name           string
		sbomContent    string
		expectedFormat sbompredicate.SBOMFormat
		expectedVer    string
	}{
		{
			name: "CycloneDX 1.5",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1,
				"components": [
					{
						"type": "library",
						"name": "test-lib",
						"version": "1.0.0"
					}
				]
			}`,
			expectedFormat: sbompredicate.FormatCycloneDX,
			expectedVer:    "1.5",
		},
		{
			name: "SPDX 2.3",
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
			expectedFormat: sbompredicate.FormatSPDX,
			expectedVer:    "SPDX-2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sbomPath := filepath.Join(tmpDir, "sbom.json")
			err := os.WriteFile(sbomPath, []byte(tt.sbomContent), 0644)
			require.NoError(t, err)

			attestor := &Attestor{
				logger: logger.NewNoop(),
				hasher: hash.New(hash.Config{
					Algorithms: []string{hash.AlgorithmSHA256},
				}),
				config: Config{
					ValidateSchema: false,
				},
				sbomPath: sbomPath,
			}

			config := core.Config{}
			err = attestor.collectSBOMInformation(context.Background(), config)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedFormat, attestor.predicate.Format)
			assert.Equal(t, tt.expectedVer, attestor.predicate.Version)
			assert.NotEmpty(t, attestor.sbomDigest)
			assert.NotEmpty(t, attestor.predicate.Content)
		})
	}
}

func TestCollectSBOMInformation_FileErrors(t *testing.T) {
	tests := []struct {
		name     string
		setupFn  func(t *testing.T) string
		errorMsg string
	}{
		{
			name: "File does not exist",
			setupFn: func(t *testing.T) string {
				return "/nonexistent/sbom.json"
			},
			errorMsg: "failed to stat SBOM file",
		},
		{
			name: "File is directory",
			setupFn: func(t *testing.T) string {
				return t.TempDir()
			},
			errorMsg: "failed to read SBOM file",
		},
		{
			name: "Empty file",
			setupFn: func(t *testing.T) string {
				tmpDir := t.TempDir()
				sbomPath := filepath.Join(tmpDir, "empty.json")
				err := os.WriteFile(sbomPath, []byte(""), 0644)
				require.NoError(t, err)
				return sbomPath
			},
			errorMsg: "failed to detect SBOM format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomPath := tt.setupFn(t)

			attestor := &Attestor{
				logger: logger.NewNoop(),
				hasher: hash.New(hash.Config{
					Algorithms: []string{hash.AlgorithmSHA256},
				}),
				sbomPath: sbomPath,
			}

			config := core.Config{}
			err := attestor.collectSBOMInformation(context.Background(), config)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestCollectSBOMInformation_ValidationBehaviors(t *testing.T) {
	// Create a minimal valid CycloneDX that might trigger validation warnings
	sbomContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1
	}`

	tests := []struct {
		name               string
		validateSchema     bool
		validationBehavior ValidationBehavior
		expectError        bool
	}{
		{
			name:               "Validation disabled",
			validateSchema:     false,
			validationBehavior: ValidationBehaviorWarn,
			expectError:        false,
		},
		{
			name:               "Validation enabled - allow",
			validateSchema:     true,
			validationBehavior: ValidationBehaviorAllow,
			expectError:        false,
		},
		{
			name:               "Validation enabled - warn",
			validateSchema:     true,
			validationBehavior: ValidationBehaviorWarn,
			expectError:        false,
		},
		{
			name:               "Validation enabled - fail",
			validateSchema:     true,
			validationBehavior: ValidationBehaviorFail,
			expectError:        false, // This particular SBOM is valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sbomPath := filepath.Join(tmpDir, "sbom.json")
			err := os.WriteFile(sbomPath, []byte(sbomContent), 0644)
			require.NoError(t, err)

			attestor := &Attestor{
				logger: logger.NewNoop(),
				hasher: hash.New(hash.Config{
					Algorithms: []string{hash.AlgorithmSHA256},
				}),
				config: Config{
					ValidateSchema:     tt.validateSchema,
					ValidationBehavior: tt.validationBehavior,
				},
				sbomPath: sbomPath,
			}

			config := core.Config{}
			err = attestor.collectSBOMInformation(context.Background(), config)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCollectSBOMInformation_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	sbomContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1
	}`
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(sbomPath, []byte(sbomContent), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		hasher: hash.New(hash.Config{
			Algorithms: []string{hash.AlgorithmSHA256},
		}),
		sbomPath: sbomPath,
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := core.Config{}
	err = attestor.collectSBOMInformation(ctx, config)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "operation cancelled")
}

func TestCollectSBOMInformation_DigestCalculation(t *testing.T) {
	sbomContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(sbomPath, []byte(sbomContent), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		hasher: hash.New(hash.Config{
			Algorithms: []string{hash.AlgorithmSHA256},
		}),
		config: Config{
			ValidateSchema: false,
		},
		sbomPath: sbomPath,
	}

	config := core.Config{}
	err = attestor.collectSBOMInformation(context.Background(), config)

	require.NoError(t, err)

	// Verify digest was calculated
	assert.NotEmpty(t, attestor.sbomDigest)
	assert.Len(t, attestor.sbomDigest, 64) // SHA-256 hex = 64 chars
}

func TestCollectSBOMInformation_ContentParsing(t *testing.T) {
	sbomContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"component": {
				"type": "application",
				"name": "test-app"
			}
		}
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(sbomPath, []byte(sbomContent), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		hasher: hash.New(hash.Config{
			Algorithms: []string{hash.AlgorithmSHA256},
		}),
		config: Config{
			ValidateSchema: false,
		},
		sbomPath: sbomPath,
	}

	config := core.Config{}
	err = attestor.collectSBOMInformation(context.Background(), config)

	require.NoError(t, err)

	// Verify content was parsed correctly
	assert.Equal(t, "CycloneDX", attestor.predicate.Content["bomFormat"])
	assert.Equal(t, "1.5", attestor.predicate.Content["specVersion"])
	assert.NotNil(t, attestor.predicate.Content["metadata"])

	// Verify nested structure
	metadata, ok := attestor.predicate.Content["metadata"].(map[string]any)
	require.True(t, ok)
	assert.NotNil(t, metadata["component"])
}

func TestCollectSBOMInformation_LargeFile(t *testing.T) {
	// Create a large but valid SBOM
	components := make([]string, 100)
	for i := range 100 {
		components[i] = `{
			"type": "library",
			"name": "lib-` + string(rune('a'+i%26)) + `",
			"version": "1.0.0"
		}`
	}

	sbomContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"components": [` + strings.Join(components, ",") + `]
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "large-sbom.json")
	err := os.WriteFile(sbomPath, []byte(sbomContent), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		hasher: hash.New(hash.Config{
			Algorithms: []string{hash.AlgorithmSHA256},
		}),
		config: Config{
			ValidateSchema: false,
		},
		sbomPath: sbomPath,
	}

	config := core.Config{}
	err = attestor.collectSBOMInformation(context.Background(), config)

	require.NoError(t, err)
	assert.NotEmpty(t, attestor.predicate.Content)

	// Verify components were parsed
	componentsField, ok := attestor.predicate.Content["components"].([]any)
	require.True(t, ok)
	assert.Len(t, componentsField, 100)
}
