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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/logger"
	sbompredicate "github.com/thomsonreuters/stamp/pkg/predicates/sbom/v1"
)

func TestID(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "sbom", attestor.ID())
}

func TestName(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "SBOM Attestor", attestor.Name())
}

func TestDescription(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Contains(t, attestor.Description(), "Software Bill of Materials")
}

func TestPredicateURI(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, sbompredicate.PredicateURI, attestor.PredicateURI())
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/sbom/v1", attestor.PredicateURI())
}

func TestAttestor_ConfigSchema(t *testing.T) {
	attestor := &Attestor{}
	schema := attestor.ConfigSchema()

	require.NotEmpty(t, schema)

	// Check required fields
	var foundSBOMPath, foundValidate, foundBehavior bool
	for _, field := range schema {
		switch field.Name {
		case "sbom-path":
			foundSBOMPath = true
			assert.Equal(t, "string", field.Type)
			assert.True(t, field.Required)
		case "validate-schema":
			foundValidate = true
			assert.Equal(t, "bool", field.Type)
			assert.False(t, field.Required)
		case "validation-behavior":
			foundBehavior = true
			assert.Equal(t, "string", field.Type)
			assert.False(t, field.Required)
		}
	}

	assert.True(t, foundSBOMPath, "sbom-path should be in config schema")
	assert.True(t, foundValidate, "validate-schema should be in config schema")
	assert.True(t, foundBehavior, "validation-behavior should be in config schema")
}

func TestAttestor_Schema(t *testing.T) {
	attestor := &Attestor{}
	schema := attestor.Schema()

	require.NotNil(t, schema)
	assert.Equal(t, "SBOM Attestation", schema.Title)
	assert.Equal(t, "Software Bill of Materials attestation predicate (CycloneDX or SPDX)", schema.Description)
	assert.NotNil(t, schema.Definitions)
}

func TestAttestor_PreAttest(t *testing.T) {
	tests := []struct {
		name        string
		sbomPath    string
		setupFile   bool
		expectError bool
	}{
		{
			name:        "Valid path",
			sbomPath:    "test-sbom.json",
			setupFile:   true,
			expectError: false,
		},
		{
			name:        "Relative path",
			sbomPath:    "./test-sbom.json",
			setupFile:   true,
			expectError: false,
		},
		{
			name:        "Absolute path",
			sbomPath:    "/tmp/test-sbom.json",
			setupFile:   false,
			expectError: false, // PreAttest doesn't check file existence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sbomPath string
			if tt.setupFile {
				tmpDir := t.TempDir()
				sbomPath = filepath.Join(tmpDir, tt.sbomPath)
				err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`), 0644)
				require.NoError(t, err)
			} else {
				sbomPath = tt.sbomPath
			}

			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			config := core.Config{
				"sbom-path": sbomPath,
			}

			err := attestor.PreAttest(context.Background(), config)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, attestor.sbomPath)
				assert.True(t, filepath.IsAbs(attestor.sbomPath))
			}
		})
	}
}

func TestAttestor_Attest(t *testing.T) {
	tests := []struct {
		name           string
		sbomContent    string
		validateSchema bool
		expectError    bool
	}{
		{
			name: "Valid CycloneDX",
			sbomContent: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"version": 1
			}`,
			validateSchema: false,
			expectError:    false,
		},
		{
			name: "Valid SPDX",
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
			validateSchema: false,
			expectError:    false,
		},
		{
			name: "Invalid JSON",
			sbomContent: `{
				"bomFormat": "CycloneDX"
				"specVersion": "1.5"
			}`,
			validateSchema: false,
			expectError:    true,
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
			}

			attestor.sbomPath = sbomPath
			attestor.config.ValidateSchema = tt.validateSchema

			config := core.Config{
				"validate-schema": tt.validateSchema,
			}

			err = attestor.Attest(context.Background(), config)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, attestor.predicate.Content)
				assert.NotEmpty(t, attestor.sbomDigest)
			}
		})
	}
}

func TestAttestor_PostAttest(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{}

	err := attestor.PostAttest(context.Background(), config)
	assert.NoError(t, err) // PostAttest is a no-op
}

func TestAttestor_GeneratePredicate(t *testing.T) {
	tests := []struct {
		name        string
		setupFn     func(*Attestor)
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid predicate",
			setupFn: func(a *Attestor) {
				a.predicate.Format = sbompredicate.FormatCycloneDX
				a.predicate.Version = "1.5"
				a.predicate.Content = map[string]any{
					"bomFormat":   "CycloneDX",
					"specVersion": "1.5",
				}
			},
			expectError: false,
		},
		{
			name: "Empty content",
			setupFn: func(a *Attestor) {
				a.predicate.Format = sbompredicate.FormatCycloneDX
				a.predicate.Version = "1.5"
				a.predicate.Content = map[string]any{}
			},
			expectError: true,
			errorMsg:    "predicate content is empty",
		},
		{
			name: "Invalid format",
			setupFn: func(a *Attestor) {
				a.predicate.Format = "invalid"
				a.predicate.Version = "1.5"
				a.predicate.Content = map[string]any{
					"test": "data",
				}
			},
			expectError: true,
			errorMsg:    "invalid SBOM format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			tt.setupFn(attestor)

			config := core.Config{}
			predicate, err := attestor.GeneratePredicate(config)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, predicate)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, predicate)

				// Verify predicate structure
				p, ok := predicate.(sbompredicate.Predicate)
				require.True(t, ok)
				assert.Equal(t, attestor.predicate.Format, p.Format)
				assert.Equal(t, attestor.predicate.Version, p.Version)
				assert.Equal(t, attestor.predicate.Content, p.Content)
			}
		})
	}
}

func TestAttestor_Subjects(t *testing.T) {
	tests := []struct {
		name       string
		sbomPath   string
		sbomDigest string
		expected   string
	}{
		{
			name:       "Simple filename",
			sbomPath:   "/path/to/sbom.json",
			sbomDigest: "abc123",
			expected:   "sbom+sbom.json",
		},
		{
			name:       "Complex filename",
			sbomPath:   "/path/to/example-app-v1.0.0.cdx.json",
			sbomDigest: "def456",
			expected:   "sbom+example-app-v1.0.0.cdx.json",
		},
		{
			name:       "Filename with spaces",
			sbomPath:   "/path/to/my sbom.json",
			sbomDigest: "789abc",
			expected:   "sbom+my sbom.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger:     logger.NewNoop(),
				sbomPath:   tt.sbomPath,
				sbomDigest: tt.sbomDigest,
			}

			config := core.Config{}
			subjects := attestor.Subjects(config)

			require.Len(t, subjects, 1)
			assert.Equal(t, tt.expected, subjects[0].Name)
			assert.Equal(t, tt.sbomDigest, subjects[0].Digest["sha256"])
		})
	}
}

func TestAttestor_ParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   core.Config
		expected Config
	}{
		{
			name: "All fields",
			config: core.Config{
				"sbom-path":           "/path/to/sbom.json",
				"validate-schema":     true,
				"validation-behavior": "warn",
			},
			expected: Config{
				SBOMPath:           "/path/to/sbom.json",
				ValidateSchema:     true,
				ValidationBehavior: ValidationBehaviorWarn,
			},
		},
		{
			name: "Minimal config",
			config: core.Config{
				"sbom-path": "/path/to/sbom.json",
			},
			expected: Config{
				SBOMPath:           "/path/to/sbom.json",
				ValidateSchema:     true,
				ValidationBehavior: "warn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{}
			attestor.parseConfig(tt.config)

			assert.Equal(t, tt.expected.SBOMPath, attestor.config.SBOMPath)
		})
	}
}

func TestAttestor_FullWorkflow(t *testing.T) {
	// Create test SBOM
	tmpDir := t.TempDir()
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
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")
	err := os.WriteFile(sbomPath, []byte(sbomContent), 0644)
	require.NoError(t, err)

	// Initialize attestor
	attestor := &Attestor{
		logger: logger.NewNoop(),
		hasher: hash.New(hash.Config{
			Algorithms: []string{hash.AlgorithmSHA256},
		}),
	}

	config := core.Config{
		"sbom-path":       sbomPath,
		"validate-schema": false,
	}

	ctx := context.Background()

	// Test full workflow
	t.Run("ValidateConfig", func(t *testing.T) {
		err := attestor.ValidateConfig(config)
		require.NoError(t, err)
	})

	t.Run("PreAttest", func(t *testing.T) {
		err := attestor.PreAttest(ctx, config)
		require.NoError(t, err)
		assert.NotEmpty(t, attestor.sbomPath)
	})

	t.Run("Attest", func(t *testing.T) {
		err := attestor.Attest(ctx, config)
		require.NoError(t, err)
		assert.NotEmpty(t, attestor.predicate.Content)
		assert.NotEmpty(t, attestor.sbomDigest)
		assert.Equal(t, sbompredicate.FormatCycloneDX, attestor.predicate.Format)
		assert.Equal(t, "1.5", attestor.predicate.Version)
	})

	t.Run("GeneratePredicate", func(t *testing.T) {
		predicate, err := attestor.GeneratePredicate(config)
		require.NoError(t, err)
		assert.NotNil(t, predicate)

		p, ok := predicate.(sbompredicate.Predicate)
		require.True(t, ok)
		assert.Equal(t, sbompredicate.FormatCycloneDX, p.Format)
		assert.Equal(t, "1.5", p.Version)
		assert.NotEmpty(t, p.Content)
	})

	t.Run("Subjects", func(t *testing.T) {
		subjects := attestor.Subjects(config)
		require.Len(t, subjects, 1)
		assert.Equal(t, "sbom+test-sbom.json", subjects[0].Name)
		assert.NotEmpty(t, subjects[0].Digest["sha256"])
	})

	t.Run("PostAttest", func(t *testing.T) {
		err := attestor.PostAttest(ctx, config)
		assert.NoError(t, err)
	})
}
