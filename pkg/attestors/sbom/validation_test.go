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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestValidateConfig_Success(t *testing.T) {
	tmpDir := t.TempDir()
	validSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1
	}`
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(sbomPath, []byte(validSBOM), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{
		"sbom-path": sbomPath,
	}

	err = attestor.ValidateConfig(config)
	require.NoError(t, err)
	assert.NotEmpty(t, attestor.sbomPath)
	assert.True(t, filepath.IsAbs(attestor.sbomPath))
}

func TestValidateConfig_MissingSBOMPath(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{}

	err := attestor.ValidateConfig(config)
	require.Error(t, err)
	// The error comes from schema validation
	assert.Contains(t, err.Error(), "sbom-path")
}

func TestValidateConfig_FileNotFound(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{
		"sbom-path": "/nonexistent/sbom.json",
	}

	err := attestor.ValidateConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SBOM file does not exist")
}

func TestValidateConfig_PathIsDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{
		"sbom-path": tmpDir,
	}

	err := attestor.ValidateConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory, not a file")
}

func TestValidateConfig_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "empty.json")
	err := os.WriteFile(sbomPath, []byte(""), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{
		"sbom-path": sbomPath,
	}

	err = attestor.ValidateConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SBOM file is empty")
}

func TestValidateConfig_InvalidValidationBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	validSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1
	}`
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(sbomPath, []byte(validSBOM), 0644)
	require.NoError(t, err)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	config := core.Config{
		"sbom-path":           sbomPath,
		"validation-behavior": "invalid",
	}

	err = attestor.ValidateConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation-behavior must be 'allow', 'warn', or 'fail'")
}

func TestValidateConfig_ValidValidationBehaviors(t *testing.T) {
	tmpDir := t.TempDir()
	validSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1
	}`
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(sbomPath, []byte(validSBOM), 0644)
	require.NoError(t, err)

	tests := []struct {
		name     string
		behavior string
	}{
		{"Allow", "allow"},
		{"Warn", "warn"},
		{"Fail", "fail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			config := core.Config{
				"sbom-path":           sbomPath,
				"validation-behavior": tt.behavior,
			}

			err := attestor.ValidateConfig(config)
			require.NoError(t, err)
			assert.Equal(t, tt.behavior, string(attestor.config.ValidationBehavior))
		})
	}
}
