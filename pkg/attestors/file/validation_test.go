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

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestValidatePatterns(t *testing.T) {
	tests := []struct {
		name        string
		config      core.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_exclude_patterns",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"exclude-patterns": []string{"**/.git/**", "**/node_modules/**", "**/*.tmp"},
			},
			expectError: false,
		},
		{
			name: "valid_include_patterns",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"include-patterns": []string{"**/*.go", "**/*.java", "**"},
			},
			expectError: false,
		},
		{
			name: "valid_subject_include_patterns",
			config: core.Config{
				"paths":           []string{"/tmp"},
				"subject-include": []string{"bin/**", "*.jar", "dist/**/*.exe"},
			},
			expectError: false,
		},
		{
			name: "invalid_exclude_pattern_unclosed_bracket",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"exclude-patterns": []string{"**/*.go", "test[/**"}, // Invalid: unclosed bracket
			},
			expectError: true,
			errorMsg:    "invalid exclude pattern",
		},
		{
			name: "invalid_include_pattern_bad_syntax",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"include-patterns": []string{"**/*.go", "test{{"}, // Invalid: unclosed brace
			},
			expectError: true,
			errorMsg:    "invalid include pattern",
		},
		{
			name: "invalid_subject_include_pattern",
			config: core.Config{
				"paths":           []string{"/tmp"},
				"subject-include": []string{"bin/**", "test[["}, // Invalid: double open bracket
			},
			expectError: true,
			errorMsg:    "invalid subject-include pattern",
		},
		{
			name: "empty_patterns_allowed",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"exclude-patterns": []string{"", "**/*.tmp"},
				"include-patterns": []string{""},
			},
			expectError: false,
		},
		{
			name: "all_patterns_valid",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"exclude-patterns": []string{"**/.git/**", "**/node_modules/**"},
				"include-patterns": []string{"**/*.go", "**/*.js"},
				"subject-include":  []string{"bin/**", "dist/**"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			attestor.parseConfig(tt.config)
			err := attestor.validateGlobPatterns()

			if tt.expectError {
				require.Error(t, err, "expected error containing '%s'", tt.errorMsg)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "expected error containing '%s'", tt.errorMsg)
				}
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}

// TestValidateGlobPattern is now in pkg/utils/pattern_test.go

func TestValidateConfig_PatternValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      core.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_config_with_patterns",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"exclude-patterns": []string{"**/.git/**"},
				"include-patterns": []string{"**/*.go"},
			},
			expectError: false,
		},
		{
			name: "invalid_config_bad_exclude_pattern",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"exclude-patterns": []string{"test[["},
			},
			expectError: true,
			errorMsg:    "invalid exclude pattern",
		},
		{
			name: "invalid_config_bad_include_pattern",
			config: core.Config{
				"paths":            []string{"/tmp"},
				"include-patterns": []string{"test{{"},
			},
			expectError: true,
			errorMsg:    "invalid include pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			err := attestor.ValidateConfig(tt.config)

			if tt.expectError {
				require.Error(t, err, "expected error containing '%s'", tt.errorMsg)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "expected error containing '%s'", tt.errorMsg)
				}
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}

func TestValidateConfig_EnhancedValidation(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		config      core.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_minimal_config",
			config: core.Config{
				"paths":     []string{tmpDir},
				"base-path": tmpDir,
			},
			expectError: false,
		},
		{
			name: "missing_paths",
			config: core.Config{
				"base-path": tmpDir,
			},
			expectError: true,
			errorMsg:    "required field is missing",
		},
		{
			name: "empty_paths_list",
			config: core.Config{
				"paths":     []string{},
				"base-path": tmpDir,
			},
			expectError: true,
			errorMsg:    "at least one path must be specified",
		},
		{
			name: "invalid_base_path_not_exists",
			config: core.Config{
				"paths":     []string{tmpDir},
				"base-path": "/nonexistent/path/that/does/not/exist",
			},
			expectError: true,
			errorMsg:    "does not exist or is not accessible",
		},
		{
			name: "invalid_max_depth_negative",
			config: core.Config{
				"paths":     []string{tmpDir},
				"max-depth": -2,
			},
			expectError: true,
			errorMsg:    "max-depth must be between -1",
		},
		{
			name: "invalid_max_depth_too_large",
			config: core.Config{
				"paths":     []string{tmpDir},
				"max-depth": 1001,
			},
			expectError: true,
			errorMsg:    "max-depth must be between -1",
		},
		{
			name: "valid_max_depth_unlimited",
			config: core.Config{
				"paths":     []string{tmpDir},
				"max-depth": -1,
			},
			expectError: false,
		},
		{
			name: "valid_max_depth_limit",
			config: core.Config{
				"paths":     []string{tmpDir},
				"max-depth": 10,
			},
			expectError: false,
		},
		{
			name: "invalid_size_threshold_negative",
			config: core.Config{
				"paths":                  []string{tmpDir},
				"size-warning-threshold": -1,
			},
			expectError: true,
			errorMsg:    "size-warning-threshold must be between 0 and 1GB",
		},
		{
			name: "invalid_size_threshold_too_large",
			config: core.Config{
				"paths":                  []string{tmpDir},
				"size-warning-threshold": 1073741825, // 1GB + 1
			},
			expectError: true,
			errorMsg:    "size-warning-threshold must be between 0 and 1GB",
		},
		{
			name: "valid_size_threshold_zero",
			config: core.Config{
				"paths":                  []string{tmpDir},
				"size-warning-threshold": 0,
			},
			expectError: false,
		},
		{
			name: "valid_size_threshold_max",
			config: core.Config{
				"paths":                  []string{tmpDir},
				"size-warning-threshold": 1073741824, // Exactly 1GB
			},
			expectError: false,
		},
		{
			name: "invalid_hash_algorithm",
			config: core.Config{
				"paths":           []string{tmpDir},
				"hash-algorithms": []string{"sha256", "md5"}, // md5 not supported
			},
			expectError: true,
			errorMsg:    "invalid hash algorithms: md5",
		},
		{
			name: "valid_hash_algorithms",
			config: core.Config{
				"paths":           []string{tmpDir},
				"hash-algorithms": []string{"sha256", "sha512", "blake3", "sha3-256", "sha3-512"},
			},
			expectError: false,
		},
		{
			name: "hash_algorithm_case_insensitive",
			config: core.Config{
				"paths":           []string{tmpDir},
				"hash-algorithms": []string{"SHA256", "Blake3"},
			},
			expectError: false,
		},
		{
			name: "invalid_subject_mode",
			config: core.Config{
				"paths":        []string{tmpDir},
				"subject-mode": "invalid-mode",
			},
			expectError: true,
			errorMsg:    "invalid subject-mode 'invalid-mode'",
		},
		{
			name: "valid_subject_mode_manifest_only",
			config: core.Config{
				"paths":        []string{tmpDir},
				"subject-mode": "manifest-only",
			},
			expectError: false,
		},
		{
			name: "valid_subject_mode_hybrid",
			config: core.Config{
				"paths":           []string{tmpDir},
				"subject-mode":    "hybrid",
				"subject-include": []string{"*.jar"},
			},
			expectError: false,
		},
		{
			name: "valid_subject_mode_all_files",
			config: core.Config{
				"paths":        []string{tmpDir},
				"subject-mode": "all-files",
			},
			expectError: false,
		},
		{
			name: "comprehensive_valid_config",
			config: core.Config{
				"paths":                  []string{tmpDir},
				"base-path":              tmpDir,
				"exclude-patterns":       []string{"**/.git/**", "**/node_modules/**"},
				"include-patterns":       []string{"**/*.go"},
				"hash-algorithms":        []string{"sha256", "sha512"},
				"max-depth":              10,
				"size-warning-threshold": 20971520, // 20MB
				"subject-mode":           "hybrid",
				"subject-include":        []string{"bin/**"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
			}

			err := attestor.ValidateConfig(tt.config)

			if tt.expectError {
				require.Error(t, err, "expected error containing '%s'", tt.errorMsg)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "expected error containing '%s'", tt.errorMsg)
				}
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}
