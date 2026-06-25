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

package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// TestValidateConfig_Valid verifies that ValidateConfig accepts valid configurations.
func TestValidateConfig_Valid(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	tests := []struct {
		name   string
		config core.Config
	}{
		{
			name:   "empty config (all defaults)",
			config: core.Config{},
		},
		{
			name: "valid IMDSv2 config",
			config: core.Config{
				"imds-version":              "v2",
				"imds-endpoint":             "http://169.254.169.254",
				"timeout":                   "10s",
				"token-ttl":                 60,
				"include-network-details":   true,
				"include-iam-info":          false,
				"include-tags":              false,
				"not-ec2-behavior":          "fail",
				"imds-unavailable-behavior": "fail",
				"redact-account-id":         false,
				"redact-private-ips":        false,
				"sensitive-fields":          []string{},
				"max-retries":               3,
				"retry-delay":               "1s",
			},
		},
		{
			name: "valid IMDSv1 config",
			config: core.Config{
				"imds-version":              "v1",
				"not-ec2-behavior":          "warn",
				"imds-unavailable-behavior": "warn",
			},
		},
		{
			name: "valid auto version config",
			config: core.Config{
				"imds-version":     "auto",
				"not-ec2-behavior": "skip",
			},
		},
		{
			name: "valid with all redaction options",
			config: core.Config{
				"redact-account-id":  true,
				"redact-private-ips": true,
				"sensitive-fields":   []string{"vpcId", "subnetId", "tags"},
			},
		},
		{
			name: "valid token TTL boundary values",
			config: core.Config{
				"token-ttl": 1, // minimum
			},
		},
		{
			name: "valid token TTL max",
			config: core.Config{
				"token-ttl": 21600, // maximum
			},
		},
		{
			name: "valid duration formats",
			config: core.Config{
				"timeout":     "30s",
				"retry-delay": "500ms",
			},
		},
		{
			name: "valid https endpoint",
			config: core.Config{
				"imds-endpoint": "https://169.254.169.254",
			},
		},
		{
			name: "zero max-retries",
			config: core.Config{
				"max-retries": 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := attestor.ValidateConfig(tt.config)
			assert.NoError(t, err, "ValidateConfig() returned error for valid config")
		})
	}
}

// TestValidateConfig_Invalid verifies that ValidateConfig rejects invalid configurations.
func TestValidateConfig_Invalid(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	tests := []struct {
		name        string
		config      core.Config
		expectError string
	}{
		{
			name: "invalid IMDS version",
			config: core.Config{
				"imds-version": "v3",
			},
			expectError: "invalid imds-version",
		},
		{
			name: "invalid not-ec2-behavior",
			config: core.Config{
				"not-ec2-behavior": "ignore",
			},
			expectError: "invalid not-ec2-behavior",
		},
		{
			name: "invalid imds-unavailable-behavior",
			config: core.Config{
				"imds-unavailable-behavior": "skip",
			},
			expectError: "invalid imds-unavailable-behavior",
		},
		{
			name: "token TTL too low",
			config: core.Config{
				"token-ttl": 0,
			},
			expectError: "invalid token-ttl",
		},
		{
			name: "token TTL too high",
			config: core.Config{
				"token-ttl": 21601,
			},
			expectError: "invalid token-ttl",
		},
		{
			name: "negative max-retries",
			config: core.Config{
				"max-retries": -1,
			},
			expectError: "invalid max-retries",
		},
		{
			name: "invalid timeout duration",
			config: core.Config{
				"timeout": "invalid",
			},
			expectError: "invalid timeout duration",
		},
		{
			name: "invalid retry-delay duration",
			config: core.Config{
				"retry-delay": "10x",
			},
			expectError: "invalid retry-delay duration",
		},
		{
			name: "invalid endpoint URL - no protocol",
			config: core.Config{
				"imds-endpoint": "169.254.169.254",
			},
			expectError: "invalid imds-endpoint",
		},
		{
			name: "invalid endpoint URL - ftp protocol",
			config: core.Config{
				"imds-endpoint": "ftp://169.254.169.254",
			},
			expectError: "invalid imds-endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := attestor.ValidateConfig(tt.config)
			require.Error(t, err, "ValidateConfig() should have returned error for invalid config")
		})
	}
}

// TestValidateConfig_EdgeCases verifies edge case handling in validation.
func TestValidateConfig_EdgeCases(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
	}

	tests := []struct {
		name        string
		config      core.Config
		shouldError bool
	}{
		{
			name: "empty strings are valid (use defaults)",
			config: core.Config{
				"imds-version":  "",
				"imds-endpoint": "",
				"timeout":       "",
				"retry-delay":   "",
			},
			shouldError: false,
		},
		{
			name: "sensitive-fields empty array",
			config: core.Config{
				"sensitive-fields": []string{},
			},
			shouldError: false,
		},
		{
			name: "sensitive-fields with duplicates",
			config: core.Config{
				"sensitive-fields": []string{"accountId", "accountId", "vpcId"},
			},
			shouldError: false, // duplicates are allowed, just inefficient
		},
		{
			name: "very long duration",
			config: core.Config{
				"timeout": "1h",
			},
			shouldError: false,
		},
		{
			name: "very short duration",
			config: core.Config{
				"retry-delay": "1ms",
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := attestor.ValidateConfig(tt.config)
			if tt.shouldError {
				assert.Error(t, err, "ValidateConfig() should have returned error")
			} else {
				assert.NoError(t, err, "ValidateConfig() returned unexpected error")
			}
		})
	}
}

// TestConfigSchema verifies that the configuration schema is properly defined.
func TestConfigSchema(t *testing.T) {
	attestor := &Attestor{}
	schema := attestor.ConfigSchema()

	require.NotEmpty(t, schema, "ConfigSchema() returned empty schema")

	// Verify key fields are present
	requiredFields := map[string]bool{
		"imds-version":              false,
		"imds-endpoint":             false,
		"timeout":                   false,
		"token-ttl":                 false,
		"not-ec2-behavior":          false,
		"imds-unavailable-behavior": false,
		"redact-account-id":         false,
		"redact-private-ips":        false,
		"sensitive-fields":          false,
		"max-retries":               false,
		"retry-delay":               false,
	}

	for _, field := range schema {
		if _, exists := requiredFields[field.Name]; exists {
			requiredFields[field.Name] = true

			// Verify field has description
			assert.NotEmpty(t, field.Description, "Field %s missing description", field.Name)

			// Verify field has type
			assert.NotEmpty(t, field.Type, "Field %s missing type", field.Name)
		}
	}

	// Verify all required fields were found
	for fieldName, found := range requiredFields {
		assert.True(t, found, "Required field %s not found in schema", fieldName)
	}
}

// TestSchema_JSONSchema verifies the JSON schema generation for the predicate.
func TestSchema_JSONSchema(t *testing.T) {
	attestor := &Attestor{}
	schema := attestor.Schema()

	require.NotNil(t, schema, "Schema() returned nil")

	assert.Equal(t, "EC2 Runtime Environment Attestation", schema.Title, "Expected schema title 'EC2 Runtime Environment Attestation'")

	assert.Equal(t, "AWS EC2 instance metadata collected from IMDS for runtime attestation", schema.Description, "Expected schema description")

	// The schema is generated from ec2predicate.Predicate using reflection
	// The actual structure depends on the jsonschema library's reflection behavior
}
