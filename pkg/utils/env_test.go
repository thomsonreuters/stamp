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

package utils

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to parse env slice to map for testing.
func parseEnvToMap(envSlice []string) map[string]string {
	envMap := make(map[string]string)
	for _, e := range envSlice {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	return envMap
}

func TestBuildEnv(t *testing.T) {
	tests := []struct {
		name      string
		baseEnv   []string
		overrides map[string]string
		expected  map[string]string
	}{
		{
			name:      "empty base and overrides",
			baseEnv:   []string{},
			overrides: map[string]string{},
			expected:  map[string]string{},
		},
		{
			name:      "nil base and overrides",
			baseEnv:   nil,
			overrides: nil,
			expected:  map[string]string{},
		},
		{
			name:      "base only",
			baseEnv:   []string{"PATH=/bin", "HOME=/root"},
			overrides: map[string]string{},
			expected: map[string]string{
				"PATH": "/bin",
				"HOME": "/root",
			},
		},
		{
			name:    "overrides only",
			baseEnv: []string{},
			overrides: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
			expected: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/user",
			},
		},
		{
			name:    "override existing variable",
			baseEnv: []string{"PATH=/bin", "HOME=/root"},
			overrides: map[string]string{
				"PATH": "/usr/bin",
			},
			expected: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/root",
			},
		},
		{
			name:    "add new variable",
			baseEnv: []string{"PATH=/bin"},
			overrides: map[string]string{
				"HOME": "/home/user",
			},
			expected: map[string]string{
				"PATH": "/bin",
				"HOME": "/home/user",
			},
		},
		{
			name:      "value with equals sign",
			baseEnv:   []string{"KEY=value=with=equals"},
			overrides: map[string]string{},
			expected: map[string]string{
				"KEY": "value=with=equals",
			},
		},
		{
			name:    "override with value containing equals",
			baseEnv: []string{"KEY=old"},
			overrides: map[string]string{
				"KEY": "new=value=with=equals",
			},
			expected: map[string]string{
				"KEY": "new=value=with=equals",
			},
		},
		{
			name:      "empty value",
			baseEnv:   []string{"KEY="},
			overrides: map[string]string{},
			expected: map[string]string{
				"KEY": "",
			},
		},
		{
			name:    "override with empty value",
			baseEnv: []string{"KEY=value"},
			overrides: map[string]string{
				"KEY": "",
			},
			expected: map[string]string{
				"KEY": "",
			},
		},
		{
			name:      "malformed entry without equals",
			baseEnv:   []string{"VALID=value", "INVALID", "ANOTHER=test"},
			overrides: map[string]string{},
			expected: map[string]string{
				"VALID":   "value",
				"ANOTHER": "test",
			},
		},
		{
			name:      "duplicate keys in base (last wins)",
			baseEnv:   []string{"PATH=/bin", "PATH=/usr/bin"},
			overrides: map[string]string{},
			expected: map[string]string{
				"PATH": "/usr/bin",
			},
		},
		{
			name:    "multiple overrides",
			baseEnv: []string{"A=1", "B=2", "C=3"},
			overrides: map[string]string{
				"A": "new_a",
				"C": "new_c",
				"D": "new_d",
			},
			expected: map[string]string{
				"A": "new_a",
				"B": "2",
				"C": "new_c",
				"D": "new_d",
			},
		},
		{
			name:      "special characters in value",
			baseEnv:   []string{`KEY=value with spaces and "quotes"`},
			overrides: map[string]string{},
			expected: map[string]string{
				"KEY": `value with spaces and "quotes"`,
			},
		},
		{
			name:    "unicode in key and value",
			baseEnv: []string{"KEY=日本語"},
			overrides: map[string]string{
				"名前": "値",
			},
			expected: map[string]string{
				"KEY": "日本語",
				"名前":  "値",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildEnv(tt.baseEnv, tt.overrides)

			// Convert result slice to map for easier comparison
			resultMap := parseEnvToMap(result)

			assert.Equal(t, tt.expected, resultMap)

			// Verify the result is a valid environment slice
			for _, envStr := range result {
				assert.Contains(t, envStr, "=", "each entry should contain '='")
			}
		})
	}
}

func TestBuildEnv_ResultFormat(t *testing.T) {
	// Test that the result is in correct "KEY=VALUE" format
	baseEnv := []string{"PATH=/bin", "HOME=/root"}
	overrides := map[string]string{"USER": "test"}

	result := BuildEnv(baseEnv, overrides)

	require.Len(t, result, 3)

	// Each entry should be in KEY=VALUE format
	for _, entry := range result {
		parts := strings.SplitN(entry, "=", 2)
		require.Len(t, parts, 2, "entry should have exactly one '=' separator")
		assert.NotEmpty(t, parts[0], "key should not be empty")
	}
}

func TestBuildEnv_Integration(t *testing.T) {
	// Simulate real-world scenario: system environment + custom overrides
	systemEnv := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/home/user",
		"SHELL=/bin/bash",
		"USER=user",
	}

	customOverrides := map[string]string{
		"PATH":         "/custom/bin:/usr/bin", // Override PATH
		"NODE_ENV":     "production",           // Add new variable
		"DEBUG":        "false",                // Add new variable
		"DATABASE_URL": "postgres://localhost", // Add new variable with special chars
	}

	result := BuildEnv(systemEnv, customOverrides)
	resultMap := parseEnvToMap(result)

	// Verify overrides took effect
	assert.Equal(t, "/custom/bin:/usr/bin", resultMap["PATH"])
	assert.Equal(t, "production", resultMap["NODE_ENV"])
	assert.Equal(t, "false", resultMap["DEBUG"])
	assert.Equal(t, "postgres://localhost", resultMap["DATABASE_URL"])

	// Verify system vars that weren't overridden are preserved
	assert.Equal(t, "/home/user", resultMap["HOME"])
	assert.Equal(t, "/bin/bash", resultMap["SHELL"])
	assert.Equal(t, "user", resultMap["USER"])

	// Verify total count
	assert.Len(t, resultMap, 7)
}

func TestReadAllEnvVariables(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T)
		validate func(*testing.T, map[string]string)
	}{
		{
			name: "read basic environment variables",
			setup: func(t *testing.T) {
				t.Setenv("TEST_KEY1", "value1")
				t.Setenv("TEST_KEY2", "value2")
				t.Setenv("TEST_KEY3", "value3")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "value1", result["TEST_KEY1"])
				assert.Equal(t, "value2", result["TEST_KEY2"])
				assert.Equal(t, "value3", result["TEST_KEY3"])
			},
		},
		{
			name: "empty value",
			setup: func(t *testing.T) {
				t.Setenv("EMPTY_VAR", "")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Empty(t, result["EMPTY_VAR"])
			},
		},
		{
			name: "value with equals signs",
			setup: func(t *testing.T) {
				t.Setenv("KEY", "value=with=equals")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "value=with=equals", result["KEY"])
			},
		},
		{
			name: "value with special characters",
			setup: func(t *testing.T) {
				t.Setenv("URL", "https://example.com:8080/path?query=value")
				t.Setenv("JSON", `{"key":"value","nested":{"data":123}}`)
				t.Setenv("SPACES", "value with spaces")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "https://example.com:8080/path?query=value", result["URL"])
				assert.JSONEq(t, `{"key":"value","nested":{"data":123}}`, result["JSON"])
				assert.Equal(t, "value with spaces", result["SPACES"])
			},
		},
		{
			name: "unicode in key and value",
			setup: func(t *testing.T) {
				t.Setenv("TEST_KEY", "日本語テキスト")
				t.Setenv("EMOJI", "🚀 rocket 🎉")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "日本語テキスト", result["TEST_KEY"])
				assert.Equal(t, "🚀 rocket 🎉", result["EMOJI"])
			},
		},
		{
			name: "multiple variables with various patterns",
			setup: func(t *testing.T) {
				t.Setenv("MY_PATH", "/usr/bin:/bin")
				t.Setenv("MY_HOME", "/home/user")
				t.Setenv("MY_SHELL", "/bin/bash")
				t.Setenv("EMPTY", "")
				t.Setenv("WITH_EQUALS", "key=value")
				t.Setenv("GITHUB_TOKEN", "ghp_secret123")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "/usr/bin:/bin", result["MY_PATH"])
				assert.Equal(t, "/home/user", result["MY_HOME"])
				assert.Equal(t, "/bin/bash", result["MY_SHELL"])
				assert.Empty(t, result["EMPTY"])
				assert.Equal(t, "key=value", result["WITH_EQUALS"])
				assert.Equal(t, "ghp_secret123", result["GITHUB_TOKEN"])
			},
		},
		{
			name: "single variable",
			setup: func(t *testing.T) {
				t.Setenv("SINGLE", "value")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "value", result["SINGLE"])
			},
		},
		{
			name: "value with newlines and tabs",
			setup: func(t *testing.T) {
				t.Setenv("MULTILINE", "line1\nline2\ttabbed")
			},
			validate: func(t *testing.T, result map[string]string) {
				assert.Equal(t, "line1\nline2\ttabbed", result["MULTILINE"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			result := ReadAllEnvVariables()
			tt.validate(t, result)
		})
	}
}

func TestReadAllEnvVariables_ReturnType(t *testing.T) {
	t.Setenv("KEY1", "value1")
	t.Setenv("KEY2", "value2")

	result := ReadAllEnvVariables()

	// Verify it returns a map[string]string
	assert.IsType(t, map[string]string{}, result)

	// Verify keys exist and values are correct
	assert.Equal(t, "value1", result["KEY1"])
	assert.Equal(t, "value2", result["KEY2"])

	// Verify all keys are non-empty
	for key := range result {
		assert.NotEmpty(t, key, "Key should not be empty")
	}
}

func TestReadAllEnvVariables_Integration(t *testing.T) {
	// Test with actual current environment (don't clear)
	// This test validates the function works with real system environment

	result := ReadAllEnvVariables()

	// We should get at least some environment variables
	assert.NotEmpty(t, result, "should read at least some environment variables")

	// Verify all keys are non-empty
	for key := range result {
		assert.NotEmpty(t, key, "all keys should be non-empty")
	}

	// Common environment variables that should exist
	// (At least one of these should be present in most environments)
	commonVars := []string{"PATH", "HOME", "USER", "SHELL", "PWD", "USERPROFILE", "USERNAME"}
	foundAtLeastOne := false
	for _, commonVar := range commonVars {
		if _, exists := result[commonVar]; exists {
			foundAtLeastOne = true
			break
		}
	}
	assert.True(t, foundAtLeastOne, "should find at least one common environment variable")
}

func TestReadAllEnvVariables_NoSideEffects(t *testing.T) {
	// Ensure ReadAllEnvVariables doesn't modify the environment

	// Set up test environment
	t.Setenv("TEST1", "value1")
	t.Setenv("TEST2", "value2")

	// Capture environment before
	envBefore := os.Environ()

	// Call the function
	_ = ReadAllEnvVariables()

	// Capture environment after
	envAfter := os.Environ()

	// Environment should be unchanged
	assert.Equal(t, envBefore, envAfter, "function should not modify environment")
}

func TestReadAllEnvVariables_OrderIndependence(t *testing.T) {
	// Test that the function returns all variables regardless of order

	expectedVars := map[string]string{
		"AAA": "first",
		"ZZZ": "last",
		"MMM": "middle",
		"AAB": "second",
		"ZZY": "second-last",
	}

	for k, v := range expectedVars {
		t.Setenv(k, v)
	}

	result := ReadAllEnvVariables()

	// All expected variables should be present (there may be more from the system)
	for k, v := range expectedVars {
		assert.Equal(t, v, result[k], "expected variable %s to have value %s", k, v)
	}
}
