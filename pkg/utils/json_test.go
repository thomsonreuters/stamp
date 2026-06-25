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
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:funlen // Comprehensive JSON sanitization test requires extensive test cases
func TestSanitizeJSON(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		patterns          []RedactionPattern
		expectedRedacted  map[string]string // key-value pairs that should be redacted
		expectedPreserved map[string]string // key-value pairs that should be preserved
		minRedactionCount int
	}{
		{
			name: "redact email addresses",
			input: `{
				"user": "john",
				"email": "john.doe@example.com",
				"contact": "admin@company.org"
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
					Replace: "[REDACTED_EMAIL]",
				},
			},
			expectedRedacted: map[string]string{
				"email":   "[REDACTED_EMAIL]",
				"contact": "[REDACTED_EMAIL]",
			},
			expectedPreserved: map[string]string{
				"user": "john",
			},
			minRedactionCount: 2,
		},
		{
			name: "redact GitHub tokens",
			input: `{
				"token": "ghp_123456789012345678901234567890123456",
				"name": "My Token",
				"secret": "ghs_123456789012345678901234567890123456"
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36}`),
					Replace: "[REDACTED_TOKEN]",
				},
			},
			expectedRedacted: map[string]string{
				"token":  "[REDACTED_TOKEN]",
				"secret": "[REDACTED_TOKEN]",
			},
			expectedPreserved: map[string]string{
				"name": "My Token",
			},
			minRedactionCount: 2,
		},
		{
			name: "preserve JSON structure - nested objects",
			input: `{
				"user": {
					"name": "John",
					"email": "john@example.com",
					"age": 30
				},
				"settings": {
					"theme": "dark"
				}
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 1,
		},
		{
			name: "preserve JSON structure - arrays",
			input: `{
				"emails": ["admin@company.com", "support@company.com"],
				"names": ["Alice", "Bob"],
				"counts": [1, 2, 3]
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 2,
		},
		{
			name: "preserve numbers, booleans, and null",
			input: `{
				"count": 42,
				"price": 19.99,
				"active": true,
				"disabled": false,
				"optional": null,
				"token": "secret123"
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`secret\d+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 1,
		},
		{
			name: "multiple patterns",
			input: `{
				"email": "user@example.com",
				"token": "ghp_abc123def456ghi789jkl012mno345pqr",
				"password": "examplesecret123"
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED_EMAIL]",
				},
				{
					Pattern: regexp.MustCompile(`ghp_\w{36}`),
					Replace: "[REDACTED_TOKEN]",
				},
				{
					Pattern: regexp.MustCompile(`\w+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 3,
		},
		{
			name: "empty patterns - no redaction",
			input: `{
				"key": "value",
				"number": 123
			}`,
			patterns:          []RedactionPattern{},
			minRedactionCount: 0,
		},
		{
			name: "pattern doesn't match",
			input: `{
				"key": "value"
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 0,
		},
		{
			name: "deeply nested structure",
			input: `{
				"level1": {
					"level2": {
						"level3": {
							"email": "deep@example.com",
							"data": "normal"
						}
					}
				}
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 1,
		},
		{
			name: "mixed arrays and objects",
			input: `{
				"users": [
					{"name": "Alice", "email": "alice@example.com"},
					{"name": "Bob", "email": "bob@example.com"}
				],
				"metadata": {
					"count": 2,
					"admin": "admin@example.com"
				}
			}`,
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			minRedactionCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SanitizeJSON([]byte(tt.input), tt.patterns)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.GreaterOrEqual(t, result.RedactionCount, tt.minRedactionCount)

			// Verify output is valid JSON
			assert.True(t, json.Valid(result.Sanitized))

			// Parse result to verify expectations
			var parsed map[string]any
			err = json.Unmarshal(result.Sanitized, &parsed)
			require.NoError(t, err)

			// Check expected redacted values
			for key, expectedValue := range tt.expectedRedacted {
				value := getNestedValue(parsed, key)
				assert.Equal(t, expectedValue, value, "key %s should be redacted", key)
			}

			// Check expected preserved values
			for key, expectedValue := range tt.expectedPreserved {
				value := getNestedValue(parsed, key)
				assert.Equal(t, expectedValue, value, "key %s should be preserved", key)
			}
		})
	}
}

func TestSanitizeJSON_InvalidInput(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		patterns      []RedactionPattern
		expectedError string
	}{
		{
			name:          "invalid JSON - missing bracket",
			input:         `{"key": "value"`,
			patterns:      []RedactionPattern{},
			expectedError: "invalid JSON",
		},
		{
			name:          "invalid JSON - malformed",
			input:         `{key: value}`,
			patterns:      []RedactionPattern{},
			expectedError: "invalid JSON",
		},
		{
			name:          "empty input",
			input:         ``,
			patterns:      []RedactionPattern{},
			expectedError: "invalid JSON",
		},
		{
			name:          "not JSON - plain text",
			input:         `This is not JSON`,
			patterns:      []RedactionPattern{},
			expectedError: "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SanitizeJSON([]byte(tt.input), tt.patterns)

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestSanitizeJSON_PreservesStructure(t *testing.T) {
	input := `{
		"string": "value",
		"number": 42,
		"float": 3.14,
		"boolean": true,
		"null_value": null,
		"empty_string": "",
		"array": [1, 2, 3],
		"object": {"nested": "data"}
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`NOMATCH`),
			Replace: "[REDACTED]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	// Parse both input and output
	var inputParsed, outputParsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(input), &inputParsed))
	require.NoError(t, json.Unmarshal(result.Sanitized, &outputParsed))

	// Verify types are preserved
	assert.IsType(t, "", outputParsed["string"])
	assert.IsType(t, float64(0), outputParsed["number"])
	assert.IsType(t, float64(0), outputParsed["float"])
	assert.IsType(t, true, outputParsed["boolean"])
	assert.Nil(t, outputParsed["null_value"])
	assert.IsType(t, "", outputParsed["empty_string"])
	assert.IsType(t, []any{}, outputParsed["array"])
	assert.IsType(t, map[string]any{}, outputParsed["object"])

	// Verify no redactions occurred
	assert.Equal(t, 0, result.RedactionCount)
}

func TestSanitizeJSON_KeysNotRedacted(t *testing.T) {
	// This test ensures keys are never redacted, only values
	input := `{
		"email": "user@example.com",
		"token": "ghp_secret",
		"password": "secret123"
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`.*`), // Matches everything
			Replace: "[REDACTED]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	// Keys should still exist (not redacted)
	assert.Contains(t, parsed, "email")
	assert.Contains(t, parsed, "token")
	assert.Contains(t, parsed, "password")

	// Values should be redacted
	assert.Equal(t, "[REDACTED]", parsed["email"])
	assert.Equal(t, "[REDACTED]", parsed["token"])
	assert.Equal(t, "[REDACTED]", parsed["password"])
}

func TestSanitizeJSON_ComplexRealWorld(t *testing.T) {
	input := `{
		"action": "opened",
		"number": 123,
		"pull_request": {
			"id": 456789,
			"title": "Fix bug",
			"user": {
				"login": "octocat",
				"email": "octocat@github.com",
				"id": 12345
			},
			"token": "ghp_123456789012345678901234567890123456"
		},
		"repository": {
			"name": "example-repo",
			"private": true,
			"owner": {
				"login": "exampleorg",
				"email": "admin@exampleorg.com"
			}
		},
		"sender": {
			"login": "contributor",
			"api_token": "ghs_123456789012345678901234567890123456"
		}
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			Replace: "[REDACTED_EMAIL]",
		},
		{
			Pattern: regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36}`),
			Replace: "[REDACTED_TOKEN]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify it's valid JSON
	assert.True(t, json.Valid(result.Sanitized))

	// At least 4 redactions (2 emails + 2 tokens)
	assert.GreaterOrEqual(t, result.RedactionCount, 4)

	// Parse and verify structure
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	// Verify numbers and booleans preserved
	pr, _ := parsed["pull_request"].(map[string]any)
	assert.InDelta(t, float64(456789), pr["id"], 0.0001)
	assert.Equal(t, "Fix bug", pr["title"])

	repo, _ := parsed["repository"].(map[string]any)
	assert.Equal(t, "example-repo", repo["name"])
	assert.Equal(t, true, repo["private"])

	// Verify emails were redacted
	prUser, _ := pr["user"].(map[string]any)
	assert.Equal(t, "[REDACTED_EMAIL]", prUser["email"])

	repoOwner, _ := repo["owner"].(map[string]any)
	assert.Equal(t, "[REDACTED_EMAIL]", repoOwner["email"])

	// Verify tokens were redacted
	assert.Equal(t, "[REDACTED_TOKEN]", pr["token"])
	sender, _ := parsed["sender"].(map[string]any)
	assert.Equal(t, "[REDACTED_TOKEN]", sender["api_token"])

	// Verify non-sensitive values preserved
	assert.Equal(t, "opened", parsed["action"])
	assert.InDelta(t, float64(123), parsed["number"], 0.0001)
	assert.Equal(t, "octocat", prUser["login"])
}

func TestSanitizeJSON_ArrayOfObjects(t *testing.T) {
	input := `{
		"users": [
			{"name": "Alice", "email": "alice@example.com"},
			{"name": "Bob", "email": "bob@example.com"},
			{"name": "Charlie", "email": "charlie@example.com"}
		]
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`\S+@\S+`),
			Replace: "[REDACTED]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	assert.Equal(t, 3, result.RedactionCount) // 3 emails redacted

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	users, _ := parsed["users"].([]any)
	assert.Len(t, users, 3)

	// Verify all emails redacted, names preserved
	for i, expectedName := range []string{"Alice", "Bob", "Charlie"} {
		user, _ := users[i].(map[string]any)
		assert.Equal(t, expectedName, user["name"])
		assert.Equal(t, "[REDACTED]", user["email"])
	}
}

func TestSanitizeJSON_EmptyValues(t *testing.T) {
	input := `{
		"empty_string": "",
		"empty_array": [],
		"empty_object": {},
		"null_value": null
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`.*`),
			Replace: "[REDACTED]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	// Empty string should be redacted (it matches .*)
	assert.Equal(t, "[REDACTED]", parsed["empty_string"])

	// Empty array/object/null should be preserved (not strings)
	assert.Equal(t, []any{}, parsed["empty_array"])
	assert.Equal(t, map[string]any{}, parsed["empty_object"])
	assert.Nil(t, parsed["null_value"])
}

func TestSanitizeJSON_PartialMatch(t *testing.T) {
	input := `{
		"message": "My email is john@example.com and my token is ghp_123456789012345678901234567890123456",
		"url": "https://user:password@example.com/path"
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			Replace: "[EMAIL]",
		},
		{
			Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
			Replace: "[TOKEN]",
		},
		{
			Pattern: regexp.MustCompile(`://([^:]+):([^@]+)@`),
			Replace: "://$1:[PASS]@",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	// Check message has both email and token redacted
	message, _ := parsed["message"].(string)
	assert.Contains(t, message, "[EMAIL]")
	assert.Contains(t, message, "[TOKEN]")
	assert.NotContains(t, message, "john@example.com")
	assert.NotContains(t, message, "ghp_")

	// Check URL - note that email pattern matches before password pattern,
	// so the entire "user:password@example.com" part gets redacted as [EMAIL]
	url, _ := parsed["url"].(string)
	assert.NotContains(t, url, "password")
	// The URL structure is preserved, but the email/password part is redacted
	assert.Contains(t, url, "https://")
}

func TestSanitizeJSON_UnicodeValues(t *testing.T) {
	input := `{
		"japanese": "日本語のテキスト",
		"emoji": "🚀 Launch 🎉",
		"mixed": "Hello 世界 token@example.com"
	}`

	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`\S+@\S+`),
			Replace: "[REDACTED]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	// Unicode should be preserved
	assert.Equal(t, "日本語のテキスト", parsed["japanese"])
	assert.Equal(t, "🚀 Launch 🎉", parsed["emoji"])

	// Only email should be redacted
	mixed, _ := parsed["mixed"].(string)
	assert.Contains(t, mixed, "Hello 世界")
	assert.Contains(t, mixed, "[REDACTED]")
	assert.NotContains(t, mixed, "token@example.com")
}

func TestSanitizeJSON_AlwaysValidJSON(t *testing.T) {
	// Test that even with aggressive patterns, JSON is never broken
	input := `{
		"key": "value",
		"nested": {
			"data": "text"
		},
		"array": ["item1", "item2"]
	}`

	// Extremely aggressive pattern that matches everything
	patterns := []RedactionPattern{
		{
			Pattern: regexp.MustCompile(`.+`),
			Replace: "[X]",
		},
	}

	result, err := SanitizeJSON([]byte(input), patterns)
	require.NoError(t, err)

	// Should still be valid JSON
	assert.True(t, json.Valid(result.Sanitized))

	// Structure should be intact
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result.Sanitized, &parsed))

	// Keys should exist
	assert.Contains(t, parsed, "key")
	assert.Contains(t, parsed, "nested")
	assert.Contains(t, parsed, "array")

	// Values should be redacted
	assert.Equal(t, "[X]", parsed["key"])
}

func TestRedactJSONValues(t *testing.T) {
	tests := []struct {
		name          string
		input         any
		patterns      []RedactionPattern
		expectedCount int
		verifyOutput  func(*testing.T, any)
	}{
		{
			name: "simple map",
			input: map[string]any{
				"email": "test@example.com",
				"name":  "Test User",
			},
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			expectedCount: 1,
			verifyOutput: func(t *testing.T, output any) {
				m, _ := output.(map[string]any)
				assert.Equal(t, "[REDACTED]", m["email"])
				assert.Equal(t, "Test User", m["name"])
			},
		},
		{
			name: "simple array",
			input: []any{
				"email1@example.com",
				"email2@example.com",
				"normal text",
			},
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			expectedCount: 2,
			verifyOutput: func(t *testing.T, output any) {
				arr, _ := output.([]any)
				assert.Equal(t, "[REDACTED]", arr[0])
				assert.Equal(t, "[REDACTED]", arr[1])
				assert.Equal(t, "normal text", arr[2])
			},
		},
		{
			name:          "non-string values - no redaction",
			input:         map[string]any{"count": 42, "active": true},
			patterns:      []RedactionPattern{},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := redactJSONValues(tt.input, tt.patterns)
			assert.Equal(t, tt.expectedCount, count)

			if tt.verifyOutput != nil {
				tt.verifyOutput(t, tt.input)
			}
		})
	}
}

func TestApplyRedactionPatterns(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		patterns      []RedactionPattern
		expectedValue string
		expectedCount int
	}{
		{
			name:  "single pattern match",
			value: "user@example.com",
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			expectedValue: "[REDACTED]",
			expectedCount: 1,
		},
		{
			name:  "multiple patterns",
			value: "email: user@example.com, token: ghp_123456789012345678901234567890123456",
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
					Replace: "[EMAIL]",
				},
				{
					Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
					Replace: "[TOKEN]",
				},
			},
			expectedValue: "email: [EMAIL], token: [TOKEN]",
			expectedCount: 2,
		},
		{
			name:          "no match",
			value:         "normal text",
			patterns:      []RedactionPattern{},
			expectedValue: "normal text",
			expectedCount: 0,
		},
		{
			name:  "multiple occurrences",
			value: "email1@test.com and email2@test.com and email3@test.com",
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[X]",
				},
			},
			expectedValue: "[X] and [X] and [X]",
			expectedCount: 3,
		},
		{
			name:  "empty value",
			value: "",
			patterns: []RedactionPattern{
				{
					Pattern: regexp.MustCompile(`\S+@\S+`),
					Replace: "[REDACTED]",
				},
			},
			expectedValue: "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, count := applyRedactionPatterns(tt.value, tt.patterns)
			assert.Equal(t, tt.expectedValue, result)
			assert.Equal(t, tt.expectedCount, count)
		})
	}
}

// Helper function to get nested value from parsed JSON.
func getNestedValue(data map[string]any, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func TestReadJSONFile(t *testing.T) {
	t.Run("valid JSON file", func(t *testing.T) {
		path := t.TempDir() + "/test.json"
		require.NoError(t, os.WriteFile(path, []byte(`{"key": "value", "num": 42}`), 0o600))

		result, err := ReadJSONFile(path)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
		assert.InDelta(t, float64(42), result["num"], 0)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ReadJSONFile("/nonexistent/path.json")
		require.Error(t, err)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		path := t.TempDir() + "/bad.json"
		require.NoError(t, os.WriteFile(path, []byte(`not json`), 0o600))

		_, err := ReadJSONFile(path)
		require.Error(t, err)
	})
}
