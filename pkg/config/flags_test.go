// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected any
	}{
		// Booleans
		{
			name:     "boolean true",
			input:    "true",
			expected: true,
		},
		{
			name:     "boolean false",
			input:    "false",
			expected: false,
		},

		// Integers
		{
			name:     "positive integer",
			input:    "42",
			expected: 42,
		},
		{
			name:     "negative integer",
			input:    "-17",
			expected: -17,
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
		},

		// Floats
		{
			name:     "positive float",
			input:    "3.14",
			expected: 3.14,
		},
		{
			name:     "negative float",
			input:    "-2.5",
			expected: -2.5,
		},
		{
			name:     "float with exponent",
			input:    "1.5e10",
			expected: 1.5e10,
		},

		// String slices (comma-separated)
		{
			name:     "comma-separated values",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "comma-separated with spaces",
			input:    "foo, bar, baz",
			expected: []string{"foo", "bar", "baz"},
		},
		{
			name:     "comma-separated with empty values",
			input:    "a,,b",
			expected: []string{"a", "b"},
		},
		{
			name:     "comma-separated numbers as strings",
			input:    "1,2,3",
			expected: []string{"1", "2", "3"},
		},

		// Plain strings
		{
			name:     "plain string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "string that looks like bool but isn't",
			input:    "True",
			expected: "True",
		},
		{
			name:     "string path",
			input:    "/path/to/file",
			expected: "/path/to/file",
		},
		{
			name:     "URL string",
			input:    "https://example.com",
			expected: "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMapEntries(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "single entry",
			input: "key=value",
			expected: map[string]string{
				"key": "value",
			},
		},
		{
			name:  "multiple entries",
			input: "key1=val1,key2=val2",
			expected: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
		},
		{
			name:  "entries with spaces",
			input: "key1 = val1 , key2 = val2",
			expected: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
		},
		{
			name:  "quoted values double quotes",
			input: `key="value with spaces"`,
			expected: map[string]string{
				"key": "value with spaces",
			},
		},
		{
			name:  "quoted values single quotes",
			input: "key='value with spaces'",
			expected: map[string]string{
				"key": "value with spaces",
			},
		},
		{
			name:  "key without value",
			input: "keyonly",
			expected: map[string]string{
				"keyonly": "",
			},
		},
		{
			name:  "mixed entries",
			input: "key1=val1,keyonly,key2=val2",
			expected: map[string]string{
				"key1":    "val1",
				"keyonly": "",
				"key2":    "val2",
			},
		},
		{
			name:  "empty entries are skipped",
			input: "key1=val1,,key2=val2",
			expected: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
		},
		{
			name:  "value with equals sign",
			input: "key=val=ue",
			expected: map[string]string{
				"key": "val=ue",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMapEntries(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSetFlags(t *testing.T) {
	t.Run("empty flags", func(t *testing.T) {
		result, err := ParseSetFlags([]string{}, "")
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("single string flag", func(t *testing.T) {
		result, err := ParseSetFlags([]string{"name=test"}, "")
		require.NoError(t, err)
		assert.Equal(t, "test", result["name"])
	})

	t.Run("multiple flags", func(t *testing.T) {
		result, err := ParseSetFlags([]string{
			"name=test",
			"count=42",
			"enabled=true",
		}, "")
		require.NoError(t, err)
		assert.Equal(t, "test", result["name"])
		assert.Equal(t, 42, result["count"])
		assert.Equal(t, true, result["enabled"])
	})

	t.Run("flag with spaces around equals", func(t *testing.T) {
		result, err := ParseSetFlags([]string{"name = test"}, "")
		require.NoError(t, err)
		assert.Equal(t, "test", result["name"])
	})

	t.Run("flag with value containing equals", func(t *testing.T) {
		result, err := ParseSetFlags([]string{"url=https://example.com?foo=bar"}, "")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com?foo=bar", result["url"])
	})

	t.Run("comma-separated values", func(t *testing.T) {
		result, err := ParseSetFlags([]string{"tags=a,b,c"}, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, result["tags"])
	})

	t.Run("error on invalid format - no equals", func(t *testing.T) {
		_, err := ParseSetFlags([]string{"invalid"}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid --set format")
	})

	t.Run("error on empty key", func(t *testing.T) {
		_, err := ParseSetFlags([]string{"=value"}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key cannot be empty")
	})

	t.Run("empty value is allowed", func(t *testing.T) {
		result, err := ParseSetFlags([]string{"key="}, "")
		require.NoError(t, err)
		assert.Empty(t, result["key"])
	})

	t.Run("boolean values", func(t *testing.T) {
		result, err := ParseSetFlags([]string{
			"enabled=true",
			"disabled=false",
		}, "")
		require.NoError(t, err)
		assert.Equal(t, true, result["enabled"])
		assert.Equal(t, false, result["disabled"])
	})

	t.Run("numeric values", func(t *testing.T) {
		result, err := ParseSetFlags([]string{
			"port=8080",
			"ratio=0.75",
		}, "")
		require.NoError(t, err)
		assert.Equal(t, 8080, result["port"])
		assert.InDelta(t, 0.75, result["ratio"], 0.0001)
	})

	t.Run("path values", func(t *testing.T) {
		result, err := ParseSetFlags([]string{
			"path=/usr/local/bin",
			"file=./config.yaml",
		}, "")
		require.NoError(t, err)
		assert.Equal(t, "/usr/local/bin", result["path"])
		assert.Equal(t, "./config.yaml", result["file"])
	})

	t.Run("overwrites duplicate keys", func(t *testing.T) {
		result, err := ParseSetFlags([]string{
			"key=first",
			"key=second",
		}, "")
		require.NoError(t, err)
		assert.Equal(t, "second", result["key"])
	})

	t.Run("with unknown attestor type falls back to default parsing", func(t *testing.T) {
		result, err := ParseSetFlags([]string{"field=value"}, "unknown-attestor")
		require.NoError(t, err)
		assert.Equal(t, "value", result["field"])
	})
}

func TestParseSetFlags_WithWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		key      string
		expected any
	}{
		{
			name:     "leading whitespace in key",
			input:    "  key=value",
			key:      "key",
			expected: "value",
		},
		{
			name:     "trailing whitespace in key",
			input:    "key  =value",
			key:      "key",
			expected: "value",
		},
		{
			name:     "leading whitespace in value",
			input:    "key=  value",
			key:      "key",
			expected: "value",
		},
		{
			name:     "trailing whitespace in value",
			input:    "key=value  ",
			key:      "key",
			expected: "value",
		},
		{
			name:     "whitespace around both",
			input:    "  key  =  value  ",
			key:      "key",
			expected: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSetFlags([]string{tt.input}, "")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result[tt.key])
		})
	}
}

func TestParseValue_EdgeCases(t *testing.T) {
	t.Run("large integer within int range", func(t *testing.T) {
		result := ParseValue("2147483647")
		assert.Equal(t, 2147483647, result)
	})

	t.Run("negative large integer", func(t *testing.T) {
		result := ParseValue("-2147483648")
		assert.Equal(t, -2147483648, result)
	})

	t.Run("very small float", func(t *testing.T) {
		result := ParseValue("0.0001")
		assert.InDelta(t, 0.0001, result, 0.00001)
	})

	t.Run("scientific notation", func(t *testing.T) {
		result := ParseValue("1e-5")
		assert.InDelta(t, 1e-5, result, 0.000001)
	})

	t.Run("trailing comma creates empty entry filtered out", func(t *testing.T) {
		result := ParseValue("a,b,")
		assert.Equal(t, []string{"a", "b"}, result)
	})

	t.Run("leading comma creates empty entry filtered out", func(t *testing.T) {
		result := ParseValue(",a,b")
		assert.Equal(t, []string{"a", "b"}, result)
	})

	t.Run("only whitespace between commas", func(t *testing.T) {
		result := ParseValue("a,   ,b")
		assert.Equal(t, []string{"a", "b"}, result)
	})
}

func TestParseMapEntries_EdgeCases(t *testing.T) {
	t.Run("value with embedded comma not supported", func(t *testing.T) {
		// This is a known limitation - commas in values need quoting
		result := ParseMapEntries("key=a,b,c")
		// Without quotes, this gets split incorrectly
		assert.Contains(t, result, "key")
	})

	t.Run("multiple equals in value", func(t *testing.T) {
		result := ParseMapEntries("equation=1+1=2")
		assert.Equal(t, "1+1=2", result["equation"])
	})

	t.Run("only whitespace entries", func(t *testing.T) {
		result := ParseMapEntries("   ,   ,   ")
		assert.Empty(t, result)
	})

	t.Run("mixed quotes", func(t *testing.T) {
		result := ParseMapEntries(`key="value'`)
		// Outer quotes are stripped
		assert.Equal(t, "value", result["key"])
	})
}
