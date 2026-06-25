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

package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestorConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		schema      []ConfigField
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with all required fields",
			config: Config{
				"name":    "test",
				"enabled": true,
				"count":   42,
			},
			schema: []ConfigField{
				{Name: "name", Type: "string", Required: true},
				{Name: "enabled", Type: "bool", Required: true},
				{Name: "count", Type: "int", Required: false},
			},
			expectError: false,
		},
		{
			name: "missing required field",
			config: Config{
				"name": "test",
			},
			schema: []ConfigField{
				{Name: "name", Type: "string", Required: true},
				{Name: "enabled", Type: "bool", Required: true},
			},
			expectError: true,
			errorMsg:    "required field is missing",
		},
		{
			name: "invalid type - string expected",
			config: Config{
				"name": 123,
			},
			schema: []ConfigField{
				{Name: "name", Type: "string", Required: true},
			},
			expectError: true,
			errorMsg:    "must be a string",
		},
		{
			name: "invalid type - bool expected",
			config: Config{
				"enabled": "true",
			},
			schema: []ConfigField{
				{Name: "enabled", Type: "bool", Required: true},
			},
			expectError: true,
			errorMsg:    "must be a boolean",
		},
		{
			name: "invalid type - int expected",
			config: Config{
				"count": "42",
			},
			schema: []ConfigField{
				{Name: "count", Type: "int", Required: true},
			},
			expectError: true,
			errorMsg:    "must be an integer",
		},
		{
			name: "valid string slice",
			config: Config{
				"tags": []string{"tag1", "tag2"},
			},
			schema: []ConfigField{
				{Name: "tags", Type: "[]string", Required: true},
			},
			expectError: false,
		},
		{
			name: "valid string slice from interface slice",
			config: Config{
				"tags": []any{"tag1", "tag2"},
			},
			schema: []ConfigField{
				{Name: "tags", Type: "[]string", Required: true},
			},
			expectError: false,
		},
		{
			name: "invalid string slice - contains non-string",
			config: Config{
				"tags": []any{"tag1", 123},
			},
			schema: []ConfigField{
				{Name: "tags", Type: "[]string", Required: true},
			},
			expectError: true,
			errorMsg:    "must be a string",
		},
		{
			name: "valid map string to string",
			config: Config{
				"labels": map[string]string{"key": "value"},
			},
			schema: []ConfigField{
				{Name: "labels", Type: "map[string]string", Required: true},
			},
			expectError: false,
		},
		{
			name: "valid map from interface map",
			config: Config{
				"labels": map[string]any{"key": "value"},
			},
			schema: []ConfigField{
				{Name: "labels", Type: "map[string]string", Required: true},
			},
			expectError: false,
		},
		{
			name: "optional field missing is valid",
			config: Config{
				"name": "test",
			},
			schema: []ConfigField{
				{Name: "name", Type: "string", Required: true},
				{Name: "optional", Type: "string", Required: false},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate(tt.schema)

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

func TestAttestorConfig_GetString(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		key          string
		defaultValue string
		expected     string
	}{
		{
			name:         "existing string value",
			config:       Config{"name": "test"},
			key:          "name",
			defaultValue: "default",
			expected:     "test",
		},
		{
			name:         "missing key returns default",
			config:       Config{},
			key:          "name",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "wrong type returns default",
			config:       Config{"name": 123},
			key:          "name",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "empty string value",
			config:       Config{"name": ""},
			key:          "name",
			defaultValue: "default",
			expected:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetString(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttestorConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		key      string
		expected bool
	}{
		{
			name:     "missing key is empty",
			config:   Config{},
			key:      "name",
			expected: true,
		},
		{
			name:     "empty string value is empty",
			config:   Config{"name": ""},
			key:      "name",
			expected: true,
		},
		{
			name:     "non-string value is empty",
			config:   Config{"count": 42},
			key:      "count",
			expected: true,
		},
		{
			name:     "non-empty string is not empty",
			config:   Config{"name": "test"},
			key:      "name",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.IsEmpty(tt.key))
		})
	}
}

func TestAttestorConfig_GetBool(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		key          string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "existing bool true",
			config:       Config{"enabled": true},
			key:          "enabled",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "existing bool false",
			config:       Config{"enabled": false},
			key:          "enabled",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "string 'true'",
			config:       Config{"enabled": "true"},
			key:          "enabled",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "string 'TRUE' (case insensitive)",
			config:       Config{"enabled": "TRUE"},
			key:          "enabled",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "string 'false'",
			config:       Config{"enabled": "false"},
			key:          "enabled",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "missing key returns default",
			config:       Config{},
			key:          "enabled",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "wrong type returns default",
			config:       Config{"enabled": 123},
			key:          "enabled",
			defaultValue: true,
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetBool(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttestorConfig_GetInt(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		key          string
		defaultValue int
		expected     int
	}{
		{
			name:         "existing int value",
			config:       Config{"count": 42},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "int from float64 (JSON unmarshaling)",
			config:       Config{"count": float64(42)},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "int from int64",
			config:       Config{"count": int64(42)},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "int from int32",
			config:       Config{"count": int32(42)},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "missing key returns default",
			config:       Config{},
			key:          "count",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "wrong type returns default",
			config:       Config{"count": "42"},
			key:          "count",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "zero value",
			config:       Config{"count": 0},
			key:          "count",
			defaultValue: 99,
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetInt(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttestorConfig_GetInt64(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		key          string
		defaultValue int64
		expected     int64
	}{
		{
			name:         "existing int64 value",
			config:       Config{"count": int64(42)},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "int64 from int",
			config:       Config{"count": 42},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "int64 from float64",
			config:       Config{"count": float64(42)},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "int64 from int32",
			config:       Config{"count": int32(42)},
			key:          "count",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "missing key returns default",
			config:       Config{},
			key:          "count",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "large int64 value",
			config:       Config{"count": int64(9223372036854775807)},
			key:          "count",
			defaultValue: 0,
			expected:     9223372036854775807,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetInt64(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttestorConfig_GetDuration(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		key          string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{
			name:         "existing duration value",
			config:       Config{"timeout": 10 * time.Second},
			key:          "timeout",
			defaultValue: 5 * time.Second,
			expected:     10 * time.Second,
		},
		{
			name:         "duration from string",
			config:       Config{"timeout": "30s"},
			key:          "timeout",
			defaultValue: 5 * time.Second,
			expected:     30 * time.Second,
		},
		{
			name:         "duration from string minutes",
			config:       Config{"timeout": "5m"},
			key:          "timeout",
			defaultValue: 1 * time.Second,
			expected:     5 * time.Minute,
		},
		{
			name:         "duration from string hours",
			config:       Config{"timeout": "2h"},
			key:          "timeout",
			defaultValue: 1 * time.Second,
			expected:     2 * time.Hour,
		},
		{
			name:         "duration from string milliseconds",
			config:       Config{"timeout": "500ms"},
			key:          "timeout",
			defaultValue: 1 * time.Second,
			expected:     500 * time.Millisecond,
		},
		{
			name:         "duration from string complex",
			config:       Config{"timeout": "1h30m"},
			key:          "timeout",
			defaultValue: 1 * time.Second,
			expected:     90 * time.Minute,
		},
		{
			name:         "missing key returns default",
			config:       Config{},
			key:          "timeout",
			defaultValue: 15 * time.Second,
			expected:     15 * time.Second,
		},
		{
			name:         "invalid duration string returns default",
			config:       Config{"timeout": "invalid"},
			key:          "timeout",
			defaultValue: 10 * time.Second,
			expected:     10 * time.Second,
		},
		{
			name:         "empty string returns default",
			config:       Config{"timeout": ""},
			key:          "timeout",
			defaultValue: 10 * time.Second,
			expected:     10 * time.Second,
		},
		{
			name:         "wrong type returns default",
			config:       Config{"timeout": 123},
			key:          "timeout",
			defaultValue: 10 * time.Second,
			expected:     10 * time.Second,
		},
		{
			name:         "zero duration",
			config:       Config{"timeout": 0 * time.Second},
			key:          "timeout",
			defaultValue: 10 * time.Second,
			expected:     0 * time.Second,
		},
		{
			name:         "negative duration",
			config:       Config{"timeout": -5 * time.Second},
			key:          "timeout",
			defaultValue: 10 * time.Second,
			expected:     -5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetDuration(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttestorConfig_GetStringSlice(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		key          string
		defaultValue []string
		expected     []string
	}{
		{
			name:         "existing string slice",
			config:       Config{"tags": []string{"tag1", "tag2"}},
			key:          "tags",
			defaultValue: nil,
			expected:     []string{"tag1", "tag2"},
		},
		{
			name:         "interface slice with strings",
			config:       Config{"tags": []any{"tag1", "tag2"}},
			key:          "tags",
			defaultValue: nil,
			expected:     []string{"tag1", "tag2"},
		},
		{
			name:         "comma-separated string",
			config:       Config{"tags": "tag1,tag2,tag3"},
			key:          "tags",
			defaultValue: nil,
			expected:     []string{"tag1", "tag2", "tag3"},
		},
		{
			name:         "comma-separated string with spaces",
			config:       Config{"tags": "tag1, tag2 , tag3"},
			key:          "tags",
			defaultValue: nil,
			expected:     []string{"tag1", "tag2", "tag3"},
		},
		{
			name:         "missing key returns default",
			config:       Config{},
			key:          "tags",
			defaultValue: []string{"default1", "default2"},
			expected:     []string{"default1", "default2"},
		},
		{
			name:         "missing key without default returns empty slice",
			config:       Config{},
			key:          "tags",
			defaultValue: nil,
			expected:     []string{},
		},
		{
			name:         "empty string returns default",
			config:       Config{"tags": ""},
			key:          "tags",
			defaultValue: []string{"default"},
			expected:     []string{"default"},
		},
		{
			name:         "interface slice with non-strings returns default",
			config:       Config{"tags": []any{"tag1", 123}},
			key:          "tags",
			defaultValue: []string{"default"},
			expected:     []string{"tag1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []string
			if tt.defaultValue != nil {
				result = tt.config.GetStringSlice(tt.key, tt.defaultValue)
			} else {
				result = tt.config.GetStringSlice(tt.key)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttestorConfig_GetMap(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		key      string
		expected map[string]string
	}{
		{
			name: "existing map string to string",
			config: Config{
				"labels": map[string]string{"key1": "value1", "key2": "value2"},
			},
			key:      "labels",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name: "map string to interface",
			config: Config{
				"labels": map[string]any{"key1": "value1", "key2": 123},
			},
			key:      "labels",
			expected: map[string]string{"key1": "value1", "key2": "123"},
		},
		{
			name:     "string format KEY=VALUE",
			config:   Config{"labels": "key1=value1,key2=value2"},
			key:      "labels",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "string format with spaces",
			config:   Config{"labels": "key1=value1, key2 = value2"},
			key:      "labels",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "missing key returns nil",
			config:   Config{},
			key:      "labels",
			expected: nil,
		},
		{
			name:     "empty string returns nil",
			config:   Config{"labels": ""},
			key:      "labels",
			expected: nil,
		},
		{
			name:     "wrong type returns nil",
			config:   Config{"labels": 123},
			key:      "labels",
			expected: nil,
		},
		{
			name:     "empty map",
			config:   Config{"labels": map[string]string{}},
			key:      "labels",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMap(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

//nolint:funlen // Field type validation test requires many test cases for different types
func TestValidateFieldType(t *testing.T) {
	tests := []struct {
		name         string
		fieldName    string
		value        any
		expectedType string
		expectError  bool
	}{
		{
			name:         "valid string",
			fieldName:    "name",
			value:        "test",
			expectedType: "string",
			expectError:  false,
		},
		{
			name:         "invalid string",
			fieldName:    "name",
			value:        123,
			expectedType: "string",
			expectError:  true,
		},
		{
			name:         "valid bool",
			fieldName:    "enabled",
			value:        true,
			expectedType: "bool",
			expectError:  false,
		},
		{
			name:         "invalid bool",
			fieldName:    "enabled",
			value:        "true",
			expectedType: "bool",
			expectError:  true,
		},
		{
			name:         "valid int",
			fieldName:    "count",
			value:        42,
			expectedType: "int",
			expectError:  false,
		},
		{
			name:         "valid int32",
			fieldName:    "count",
			value:        int32(42),
			expectedType: "int",
			expectError:  false,
		},
		{
			name:         "valid int64",
			fieldName:    "count",
			value:        int64(42),
			expectedType: "int",
			expectError:  false,
		},
		{
			name:         "valid float64 as int (JSON unmarshaling)",
			fieldName:    "count",
			value:        float64(42),
			expectedType: "int",
			expectError:  false,
		},
		{
			name:         "invalid int",
			fieldName:    "count",
			value:        "42",
			expectedType: "int",
			expectError:  true,
		},
		{
			name:         "valid float32",
			fieldName:    "rate",
			value:        float32(3.14),
			expectedType: "float",
			expectError:  false,
		},
		{
			name:         "valid float64",
			fieldName:    "rate",
			value:        float64(3.14),
			expectedType: "float",
			expectError:  false,
		},
		{
			name:         "invalid float",
			fieldName:    "rate",
			value:        "3.14",
			expectedType: "float",
			expectError:  true,
		},
		{
			name:         "valid string slice",
			fieldName:    "tags",
			value:        []string{"tag1", "tag2"},
			expectedType: "[]string",
			expectError:  false,
		},
		{
			name:         "valid any slice with strings",
			fieldName:    "tags",
			value:        []any{"tag1", "tag2"},
			expectedType: "[]string",
			expectError:  false,
		},
		{
			name:         "invalid any slice with non-string",
			fieldName:    "tags",
			value:        []any{"tag1", 123},
			expectedType: "[]string",
			expectError:  true,
		},
		{
			name:         "invalid slice type",
			fieldName:    "tags",
			value:        []int{1, 2, 3},
			expectedType: "[]string",
			expectError:  true,
		},
		{
			name:         "invalid slice - wrong type",
			fieldName:    "tags",
			value:        "not a slice",
			expectedType: "[]string",
			expectError:  true,
		},
		{
			name:         "valid map string to string",
			fieldName:    "labels",
			value:        map[string]string{"key": "value"},
			expectedType: "map[string]string",
			expectError:  false,
		},
		{
			name:         "valid map string to any with string values",
			fieldName:    "labels",
			value:        map[string]any{"key": "value"},
			expectedType: "map[string]string",
			expectError:  false,
		},
		{
			name:         "invalid map string to any with non-string value",
			fieldName:    "labels",
			value:        map[string]any{"key": 123},
			expectedType: "map[string]string",
			expectError:  true,
		},
		{
			name:         "valid map any to any with string keys and values",
			fieldName:    "labels",
			value:        map[any]any{"key": "value"},
			expectedType: "map[string]string",
			expectError:  false,
		},
		{
			name:         "invalid map any to any with non-string key",
			fieldName:    "labels",
			value:        map[any]any{123: "value"},
			expectedType: "map[string]string",
			expectError:  true,
		},
		{
			name:         "invalid map any to any with non-string value",
			fieldName:    "labels",
			value:        map[any]any{"key": 123},
			expectedType: "map[string]string",
			expectError:  true,
		},
		{
			name:         "invalid map type",
			fieldName:    "labels",
			value:        []string{"not", "a", "map"},
			expectedType: "map[string]string",
			expectError:  true,
		},
		{
			name:         "unknown type - no validation",
			fieldName:    "custom",
			value:        "anything",
			expectedType: "custom",
			expectError:  false,
		},
		{
			name:         "duration type not validated",
			fieldName:    "timeout",
			value:        "10s",
			expectedType: "duration",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFieldType(tt.fieldName, tt.value, tt.expectedType)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateFieldType_ErrorMessages(t *testing.T) {
	tests := []struct {
		name         string
		fieldName    string
		value        any
		expectedType string
		errorSubstr  string
	}{
		{
			name:         "string type error message",
			fieldName:    "name",
			value:        123,
			expectedType: "string",
			errorSubstr:  "must be a string",
		},
		{
			name:         "bool type error message",
			fieldName:    "enabled",
			value:        "yes",
			expectedType: "bool",
			errorSubstr:  "must be a boolean",
		},
		{
			name:         "int type error message",
			fieldName:    "count",
			value:        "42",
			expectedType: "int",
			errorSubstr:  "must be an integer",
		},
		{
			name:         "float type error message",
			fieldName:    "rate",
			value:        "3.14",
			expectedType: "float",
			errorSubstr:  "must be a float",
		},
		{
			name:         "string slice type error message",
			fieldName:    "tags",
			value:        123,
			expectedType: "[]string",
			errorSubstr:  "must be a string array",
		},
		{
			name:         "string slice element error message",
			fieldName:    "tags",
			value:        []any{"tag1", 123},
			expectedType: "[]string",
			errorSubstr:  "element at index 1 must be a string",
		},
		{
			name:         "map type error message",
			fieldName:    "labels",
			value:        "not a map",
			expectedType: "map[string]string",
			errorSubstr:  "must be a map[string]string",
		},
		{
			name:         "map key error message",
			fieldName:    "labels",
			value:        map[any]any{123: "value"},
			expectedType: "map[string]string",
			errorSubstr:  "key must be a string",
		},
		{
			name:         "map value error message",
			fieldName:    "labels",
			value:        map[string]any{"key": 123},
			expectedType: "map[string]string",
			errorSubstr:  "value for key 'key' must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFieldType(tt.fieldName, tt.value, tt.expectedType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorSubstr)
		})
	}
}
