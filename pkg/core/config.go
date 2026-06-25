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
	"fmt"
	"strings"
	"time"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// ConfigField describes a configuration field for an attestor.
type ConfigField struct {
	Name        string `json:"name"              yaml:"name"`
	Type        string `json:"type"              yaml:"type"`
	Default     any    `json:"default"           yaml:"default"`
	Required    bool   `json:"required"          yaml:"required"`
	Description string `json:"description"       yaml:"description"`
	Example     any    `json:"example,omitempty" yaml:"example,omitempty"`
}

// Config represents the configuration map for an attestor.
//
// It's a flexible key-value map that allows attestors to define their own
// configuration schema. Values can be of any type (string, bool, int, float,
// []string, map[string]string, etc.).
type Config map[string]any

// Validate checks the configuration against the provided schema, ensuring required fields exist and values have correct types.
func (c Config) Validate(schema []ConfigField) error {
	for _, field := range schema {
		if field.Required {
			if _, exists := c[field.Name]; !exists {
				v := pkgerrors.NewValidatorFor("config")
				v.AddError(field.Name, "required field is missing")
				return v
			}
		}

		if val, exists := c[field.Name]; exists {
			if err := validateFieldType(field.Name, val, field.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetString returns the string value for the given key, or the default value if not found or not a string.
func (c Config) GetString(key string, defaultValue string) string {
	if v, ok := c[key].(string); ok {
		return v
	}
	return defaultValue
}

// IsEmpty returns true if the key is missing or its string value is empty.
func (c Config) IsEmpty(key string) bool {
	return c.GetString(key, "") == ""
}

// GetBool returns the boolean value for the given key, or the default value if not found.
func (c Config) GetBool(key string, defaultValue bool) bool {
	if v, ok := c[key].(bool); ok {
		return v
	}
	if v, ok := c[key].(string); ok {
		return strings.ToLower(v) == "true"
	}
	return defaultValue
}

// GetInt returns the integer value for the given key, or the default value if not found.
func (c Config) GetInt(key string, defaultValue int) int {
	if v, ok := c[key].(int); ok {
		return v
	}
	if v, ok := c[key].(float64); ok {
		return int(v)
	}
	if v, ok := c[key].(int64); ok {
		return int(v)
	}
	if v, ok := c[key].(int32); ok {
		return int(v)
	}
	return defaultValue
}

// GetInt64 returns the int64 value for the given key, or the default value if not found.
func (c Config) GetInt64(key string, defaultValue int64) int64 {
	if v, ok := c[key].(int64); ok {
		return v
	}
	if v, ok := c[key].(int); ok {
		return int64(v)
	}
	if v, ok := c[key].(float64); ok {
		return int64(v)
	}
	if v, ok := c[key].(int32); ok {
		return int64(v)
	}
	return defaultValue
}

// GetDuration returns the time.Duration value for the given key, or the default value if not found.
func (c Config) GetDuration(key string, defaultValue time.Duration) time.Duration {
	if v, ok := c[key].(time.Duration); ok {
		return v
	}
	if v, ok := c[key].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}

// GetStringSlice returns the string slice value for the given key, or the default value if not found.
func (c Config) GetStringSlice(key string, defaultValue ...[]string) []string {
	if v, ok := c[key].([]string); ok {
		return v
	}

	if v, ok := c[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, isString := item.(string); isString {
				result = append(result, s)
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	if v, ok := c[key].(string); ok && v != "" {
		return utils.SplitAndTrim(v, ",")
	}

	if len(defaultValue) > 0 && defaultValue[0] != nil {
		return defaultValue[0]
	}

	return []string{}
}

// GetMap returns the map[string]string value for the given key, or nil if not found.
func (c Config) GetMap(key string) map[string]string {
	if v, ok := c[key].(map[string]string); ok {
		return v
	}

	if v, ok := c[key].(map[string]any); ok {
		result := make(map[string]string)
		for k, val := range v {
			result[k] = fmt.Sprintf("%v", val)
		}
		return result
	}

	const keyValueParts = 2

	if v, ok := c[key].(string); ok && v != "" {
		result := make(map[string]string)
		pairs := utils.SplitAndTrim(v, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, "=", keyValueParts)
			if len(parts) == keyValueParts {
				result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	return nil
}

// validateFieldType checks that a configuration value matches the expected type.
//
//nolint:gocognit // validation requires comprehensive type checking for all supported types
func validateFieldType(name string, value any, expectedType string) error {
	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return pkgerrors.NewWithContext("config", "validate_type",
				fmt.Sprintf("field '%s' must be a string, got %T", name, value))
		}
	case "bool":
		if _, ok := value.(bool); !ok {
			return pkgerrors.NewWithContext("config", "validate_type",
				fmt.Sprintf("field '%s' must be a boolean, got %T", name, value))
		}
	case "int":
		switch value.(type) {
		case int, int32, int64, float64:
			// Valid integer types (float64 from JSON/YAML unmarshaling)
		default:
			return pkgerrors.NewWithContext("config", "validate_type",
				fmt.Sprintf("field '%s' must be an integer, got %T", name, value))
		}
	case "float":
		switch value.(type) {
		case float32, float64:
			// Valid float types
		default:
			return pkgerrors.NewWithContext("config", "validate_type",
				fmt.Sprintf("field '%s' must be a float, got %T", name, value))
		}
	case "[]string":
		switch v := value.(type) {
		case []string:
			// Already the right type
		case []any:
			// Check all elements are strings
			for i, elem := range v {
				if _, ok := elem.(string); !ok {
					return pkgerrors.NewWithContext("config", "validate_type",
						fmt.Sprintf("field '%s' element at index %d must be a string, got %T",
							name, i, elem))
				}
			}
		default:
			return pkgerrors.NewWithContext("config", "validate_type",
				fmt.Sprintf("field '%s' must be a string array, got %T", name, value))
		}
	case "map[string]string":
		switch v := value.(type) {
		case map[string]string:
			// Direct type match
		case map[string]any:
			// Validate all values are strings (common from JSON/YAML parsing)
			for k, val := range v {
				if _, ok := val.(string); !ok {
					return pkgerrors.NewWithContext("config", "validate_type",
						fmt.Sprintf("field '%s' value for key '%s' must be a string, got %T",
							name, k, val))
				}
			}
		case map[any]any:
			// Validate keys and values are strings (common from YAML parsing)
			for k, val := range v {
				if _, ok := k.(string); !ok {
					return pkgerrors.NewWithContext("config", "validate_type",
						fmt.Sprintf("field '%s' key must be a string, got %T", name, k))
				}
				if _, ok := val.(string); !ok {
					return pkgerrors.NewWithContext("config", "validate_type",
						fmt.Sprintf("field '%s' value must be a string, got %T", name, val))
				}
			}
		default:
			return pkgerrors.NewWithContext("config", "validate_type",
				fmt.Sprintf("field '%s' must be a map[string]string, got %T", name, value))
		}
	}
	return nil
}
