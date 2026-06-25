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

package config

import (
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// ParseSetFlags parses --set flags into attestor configuration.
// Supports field type detection via ConfigSchema for proper type handling.
func ParseSetFlags(setFlags []string, attestorID string) (core.Config, error) {
	config := make(core.Config)

	// Get field types from attestor schema using ID
	var fieldTypes map[string]string
	if attestorID != "" {
		if attestor, err := core.GetAttestorByID(attestorID, logger.NewNoop()); err == nil {
			fieldTypes = make(map[string]string)
			for _, field := range attestor.ConfigSchema() {
				fieldTypes[field.Name] = field.Type
			}
		}
	}

	// Track map fields that accumulate values
	mapFields := make(map[string]map[string]string)

	for _, flag := range setFlags {
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) != 2 {
			return nil, pkgerrors.NewWithContext("config", "parse_set_flags", fmt.Sprintf("invalid --set format '%s': expected key=value", flag))
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, pkgerrors.NewWithContext("config", "parse_set_flags", fmt.Sprintf("invalid --set format '%s': key cannot be empty", flag))
		}

		// Handle map[string]string fields
		//nolint:gocritic,nestif // if-else chain is clearer than switch for dynamic type checking
		if fieldTypes != nil &&
			fieldTypes[key] == "map[string]string" {
			if mapFields[key] == nil {
				mapFields[key] = make(map[string]string)
			}
			entries := ParseMapEntries(value)
			maps.Copy(mapFields[key], entries)
		} else if fieldTypes != nil && fieldTypes[key] == "[]string" {
			// Handle []string fields - ensure single values are wrapped in array
			parsedValue := ParseValue(value)
			// If ParseValue returned a string (no comma), wrap it in an array
			if strValue, ok := parsedValue.(string); ok {
				config[key] = []string{strValue}
			} else {
				// Already an array from comma-separated parsing
				config[key] = parsedValue
			}
		} else {
			config[key] = ParseValue(value)
		}
	}

	// Add accumulated map fields
	for key, mapValue := range mapFields {
		config[key] = mapValue
	}

	return config, nil
}

// ParseValue parses a string value into its appropriate type.
// Priority: boolean -> number -> comma-separated list -> string.
func ParseValue(value string) any {
	// Boolean
	if value == "true" {
		return true
	}
	if value == "false" {
		return false
	}

	// Don't parse numbers if value contains commas
	if !strings.Contains(value, ",") {
		// Integer
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			if intVal >= int64(^uint(0)>>1)*-1 && intVal <= int64(^uint(0)>>1) {
				return int(intVal)
			}
			return intVal
		}

		// Float
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}

	// String slice (comma-separated)
	if strings.Contains(value, ",") {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}

	// String
	return value
}

// ParseMapEntries parses a string containing map entries.
// Supports formats: KEY=VALUE or KEY1=VALUE1,KEY2=VALUE2.
func ParseMapEntries(value string) map[string]string {
	result := make(map[string]string)

	if value == "" {
		return result
	}

	entries := strings.SplitSeq(value, ",")
	for entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// Remove quotes if present
			val = strings.Trim(val, "\"'")

			result[key] = val
		} else {
			// Single value without '=', use as key with empty value
			result[entry] = ""
		}
	}

	return result
}
