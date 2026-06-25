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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// RedactionPattern defines a regex pattern and its replacement value.
type RedactionPattern struct {
	Pattern *regexp.Regexp
	Replace string
}

// RedactionResult contains the sanitized JSON and metadata about the redaction.
type RedactionResult struct {
	Sanitized      json.RawMessage
	RedactionCount int
}

// SanitizeJSON redacts sensitive information from JSON data while preserving JSON structure.
// It parses the JSON, applies regex patterns only to string values (not keys or structure),
// and re-marshals to guarantee valid JSON output.
//
// Example:
//
//	patterns := []RedactionPattern{
//	    {Pattern: regexp.MustCompile(`\S+@\S+`), Replace: "[REDACTED_EMAIL]"},
//	    {Pattern: regexp.MustCompile(`ghp_\w+`), Replace: "[REDACTED_TOKEN]"},
//	}
//	result, err := SanitizeJSON(jsonData, patterns)
func SanitizeJSON(data []byte, patterns []RedactionPattern) (*RedactionResult, error) {
	// Parse JSON into generic structure
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Redact values recursively
	redactionCount := redactJSONValues(parsed, patterns)

	// Marshal back to JSON - guaranteed valid!
	sanitized, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sanitized JSON: %w", err)
	}

	return &RedactionResult{
		Sanitized:      json.RawMessage(sanitized),
		RedactionCount: redactionCount,
	}, nil
}

// redactJSONValues recursively traverses JSON structure and redacts only string values.
// Keys, numbers, booleans, and null values are preserved.
// Returns the total number of redactions applied.
func redactJSONValues(data any, patterns []RedactionPattern) int {
	redactionCount := 0

	switch v := data.(type) {
	case map[string]any:
		// Process object: redact string values, recurse into nested structures
		for key, value := range v {
			if str, ok := value.(string); ok {
				// Redact string values
				redacted, count := applyRedactionPatterns(str, patterns)
				v[key] = redacted
				redactionCount += count
			} else if value != nil {
				// Recurse into nested objects/arrays
				redactionCount += redactJSONValues(value, patterns)
			}
		}

	case []any:
		// Process array: redact string elements, recurse into nested structures
		for i, value := range v {
			if str, ok := value.(string); ok {
				// Redact string values
				redacted, count := applyRedactionPatterns(str, patterns)
				v[i] = redacted
				redactionCount += count
			} else if value != nil {
				// Recurse into nested objects/arrays
				redactionCount += redactJSONValues(value, patterns)
			}
		}
	}

	return redactionCount
}

// applyRedactionPatterns applies all redaction patterns to a string value.
// Returns the redacted string and the number of redactions applied.
func applyRedactionPatterns(value string, patterns []RedactionPattern) (string, int) {
	redactionCount := 0

	for _, p := range patterns {
		matches := p.Pattern.FindAllString(value, -1)
		if len(matches) > 0 {
			value = p.Pattern.ReplaceAllString(value, p.Replace)
			redactionCount += len(matches)
		}
	}

	return value, redactionCount
}

// ReadJSONFile reads a JSON file and unmarshals it into a map.
func ReadJSONFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading JSON file %q: %w", path, err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing JSON file %q: %w", path, err)
	}
	return result, nil
}
