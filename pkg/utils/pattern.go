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

// Package utils provides common utility functions for attestors.
package utils

import (
	"errors"
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
)

var (
	ErrInvalidGlobPattern = errors.New("invalid glob pattern")
)

// ValidateGlobPattern validates a single glob pattern by attempting to match it
// against a test path. Returns the pattern unchanged if valid, or an error if invalid.
func ValidateGlobPattern(pattern string) (string, error) {
	ok := doublestar.ValidatePattern(pattern)
	if !ok {
		return "", ErrInvalidGlobPattern
	}
	return pattern, nil
}

// ValidateGlobPatterns validates multiple glob patterns and returns an error if any pattern is invalid.
func ValidateGlobPatterns(patterns []string, patternType string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if _, err := ValidateGlobPattern(pattern); err != nil {
			return fmt.Errorf("invalid %s pattern '%s': %w", patternType, pattern, err)
		}
	}
	return nil
}

// MatchesAny checks if an item matches any candidate in a list using a custom matcher function.
func MatchesAny[T any](item T, candidates []T, matcher func(candidate T, item T) (bool, error)) (bool, error) {
	for _, candidate := range candidates {
		matched, err := matcher(candidate, item)
		if err != nil {
			return false, err
		}

		if matched {
			return true, nil
		}
	}

	return false, nil
}

// MatchesAnyPattern checks if a path matches any glob pattern in the provided list.
func MatchesAnyPattern(path string, patterns []string) (bool, error) {
	return MatchesAny(path, patterns, func(pattern, path string) (bool, error) {
		matched, err := doublestar.Match(pattern, path)
		if err != nil {
			return false, fmt.Errorf("pattern matching error for pattern '%s': %w", pattern, err)
		}
		return matched, nil
	})
}
