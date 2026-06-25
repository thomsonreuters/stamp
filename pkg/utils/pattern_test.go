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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateGlobPattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{
			name:        "valid_wildcard",
			pattern:     "*.txt",
			expectError: false,
		},
		{
			name:        "valid_recursive_wildcard",
			pattern:     "**/*.go",
			expectError: false,
		},
		{
			name:        "valid_directory_pattern",
			pattern:     "src/**/test",
			expectError: false,
		},
		{
			name:        "empty_pattern",
			pattern:     "",
			expectError: false,
		},
		{
			name:        "invalid_pattern_unclosed_bracket",
			pattern:     "[abc",
			expectError: true,
		},
		{
			name:        "invalid_pattern_unclosed_brace",
			pattern:     "{a,b",
			expectError: true,
		},
		{
			name:        "valid_complex_pattern",
			pattern:     "**/node_modules/**/*.{js,ts}",
			expectError: false,
		},
		{
			name:        "valid_negation",
			pattern:     "!test",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateGlobPattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.pattern, result)
			}
		})
	}
}

func TestValidateGlobPatterns(t *testing.T) {
	tests := []struct {
		name        string
		patterns    []string
		patternType string
		expectError bool
	}{
		{
			name:        "all_valid_patterns",
			patterns:    []string{"*.txt", "**/*.go", "src/**/test"},
			patternType: "include",
			expectError: false,
		},
		{
			name:        "empty_patterns",
			patterns:    []string{},
			patternType: "exclude",
			expectError: false,
		},
		{
			name:        "patterns_with_empty_string",
			patterns:    []string{"*.txt", "", "*.go"},
			patternType: "include",
			expectError: false,
		},
		{
			name:        "one_invalid_pattern",
			patterns:    []string{"*.txt", "[abc", "*.go"},
			patternType: "exclude",
			expectError: true,
		},
		{
			name:        "all_invalid_patterns",
			patterns:    []string{"[abc", "{a,b"},
			patternType: "include",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGlobPatterns(tt.patterns, tt.patternType)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.patternType)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMatchesAny(t *testing.T) {
	tests := []struct {
		name        string
		item        string
		candidates  []string
		expected    bool
		expectError bool
	}{
		{
			name:        "prefix_match_first",
			item:        "hello world",
			candidates:  []string{"hello", "hi", "hey"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "prefix_match_last",
			item:        "greetings",
			candidates:  []string{"hello", "hi", "greet"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "no_match",
			item:        "goodbye",
			candidates:  []string{"hello", "hi", "hey"},
			expected:    false,
			expectError: false,
		},
		{
			name:        "empty_candidates",
			item:        "test",
			candidates:  []string{},
			expected:    false,
			expectError: false,
		},
		{
			name:        "exact_match",
			item:        "exact",
			candidates:  []string{"not", "exact", "match"},
			expected:    true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Custom matcher: checks if item starts with candidate
			matcher := func(prefix, text string) (bool, error) {
				if prefix == "exact" && text == "exact" {
					return true, nil // exact match case
				}
				// Check if text starts with prefix
				if len(text) >= len(prefix) && text[:len(prefix)] == prefix {
					return true, nil
				}
				return false, nil
			}

			matched, err := MatchesAny(tt.item, tt.candidates, matcher)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, matched)
			}
		})
	}
}

func TestMatchesAny_WithIntegers(t *testing.T) {
	// Test with integers to show generic capability
	tests := []struct {
		name       string
		item       int
		candidates []int
		expected   bool
	}{
		{
			name:       "divisible_match",
			item:       10,
			candidates: []int{2, 3, 5},
			expected:   true, // 10 is divisible by 2 and 5
		},
		{
			name:       "no_divisible_match",
			item:       7,
			candidates: []int{2, 3, 5},
			expected:   false, // 7 is not divisible by 2, 3, or 5
		},
		{
			name:       "exact_match",
			item:       42,
			candidates: []int{10, 42, 100},
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Matcher: checks if item is divisible by candidate
			matcher := func(divisor, num int) (bool, error) {
				if num%divisor == 0 {
					return true, nil
				}
				return false, nil
			}

			matched, err := MatchesAny(tt.item, tt.candidates, matcher)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, matched)
		})
	}
}

func TestMatchesAny_WithError(t *testing.T) {
	// Test error propagation
	matcher := func(pattern, text string) (bool, error) {
		if pattern == "error" {
			return false, errors.New("intentional error")
		}
		return pattern == text, nil
	}

	matched, err := MatchesAny("test", []string{"ok", "error", "test"}, matcher)

	require.Error(t, err)
	assert.False(t, matched)
	assert.Contains(t, err.Error(), "intentional error")
}

func TestMatchesAnyPattern(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		patterns    []string
		expected    bool
		expectError bool
	}{
		{
			name:        "exact_match",
			path:        "test.txt",
			patterns:    []string{"test.txt"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "wildcard_match",
			path:        "test.txt",
			patterns:    []string{"*.txt"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "recursive_wildcard_match",
			path:        "dir/subdir/test.txt",
			patterns:    []string{"**/test.txt"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "no_match",
			path:        "test.txt",
			patterns:    []string{"*.go"},
			expected:    false,
			expectError: false,
		},
		{
			name:        "empty_patterns",
			path:        "test.txt",
			patterns:    []string{},
			expected:    false,
			expectError: false,
		},
		{
			name:        "multiple_patterns_first_matches",
			path:        "test.txt",
			patterns:    []string{"*.txt", "*.go", "*.md"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "multiple_patterns_last_matches",
			path:        "test.go",
			patterns:    []string{"*.txt", "*.md", "*.go"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "complex_recursive_pattern",
			path:        "src/pkg/utils/helper.go",
			patterns:    []string{"**/utils/**/*.go"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "brace_expansion_match",
			path:        "test.js",
			patterns:    []string{"*.{js,ts,tsx}"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "nested_directory_match",
			path:        "node_modules/package/index.js",
			patterns:    []string{"**/node_modules/**"},
			expected:    true,
			expectError: false,
		},
		{
			name:        "invalid_pattern_returns_error",
			path:        "test.txt",
			patterns:    []string{"[abc"},
			expected:    false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := MatchesAnyPattern(tt.path, tt.patterns)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, matched)
			}
		})
	}
}

// Benchmarks

func BenchmarkValidateGlobPattern(b *testing.B) {
	patterns := []string{
		"*.txt",
		"**/*.go",
		"src/**/test/**/*.{js,ts}",
		"**/node_modules/**",
	}

	for _, pattern := range patterns {
		b.Run(pattern, func(b *testing.B) {
			for range b.N {
				_, _ = ValidateGlobPattern(pattern)
			}
		})
	}
}

func BenchmarkValidateGlobPatterns(b *testing.B) {
	patterns := []string{
		"*.txt",
		"**/*.go",
		"src/**/test",
		"**/node_modules/**/*.js",
		"dist/**/*.{js,ts,tsx}",
	}

	for b.Loop() {
		_ = ValidateGlobPatterns(patterns, "test")
	}
}

func BenchmarkMatchesAny(b *testing.B) {
	// Benchmark generic MatchesAny with string prefix matching
	prefixes := []string{"hello", "world", "test", "bench", "mark"}

	tests := []struct {
		name string
		text string
	}{
		{"match_first", "hello there"},
		{"match_middle", "testing 123"},
		{"match_last", "marking done"},
		{"no_match", "goodbye world"},
	}

	matcher := func(prefix, text string) (bool, error) {
		return len(text) >= len(prefix) && text[:len(prefix)] == prefix, nil
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for range b.N {
				_, _ = MatchesAny(tt.text, prefixes, matcher)
			}
		})
	}
}

func BenchmarkMatchesAnyPattern(b *testing.B) {
	patterns := []string{
		"*.txt",
		"*.go",
		"**/node_modules/**",
		"**/dist/**/*.js",
		"src/**/*.go",
	}

	tests := []struct {
		name string
		path string
	}{
		{"short_path", "test.txt"},
		{"nested_path", "src/pkg/utils/helper.go"},
		{"deep_nested_path", "project/src/internal/pkg/utils/testdata/file.txt"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for range b.N {
				_, _ = MatchesAnyPattern(tt.path, patterns)
			}
		})
	}
}
