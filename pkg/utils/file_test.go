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
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "unix_absolute_path",
			input:    "/home/user/project/file.go",
			expected: "/home/user/project/file.go",
		},
		{
			name:     "unix_relative_path",
			input:    "project/file.go",
			expected: "project/file.go",
		},
		{
			name:     "unix_path_with_dot_dot",
			input:    "/home/user/../project/file.go",
			expected: "/home/project/file.go",
		},
		{
			name:     "unix_path_with_dot",
			input:    "./project/./file.go",
			expected: "project/file.go",
		},
		{
			name:     "current_directory",
			input:    ".",
			expected: ".",
		},
		{
			name:     "parent_directory",
			input:    "..",
			expected: "..",
		},
		{
			name:     "empty_path",
			input:    "",
			expected: ".",
		},
		{
			name:     "trailing_slash_unix",
			input:    "/home/user/project/",
			expected: "/home/user/project",
		},
		{
			name:     "multiple_dots",
			input:    "../../file.go",
			expected: "../../file.go",
		},
		{
			name:     "mixed_unix_separators",
			input:    "/home//user///project/file.go",
			expected: "/home/user/project/file.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.input)
			assert.Equal(t, tt.expected, result, "NormalizePath(%q)", tt.input)
		})
	}
}

func TestNormalizePath_Platform(t *testing.T) {
	// Platform-specific tests that only work on their respective platforms
	if runtime.GOOS == "windows" {
		tests := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "windows_backslash_path",
				input:    "C:\\Users\\user\\project\\file.go",
				expected: "C:/Users/user/project/file.go",
			},
			{
				name:     "windows_path_with_dot_dot",
				input:    "C:\\Users\\user\\..\\project\\file.go",
				expected: "C:/Users/project/file.go",
			},
			{
				name:     "mixed_separators",
				input:    "C:\\Users/user\\project/file.go",
				expected: "C:/Users/user/project/file.go",
			},
			{
				name:     "trailing_slash_windows",
				input:    "C:\\Users\\user\\",
				expected: "C:/Users/user",
			},
			{
				name:     "windows_drive_letter_lowercase",
				input:    "c:\\project\\file.go",
				expected: "c:/project/file.go",
			},
			{
				name:     "windows_unc_path",
				input:    "\\\\server\\share\\file.go",
				expected: "//server/share/file.go",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := NormalizePath(tt.input)
				assert.Equal(t, tt.expected, result, "NormalizePath(%q)", tt.input)
			})
		}
	}
}

func TestIsSpecialDirectory(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "current_directory",
			input:    ".",
			expected: true,
		},
		{
			name:     "parent_directory",
			input:    "..",
			expected: true,
		},
		{
			name:     "regular_directory",
			input:    "foo",
			expected: false,
		},
		{
			name:     "hidden_directory",
			input:    ".git",
			expected: false,
		},
		{
			name:     "empty_string",
			input:    "",
			expected: false,
		},
		{
			name:     "dot_in_name",
			input:    "foo.bar",
			expected: false,
		},
		{
			name:     "multiple_dots",
			input:    "...",
			expected: false,
		},
		{
			name:     "space",
			input:    " ",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSpecialDirectory(tt.input)
			assert.Equal(t, tt.expected, result, "IsSpecialDirectory(%q)", tt.input)
		})
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	paths := []string{
		"/home/user/project/file.go",
		"C:\\Users\\user\\project\\file.go",
		"./project/../file.go",
		"../../project/./file.go",
	}

	for b.Loop() {
		for _, path := range paths {
			_ = NormalizePath(path)
		}
	}
}

func BenchmarkIsSpecialDirectory(b *testing.B) {
	names := []string{".", "..", "foo", ".git", "bar"}

	for b.Loop() {
		for _, name := range names {
			_ = IsSpecialDirectory(name)
		}
	}
}

// Size parsing tests

func TestParseSize(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  int64
		expectErr bool
	}{
		// Basic cases
		{name: "zero", input: "0", expected: 0},
		{name: "empty", input: "", expected: 0},
		{name: "whitespace", input: "  ", expected: 0},

		// Bytes
		{name: "bytes_explicit", input: "100B", expected: 100},
		{name: "bytes_raw", input: "1024", expected: 1024},
		{name: "bytes_lowercase", input: "500b", expected: 500},

		// Kilobytes
		{name: "kb_integer", input: "512KB", expected: 524288},
		{name: "kb_float", input: "1.5KB", expected: 1536},
		{name: "kb_lowercase", input: "2kb", expected: 2048},
		{name: "kb_with_spaces", input: "  10  KB  ", expected: 10240},

		// Megabytes
		{name: "mb_integer", input: "1MB", expected: 1048576},
		{name: "mb_float", input: "1.5MB", expected: 1572864},
		{name: "mb_large", input: "100MB", expected: 104857600},
		{name: "mb_lowercase", input: "5mb", expected: 5242880},

		// Gigabytes
		{name: "gb_integer", input: "1GB", expected: 1073741824},
		{name: "gb_float", input: "2.5GB", expected: 2684354560},
		{name: "gb_lowercase", input: "5gb", expected: 5368709120},

		// Terabytes
		{name: "tb_integer", input: "1TB", expected: 1099511627776},
		{name: "tb_float", input: "0.5TB", expected: 549755813888},

		// Petabytes
		{name: "pb_integer", input: "1PB", expected: 1125899906842624},

		// Scientific notation
		{name: "scientific_kb", input: "1e3KB", expected: 1024000},
		{name: "scientific_mb", input: "1.5e2MB", expected: 157286400},

		// Edge cases - valid
		{name: "very_small", input: "0.1KB", expected: 102},
		{name: "zero_point_zero", input: "0.0MB", expected: 0},

		// Error cases - negative
		{name: "negative_integer", input: "-100KB", expectErr: true},
		{name: "negative_float", input: "-1.5MB", expectErr: true},

		// Error cases - invalid format
		{name: "invalid_suffix", input: "100XB", expectErr: true},
		{name: "invalid_number", input: "abcKB", expectErr: true},
		{name: "double_suffix", input: "100KBMB", expectErr: true},
		{name: "no_number", input: "KB", expectErr: true},
		{name: "special_chars", input: "100@KB", expectErr: true},

		// Error cases - overflow
		{name: "overflow_pb", input: "10000PB", expectErr: true},
		{name: "overflow_large", input: "99999999999999999999999999", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSize(tt.input)

			if tt.expectErr {
				assert.Error(t, err, "Expected error for input: %s", tt.input)
				return
			}

			require.NoError(t, err, "Unexpected error for input: %s", tt.input)
			assert.Equal(t, tt.expected, result, "For input: %s", tt.input)
		})
	}
}

func TestParseSizeConstants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{"1KB", "1KB", KB},
		{"1MB", "1MB", MB},
		{"1GB", "1GB", GB},
		{"1TB", "1TB", TB},
		{"1PB", "1PB", PB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSize(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSizeCaseInsensitive(t *testing.T) {
	variations := []string{
		"1KB", "1Kb", "1kB", "1kb",
		"1MB", "1Mb", "1mB", "1mb",
		"1GB", "1Gb", "1gB", "1gb",
	}

	for _, input := range variations {
		t.Run(input, func(t *testing.T) {
			result, err := ParseSize(input)
			require.NoError(t, err)
			assert.Positive(t, result)
		})
	}
}

func TestParseSizeErrorMessages(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		errorContains string
	}{
		{
			name:          "negative",
			input:         "-100KB",
			errorContains: "cannot be negative",
		},
		{
			name:          "invalid_number",
			input:         "abcKB",
			errorContains: "invalid number",
		},
		{
			name:          "overflow",
			input:         "10000PB",
			errorContains: "overflow",
		},
		{
			name:          "invalid_suffix",
			input:         "100XB",
			errorContains: "invalid size format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSize(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSizeConstants(t *testing.T) {
	assert.Equal(t, int64(1024), KB)
	assert.Equal(t, int64(1048576), MB)
	assert.Equal(t, int64(1073741824), GB)
	assert.Equal(t, int64(1099511627776), TB)
	assert.Equal(t, int64(1125899906842624), PB)

	// Verify relationships
	assert.Equal(t, KB*1024, MB)
	assert.Equal(t, MB*1024, GB)
	assert.Equal(t, GB*1024, TB)
	assert.Equal(t, TB*1024, PB)
}

// Benchmark size parsing.
func BenchmarkParseSize(b *testing.B) {
	inputs := []string{"512KB", "1MB", "5GB", "1024", "1.5MB"}

	for _, input := range inputs {
		b.Run(input, func(b *testing.B) {
			for range b.N {
				_, _ = ParseSize(input)
			}
		})
	}
}
