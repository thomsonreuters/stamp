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
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsAbsoluteURL_ValidAbsoluteURLs(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "HTTP absolute URL",
			url:      "http://example.com",
			expected: true,
		},
		{
			name:     "HTTPS absolute URL",
			url:      "https://example.com",
			expected: true,
		},
		{
			name:     "HTTP absolute URL with path",
			url:      "http://example.com/path",
			expected: true,
		},
		{
			name:     "HTTPS absolute URL with path and query",
			url:      "https://example.com/path?key=value",
			expected: true,
		},
		{
			name:     "HTTP absolute URL with port",
			url:      "http://example.com:8080",
			expected: true,
		},
		{
			name:     "HTTPS absolute URL with port and path",
			url:      "https://example.com:443/path",
			expected: true,
		},
		{
			name:     "FTP absolute URL",
			url:      "ftp://ftp.example.com",
			expected: true,
		},
		{
			name:     "Absolute URL with subdomain",
			url:      "https://api.example.com",
			expected: true,
		},
		{
			name:     "Absolute URL with IP address",
			url:      "http://192.168.1.1",
			expected: true,
		},
		{
			name:     "Absolute URL with localhost",
			url:      "http://localhost:8080",
			expected: true,
		},
		{
			name:     "Absolute URL with fragment",
			url:      "https://example.com/path#section",
			expected: true,
		},
		{
			name:     "File scheme with host",
			url:      "file://localhost/path",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAbsoluteURL(tt.url)
			assert.Equal(t, tt.expected, result,
				"IsAbsoluteURL(%q) = %v, want %v", tt.url, result, tt.expected)
		})
	}
}

func TestIsAbsoluteURL_RelativeURLs(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "Relative path",
			url:      "/path/to/resource",
			expected: false,
		},
		{
			name:     "Relative path without leading slash",
			url:      "path/to/resource",
			expected: false,
		},
		{
			name:     "Just filename",
			url:      "file.txt",
			expected: false,
		},
		{
			name:     "Current directory",
			url:      "./file.txt",
			expected: false,
		},
		{
			name:     "Parent directory",
			url:      "../file.txt",
			expected: false,
		},
		{
			name:     "Root path",
			url:      "/",
			expected: false,
		},
		{
			name:     "Query string only",
			url:      "?key=value",
			expected: false,
		},
		{
			name:     "Fragment only",
			url:      "#section",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAbsoluteURL(tt.url)
			assert.Equal(t, tt.expected, result,
				"IsAbsoluteURL(%q) = %v, want %v", tt.url, result, tt.expected)
		})
	}
}

func TestIsAbsoluteURL_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "Scheme only with colon",
			url:      "http:",
			expected: false,
		},
		{
			name:     "Scheme with slashes but no host",
			url:      "http://",
			expected: false,
		},
		{
			name:     "Scheme with path but no host",
			url:      "http:///path",
			expected: false,
		},
		{
			name:     "Empty string",
			url:      "",
			expected: false,
		},
		{
			name:     "Space only",
			url:      " ",
			expected: false,
		},
		{
			name:     "Just colon",
			url:      ":",
			expected: false,
		},
		{
			name:     "Double slashes only",
			url:      "//",
			expected: false,
		},
		{
			name:     "Scheme-relative URL",
			url:      "//example.com",
			expected: false,
		},
		{
			name:     "Host without scheme",
			url:      "example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAbsoluteURL(tt.url)
			assert.Equal(t, tt.expected, result,
				"IsAbsoluteURL(%q) = %v, want %v", tt.url, result, tt.expected)
		})
	}
}

func TestIsAbsoluteURL_InvalidURLs(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "Invalid characters",
			url:      "http://[invalid",
			expected: false,
		},
		{
			name:     "Malformed URL with spaces",
			url:      "http://example .com",
			expected: false,
		},
		{
			name:     "Invalid port",
			url:      "http://[::1]:namedport",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAbsoluteURL(tt.url)
			assert.Equal(t, tt.expected, result,
				"IsAbsoluteURL(%q) = %v, want %v", tt.url, result, tt.expected)
		})
	}
}

func TestIsAbsoluteURL_SpecialSchemes(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "Mailto scheme",
			url:      "mailto:user@example.com",
			expected: false,
		},
		{
			name:     "Data URI",
			url:      "data:text/plain;base64,SGVsbG8=",
			expected: false,
		},
		{
			name:     "Tel scheme",
			url:      "tel:+1234567890",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAbsoluteURL(tt.url)
			assert.Equal(t, tt.expected, result,
				"IsAbsoluteURL(%q) = %v, want %v", tt.url, result, tt.expected)
		})
	}
}

func TestSplitAndTrim_BasicUsage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "Simple comma-separated values",
			input:    "go, rust, python",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "No whitespace",
			input:    "go,rust,python",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Extra whitespace",
			input:    "go  ,  rust  ,  python  ",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Mixed whitespace",
			input:    "go,\trust,\npython",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Single value",
			input:    "go",
			sep:      ",",
			expected: []string{"go"},
		},
		{
			name:     "Single value with whitespace",
			input:    "  go  ",
			sep:      ",",
			expected: []string{"go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTrim_EmptyCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "Empty string",
			input:    "",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "Only separator",
			input:    ",",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "Multiple separators",
			input:    ",,,",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "Whitespace only",
			input:    "   ",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "Separator with whitespace",
			input:    " , , , ",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "Mixed empty and valid",
			input:    "go,,rust,,python",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Trailing separator",
			input:    "go,rust,python,",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Leading separator",
			input:    ",go,rust,python",
			sep:      ",",
			expected: []string{"go", "rust", "python"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTrim_DifferentSeparators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "Pipe separator",
			input:    "go | rust | python",
			sep:      "|",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Semicolon separator",
			input:    "go; rust; python",
			sep:      ";",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Space separator",
			input:    "go rust python",
			sep:      " ",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Newline separator",
			input:    "go\nrust\npython",
			sep:      "\n",
			expected: []string{"go", "rust", "python"},
		},
		{
			name:     "Multi-character separator",
			input:    "go :: rust :: python",
			sep:      "::",
			expected: []string{"go", "rust", "python"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTrim_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "Hash algorithms",
			input:    "sha256, sha512, md5",
			sep:      ",",
			expected: []string{"sha256", "sha512", "md5"},
		},
		{
			name:     "File extensions",
			input:    ".go , .rs , .py , .js ",
			sep:      ",",
			expected: []string{".go", ".rs", ".py", ".js"},
		},
		{
			name:     "Environment tags",
			input:    "prod,staging,dev",
			sep:      ",",
			expected: []string{"prod", "staging", "dev"},
		},
		{
			name:     "URL list",
			input:    "https://api.example.com, https://api2.example.com",
			sep:      ",",
			expected: []string{"https://api.example.com", "https://api2.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// SplitAndTransform Tests
// ============================================================================

func TestSplitAndTransform_StringToInt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []int
	}{
		{
			name:     "Simple integers",
			input:    "1, 2, 3",
			sep:      ",",
			expected: []int{1, 2, 3},
		},
		{
			name:     "Integers with whitespace",
			input:    "  10  ,  20  ,  30  ",
			sep:      ",",
			expected: []int{10, 20, 30},
		},
		{
			name:     "Mixed valid and invalid",
			input:    "1, abc, 3, , 5",
			sep:      ",",
			expected: []int{1, 3, 5},
		},
		{
			name:     "Negative integers",
			input:    "-1, -2, -3",
			sep:      ",",
			expected: []int{-1, -2, -3},
		},
		{
			name:     "Empty string",
			input:    "",
			sep:      ",",
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTransform(tt.input, tt.sep, func(s string) (int, bool) {
				val, err := strconv.Atoi(strings.TrimSpace(s))
				return val, err == nil
			})
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTransform_StringToFloat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []float64
	}{
		{
			name:     "Simple floats",
			input:    "1.5, 2.7, 3.9",
			sep:      ",",
			expected: []float64{1.5, 2.7, 3.9},
		},
		{
			name:     "Scientific notation",
			input:    "1.5e2, 2.7e-1, 3.9e3",
			sep:      ",",
			expected: []float64{150, 0.27, 3900},
		},
		{
			name:     "Mixed valid and invalid",
			input:    "1.5, abc, 3.9",
			sep:      ",",
			expected: []float64{1.5, 3.9},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTransform(tt.input, tt.sep, func(s string) (float64, bool) {
				val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
				return val, err == nil
			})
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTransform_StringToBool(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []bool
	}{
		{
			name:     "Simple booleans",
			input:    "true, false, true",
			sep:      ",",
			expected: []bool{true, false, true},
		},
		{
			name:     "Case variations",
			input:    "True, FALSE, 1, 0",
			sep:      ",",
			expected: []bool{true, false, true, false},
		},
		{
			name:     "Mixed valid and invalid",
			input:    "true, abc, false",
			sep:      ",",
			expected: []bool{true, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTransform(tt.input, tt.sep, func(s string) (bool, bool) {
				val, err := strconv.ParseBool(strings.TrimSpace(s))
				return val, err == nil
			})
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTransform_CustomStruct(t *testing.T) {
	type Person struct {
		Name string
		Age  int
	}

	tests := []struct {
		name     string
		input    string
		sep      string
		expected []Person
	}{
		{
			name:  "Parse name:age pairs",
			input: "Alice:30, Bob:25, Charlie:35",
			sep:   ",",
			expected: []Person{
				{Name: "Alice", Age: 30},
				{Name: "Bob", Age: 25},
				{Name: "Charlie", Age: 35},
			},
		},
		{
			name:  "With invalid entries",
			input: "Alice:30, Invalid, Bob:25",
			sep:   ",",
			expected: []Person{
				{Name: "Alice", Age: 30},
				{Name: "Bob", Age: 25},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTransform(tt.input, tt.sep, func(s string) (Person, bool) {
				parts := strings.Split(strings.TrimSpace(s), ":")
				if len(parts) != 2 {
					return Person{}, false
				}
				age, err := strconv.Atoi(parts[1])
				if err != nil {
					return Person{}, false
				}
				return Person{Name: parts[0], Age: age}, true
			})
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTransform_URLTransform(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "Add HTTPS prefix",
			input:    "example.com, api.example.com, test.com",
			sep:      ",",
			expected: []string{"https://example.com", "https://api.example.com", "https://test.com"},
		},
		{
			name:     "Filter empty domains",
			input:    "example.com, , test.com, ",
			sep:      ",",
			expected: []string{"https://example.com", "https://test.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTransform(tt.input, tt.sep, func(s string) (string, bool) {
				trimmed := strings.TrimSpace(s)
				if trimmed == "" {
					return "", false
				}
				return "https://" + trimmed, true
			})
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTransform_UpperCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "Convert to uppercase",
			input:    "go, rust, python",
			sep:      ",",
			expected: []string{"GO", "RUST", "PYTHON"},
		},
		{
			name:     "Mixed case input",
			input:    "Go, RuSt, PyThOn",
			sep:      ",",
			expected: []string{"GO", "RUST", "PYTHON"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitAndTransform(tt.input, tt.sep, func(s string) (string, bool) {
				trimmed := strings.TrimSpace(s)
				if trimmed == "" {
					return "", false
				}
				return strings.ToUpper(trimmed), true
			})
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitAndTransform_EmptyString(t *testing.T) {
	result := SplitAndTransform("", ",", func(s string) (int, bool) {
		val, err := strconv.Atoi(strings.TrimSpace(s))
		return val, err == nil
	})
	assert.Empty(t, result)
	assert.Equal(t, []int{}, result)
}

func TestSplitAndTransform_AllInvalid(t *testing.T) {
	result := SplitAndTransform("abc, def, ghi", ",", func(s string) (int, bool) {
		val, err := strconv.Atoi(strings.TrimSpace(s))
		return val, err == nil
	})
	assert.Empty(t, result)
	assert.Equal(t, []int{}, result)
}

func TestParseMultilineResponse_UnixLineEndings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Simple Unix line endings",
			input:    "line1\nline2\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Single line",
			input:    "single line",
			expected: []string{"single line"},
		},
		{
			name:     "Trailing newline",
			input:    "line1\nline2\n",
			expected: []string{"line1", "line2"},
		},
		{
			name:     "Leading newline",
			input:    "\nline1\nline2",
			expected: []string{"line1", "line2"},
		},
		{
			name:     "Multiple consecutive newlines",
			input:    "line1\n\n\nline2",
			expected: []string{"line1", "line2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_WindowsLineEndings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Simple Windows line endings",
			input:    "line1\r\nline2\r\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Trailing Windows newline",
			input:    "line1\r\nline2\r\n",
			expected: []string{"line1", "line2"},
		},
		{
			name:     "Leading Windows newline",
			input:    "\r\nline1\r\nline2",
			expected: []string{"line1", "line2"},
		},
		{
			name:     "Multiple consecutive Windows newlines",
			input:    "line1\r\n\r\n\r\nline2",
			expected: []string{"line1", "line2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_MixedLineEndings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Mixed Unix and Windows",
			input:    "line1\nline2\r\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Mixed with consecutive different endings",
			input:    "line1\n\r\nline2\r\n\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Complex mixed endings",
			input:    "line1\r\n\nline2\n\r\nline3\r\nline4\n",
			expected: []string{"line1", "line2", "line3", "line4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_EmptyCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "Only newlines Unix",
			input:    "\n\n\n",
			expected: []string{},
		},
		{
			name:     "Only newlines Windows",
			input:    "\r\n\r\n\r\n",
			expected: []string{},
		},
		{
			name:     "Only whitespace",
			input:    "   \t   \n   \t   ",
			expected: []string{},
		},
		{
			name:     "Only spaces and newlines",
			input:    "  \n  \n  ",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Leading whitespace",
			input:    "  line1\n  line2\n  line3",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Trailing whitespace",
			input:    "line1  \nline2  \nline3  ",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Both leading and trailing whitespace",
			input:    "  line1  \n  line2  \n  line3  ",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Tabs",
			input:    "\tline1\t\n\tline2\t\n\tline3\t",
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Mixed whitespace characters",
			input:    " \t line1 \t \n \t line2 \t \n",
			expected: []string{"line1", "line2"},
		},
		{
			name:     "Lines with internal whitespace preserved",
			input:    "line 1\nline  2\nline   3",
			expected: []string{"line 1", "line  2", "line   3"},
		},
		{
			name:     "Empty lines with whitespace",
			input:    "line1\n   \nline2\n\t\nline3",
			expected: []string{"line1", "line2", "line3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Security group IDs",
			input:    "sg-12345678\nsg-87654321\nsg-abcdef12",
			expected: []string{"sg-12345678", "sg-87654321", "sg-abcdef12"},
		},
		{
			name:     "Tag keys",
			input:    "Environment\nApplication\nOwner\nCostCenter",
			expected: []string{"Environment", "Application", "Owner", "CostCenter"},
		},
		{
			name:     "IP addresses",
			input:    "192.168.1.1\n10.0.0.1\n172.16.0.1",
			expected: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
		},
		{
			name:     "File paths",
			input:    "/path/to/file1\n/path/to/file2\n/path/to/file3",
			expected: []string{"/path/to/file1", "/path/to/file2", "/path/to/file3"},
		},
		{
			name:     "URLs",
			input:    "https://api.example.com\nhttps://api2.example.com\nhttps://api3.example.com",
			expected: []string{"https://api.example.com", "https://api2.example.com", "https://api3.example.com"},
		},
		{
			name:     "Command output with blank lines",
			input:    "output line 1\n\noutput line 2\n\n\noutput line 3\n",
			expected: []string{"output line 1", "output line 2", "output line 3"},
		},
		{
			name:     "IMDS response with Windows endings",
			input:    "ami-12345678\r\ni-abcdef123456\r\nt2.micro\r\n",
			expected: []string{"ami-12345678", "i-abcdef123456", "t2.micro"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Unicode characters",
			input:    "你好\nこんにちは\n안녕하세요",
			expected: []string{"你好", "こんにちは", "안녕하세요"},
		},
		{
			name:     "Emoji",
			input:    "🚀\n🔥\n💯",
			expected: []string{"🚀", "🔥", "💯"},
		},
		{
			name:     "Special symbols",
			input:    "line@1\nline#2\nline$3",
			expected: []string{"line@1", "line#2", "line$3"},
		},
		{
			name:     "JSON-like content",
			input:    "{\"key\": \"value\"}\n{\"key2\": \"value2\"}",
			expected: []string{`{"key": "value"}`, `{"key2": "value2"}`},
		},
		{
			name:     "Lines with quotes",
			input:    "\"line1\"\n'line2'\n`line3`",
			expected: []string{`"line1"`, "'line2'", "`line3`"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Very long line",
			input:    strings.Repeat("a", 10000) + "\nshort",
			expected: []string{strings.Repeat("a", 10000), "short"},
		},
		{
			name:  "Many lines",
			input: strings.Repeat("line\n", 1000),
			expected: func() []string {
				result := make([]string, 1000)
				for i := range result {
					result[i] = "line"
				}
				return result
			}(),
		},
		{
			name:     "Only carriage return (not Windows)",
			input:    "line1\rline2",
			expected: []string{"line1\rline2"},
		},
		{
			name:     "Single newline",
			input:    "\n",
			expected: []string{},
		},
		{
			name:     "Single Windows newline",
			input:    "\r\n",
			expected: []string{},
		},
		{
			name:     "Content with no newlines",
			input:    "single line content",
			expected: []string{"single line content"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMultilineResponse(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMultilineResponse_Consistency(t *testing.T) {
	input := "line1\nline2\nline3"

	result1 := ParseMultilineResponse(input)
	result2 := ParseMultilineResponse(input)

	assert.Equal(t, result1, result2, "Multiple calls with same input should return identical results")
}

func TestParseMultilineResponse_EmptySliceNotNil(t *testing.T) {
	result := ParseMultilineResponse("")

	assert.NotNil(t, result, "Result should not be nil")
	assert.Empty(t, result, "Result should be empty")
	assert.Equal(t, []string{}, result, "Result should be an empty slice, not nil")
}

func TestParseNumber_ValidIntegers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "Positive integer",
			input:    "42",
			expected: 42.0,
		},
		{
			name:     "Negative integer",
			input:    "-42",
			expected: -42.0,
		},
		{
			name:     "Zero",
			input:    "0",
			expected: 0.0,
		},
		{
			name:     "Large positive integer",
			input:    "999999999",
			expected: 999999999.0,
		},
		{
			name:     "Large negative integer",
			input:    "-999999999",
			expected: -999999999.0,
		},
		{
			name:     "Single digit",
			input:    "5",
			expected: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			require.NoError(t, err)
			assert.InDelta(t, tt.expected, result, 0.0001)
		})
	}
}

func TestParseNumber_ValidFloats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "Simple decimal",
			input:    "3.14",
			expected: 3.14,
		},
		{
			name:     "Negative decimal",
			input:    "-3.14",
			expected: -3.14,
		},
		{
			name:     "Leading zero",
			input:    "0.5",
			expected: 0.5,
		},
		{
			name:     "Trailing zeros",
			input:    "1.500",
			expected: 1.5,
		},
		{
			name:     "Many decimal places",
			input:    "3.14159265359",
			expected: 3.14159265359,
		},
		{
			name:     "Zero with decimal",
			input:    "0.0",
			expected: 0.0,
		},
		{
			name:     "Small positive decimal",
			input:    "0.001",
			expected: 0.001,
		},
		{
			name:     "Small negative decimal",
			input:    "-0.001",
			expected: -0.001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			require.NoError(t, err)
			assert.InDelta(t, tt.expected, result, 0.0000001)
		})
	}
}

func TestParseNumber_ScientificNotation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "Positive exponent lowercase",
			input:    "1.5e2",
			expected: 150.0,
		},
		{
			name:     "Positive exponent uppercase",
			input:    "1.5E2",
			expected: 150.0,
		},
		{
			name:     "Negative exponent",
			input:    "2.7e-1",
			expected: 0.27,
		},
		{
			name:     "Large exponent",
			input:    "1.23e10",
			expected: 1.23e10,
		},
		{
			name:     "Very small number",
			input:    "1e-10",
			expected: 1e-10,
		},
		{
			name:     "Negative with positive exponent",
			input:    "-1.5e2",
			expected: -150.0,
		},
		{
			name:     "Negative with negative exponent",
			input:    "-2.7e-1",
			expected: -0.27,
		},
		{
			name:     "Zero exponent",
			input:    "5e0",
			expected: 5.0,
		},
		{
			name:     "Integer with exponent",
			input:    "3e3",
			expected: 3000.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			require.NoError(t, err)
			// Use absolute value for delta calculation to handle negative numbers
			delta := tt.expected * 1e-10
			if delta < 0 {
				delta = -delta
			}
			if delta == 0 {
				delta = 1e-10
			}
			assert.InDelta(t, tt.expected, result, delta)
		})
	}
}

func TestParseNumber_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
		wantErr  bool
	}{
		{
			name:     "Very large number",
			input:    "1.7976931348623157e308",
			expected: 1.7976931348623157e308,
			wantErr:  false,
		},
		{
			name:     "Very small positive number",
			input:    "2.2250738585072014e-308",
			expected: 2.2250738585072014e-308,
			wantErr:  false,
		},
		{
			name:     "Leading plus sign",
			input:    "+42",
			expected: 42.0,
			wantErr:  false,
		},
		{
			name:     "Leading plus with decimal",
			input:    "+3.14",
			expected: 3.14,
			wantErr:  false,
		},
		{
			name:     "No leading zero",
			input:    ".5",
			expected: 0.5,
			wantErr:  false,
		},
		{
			name:     "No trailing digits",
			input:    "5.",
			expected: 5.0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid number")
			} else {
				require.NoError(t, err)
				if tt.expected == 0 {
					assert.InDelta(t, tt.expected, result, 0.0001)
				} else {
					assert.InDelta(t, tt.expected, result, tt.expected*1e-10)
				}
			}
		})
	}
}

func TestParseNumber_InvalidInputs(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Empty string",
			input: "",
		},
		{
			name:  "Text only",
			input: "abc",
		},
		{
			name:  "Text with number",
			input: "abc123",
		},
		{
			name:  "Number with text",
			input: "123abc",
		},
		{
			name:  "Multiple dots",
			input: "1.2.3",
		},
		{
			name:  "Multiple signs",
			input: "+-42",
		},
		{
			name:  "Sign in middle",
			input: "4-2",
		},
		{
			name:  "Space in number",
			input: "4 2",
		},
		{
			name:  "Comma separator",
			input: "1,234",
		},
		{
			name:  "Special characters",
			input: "@#$%",
		},
		{
			name:  "Parentheses",
			input: "(42)",
		},
		{
			name:  "Invalid scientific notation",
			input: "1e",
		},
		{
			name:  "Multiple e in scientific",
			input: "1e2e3",
		},
		{
			name:  "Hex notation",
			input: "0x42",
		},
		{
			name:  "Binary notation",
			input: "0b101",
		},
		{
			name:  "Octal notation",
			input: "0o52",
		},
		{
			name:  "Null string",
			input: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid number")
			assert.Contains(t, err.Error(), tt.input)
			assert.InDelta(t, 0.0, result, 0.0001)
		})
	}
}

func TestParseNumber_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Leading space",
			input:   " 42",
			wantErr: true,
		},
		{
			name:    "Trailing space",
			input:   "42 ",
			wantErr: true,
		},
		{
			name:    "Both spaces",
			input:   " 42 ",
			wantErr: true,
		},
		{
			name:    "Tab before",
			input:   "\t42",
			wantErr: true,
		},
		{
			name:    "Newline after",
			input:   "42\n",
			wantErr: true,
		},
		{
			name:    "Only whitespace",
			input:   "   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseNumber(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid number")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseNumber_Precision(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "High precision decimal",
			input:    "0.123456789012345",
			expected: 0.123456789012345,
		},
		{
			name:     "Very precise scientific",
			input:    "1.234567890123456e-10",
			expected: 1.234567890123456e-10,
		},
		{
			name:     "Pi approximation",
			input:    "3.141592653589793",
			expected: 3.141592653589793,
		},
		{
			name:     "Euler's number approximation",
			input:    "2.718281828459045",
			expected: 2.718281828459045,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			require.NoError(t, err)
			assert.InDelta(t, tt.expected, result, 0.0000001)
		})
	}
}

func TestParseNumber_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "CPU usage percentage",
			input:    "75.5",
			expected: 75.5,
		},
		{
			name:     "Memory in GB",
			input:    "8.25",
			expected: 8.25,
		},
		{
			name:     "Temperature in Celsius",
			input:    "-10.5",
			expected: -10.5,
		},
		{
			name:     "Price with cents",
			input:    "19.99",
			expected: 19.99,
		},
		{
			name:     "Scientific constant",
			input:    "6.022e23",
			expected: 6.022e23,
		},
		{
			name:     "Latitude",
			input:    "40.7128",
			expected: 40.7128,
		},
		{
			name:     "Longitude",
			input:    "-74.0060",
			expected: -74.0060,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNumber(tt.input)
			require.NoError(t, err)
			assert.InDelta(t, tt.expected, result, 0.0001)
		})
	}
}
