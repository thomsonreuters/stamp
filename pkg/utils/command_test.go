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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:funlen // Comprehensive command parsing test requires extensive test cases
func TestParseCommand(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []string
		expectError bool
		errorMsg    string
	}{
		// Basic cases
		{
			name:     "simple command",
			input:    "echo hello world",
			expected: []string{"echo", "hello", "world"},
		},
		{
			name:     "single argument",
			input:    "ls",
			expected: []string{"ls"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "only whitespace",
			input:    "   \t\n   ",
			expected: []string{},
		},

		// Quote handling - double quotes
		{
			name:     "double quoted argument",
			input:    `echo "hello world"`,
			expected: []string{"echo", "hello world"},
		},
		{
			name:     "multiple double quoted arguments",
			input:    `echo "hello" "world"`,
			expected: []string{"echo", "hello", "world"},
		},
		{
			name:     "double quotes with single quotes inside",
			input:    `echo "it's working"`,
			expected: []string{"echo", "it's working"},
		},
		{
			name:     "empty double quoted string",
			input:    `echo "" test`,
			expected: []string{"echo", "", "test"},
		},
		{
			name:     "multiple empty double quoted strings",
			input:    `echo "" "" "hello"`,
			expected: []string{"echo", "", "", "hello"},
		},

		// Quote handling - single quotes
		{
			name:     "single quoted argument",
			input:    "echo 'hello world'",
			expected: []string{"echo", "hello world"},
		},
		{
			name:     "single quotes with double quotes inside",
			input:    `echo 'he said "hi"'`,
			expected: []string{"echo", `he said "hi"`},
		},
		{
			name:     "empty single quoted string",
			input:    "echo '' test",
			expected: []string{"echo", "", "test"},
		},

		// Mixed quotes
		{
			name:     "alternating quote types",
			input:    `echo "hello" 'world' "foo"`,
			expected: []string{"echo", "hello", "world", "foo"},
		},
		{
			name:     "adjacent quotes",
			input:    `echo "hello"'world'`,
			expected: []string{"echo", "hello", "world"},
		},

		// Escape sequences outside quotes
		{
			name:     "escaped space",
			input:    `echo hello\ world`,
			expected: []string{"echo", "hello world"},
		},
		{
			name:     "escaped quote outside quotes",
			input:    `echo hello\"world`,
			expected: []string{"echo", `hello"world`},
		},
		{
			name:     "escaped backslash",
			input:    `echo hello\\world`,
			expected: []string{"echo", `hello\world`},
		},
		{
			name:     "escaped newline",
			input:    "echo hello\\\nworld",
			expected: []string{"echo", "hello\nworld"},
		},

		// Escape sequences inside quotes
		{
			name:     "escaped quote inside double quotes",
			input:    `echo "hello\"world"`,
			expected: []string{"echo", `hello"world`},
		},
		{
			name:     "escaped quote inside single quotes",
			input:    `echo 'hello\'world'`,
			expected: []string{"echo", `hello'world`},
		},
		{
			name:     "escaped backslash inside quotes",
			input:    `echo "hello\\world"`,
			expected: []string{"echo", `hello\world`},
		},

		// Multiple whitespace
		{
			name:     "multiple spaces",
			input:    "echo    hello     world",
			expected: []string{"echo", "hello", "world"},
		},
		{
			name:     "tabs and spaces",
			input:    "echo\thello\t\tworld",
			expected: []string{"echo", "hello", "world"},
		},
		{
			name:     "newlines",
			input:    "echo\nhello\nworld",
			expected: []string{"echo", "hello", "world"},
		},
		{
			name:     "leading and trailing whitespace",
			input:    "  \t echo hello world \n ",
			expected: []string{"echo", "hello", "world"},
		},

		// Real-world examples
		{
			name:     "git commit",
			input:    `git commit -m "fix: resolve bug"`,
			expected: []string{"git", "commit", "-m", "fix: resolve bug"},
		},
		{
			name:     "docker run",
			input:    `docker run -e "API_KEY=secret123" nginx`,
			expected: []string{"docker", "run", "-e", "API_KEY=secret123", "nginx"},
		},
		{
			name:     "ssh command",
			input:    `ssh user@host 'ls -la /home/user'`,
			expected: []string{"ssh", "user@host", "ls -la /home/user"},
		},
		{
			name:     "find with exec",
			input:    `find . -name "*.go" -type f`,
			expected: []string{"find", ".", "-name", "*.go", "-type", "f"},
		},

		// Unicode support
		{
			name:     "unicode characters",
			input:    `echo "你好世界" "こんにちは"`,
			expected: []string{"echo", "你好世界", "こんにちは"},
		},
		{
			name:     "emoji",
			input:    `echo "🎉 success 🚀"`,
			expected: []string{"echo", "🎉 success 🚀"},
		},

		// Special characters (no shell expansion)
		{
			name:     "dollar sign",
			input:    `echo $HOME test`,
			expected: []string{"echo", "$HOME", "test"},
		},
		{
			name:     "pipe character",
			input:    `echo hello | grep world`,
			expected: []string{"echo", "hello", "|", "grep", "world"},
		},
		{
			name:     "ampersand",
			input:    `echo hello && echo world`,
			expected: []string{"echo", "hello", "&&", "echo", "world"},
		},

		// Error cases - unclosed quotes
		{
			name:        "unclosed double quote",
			input:       `echo "hello world`,
			expectError: true,
			errorMsg:    "unclosed quote",
		},
		{
			name:        "unclosed single quote",
			input:       "echo 'hello world",
			expectError: true,
			errorMsg:    "unclosed quote",
		},
		{
			name:        "unclosed quote with other content",
			input:       `echo "hello" "world`,
			expectError: true,
			errorMsg:    "unclosed quote",
		},

		// Error cases - trailing backslash
		{
			name:        "trailing backslash",
			input:       `echo hello\`,
			expectError: true,
			errorMsg:    "trailing backslash",
		},
		{
			name:        "trailing backslash after space",
			input:       `echo hello \`,
			expectError: true,
			errorMsg:    "trailing backslash",
		},

		// Edge cases
		{
			name:     "only quotes",
			input:    `""`,
			expected: []string{""},
		},
		{
			name:     "multiple empty strings",
			input:    `"" "" ""`,
			expected: []string{"", "", ""},
		},
		{
			name:     "quote at start",
			input:    `"echo" hello`,
			expected: []string{"echo", "hello"},
		},
		{
			name:     "quote at end",
			input:    `echo "hello"`,
			expected: []string{"echo", "hello"},
		},
		{
			name:     "backslash before quote",
			input:    `echo \"hello\"`,
			expected: []string{"echo", `"hello"`},
		},
		{
			name:     "complex escaping",
			input:    `echo "a\"b\\c'd"`,
			expected: []string{"echo", `a"b\c'd`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCommand(tt.input)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseCommand_EmptyInputVariations(t *testing.T) {
	variations := []string{
		"",
		" ",
		"  ",
		"\t",
		"\n",
		"\t\n",
		"   \t\n   ",
	}

	for _, input := range variations {
		t.Run("empty_input", func(t *testing.T) {
			result, err := ParseCommand(input)
			require.NoError(t, err)
			assert.Empty(t, result)
		})
	}
}

func TestParseCommand_QuoteVariations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "double then single",
			input:    `"hello" 'world'`,
			expected: []string{"hello", "world"},
		},
		{
			name:     "single then double",
			input:    `'hello' "world"`,
			expected: []string{"hello", "world"},
		},
		{
			name:     "nested appearance (but separate)",
			input:    `"outer 'inner' outer"`,
			expected: []string{"outer 'inner' outer"},
		},
		{
			name:     "reverse nested appearance",
			input:    `'outer "inner" outer'`,
			expected: []string{`outer "inner" outer`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCommand(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseCommand_EmbeddedNewlines tests Issue #10: commands with embedded newlines in strings.
func TestParseCommand_EmbeddedNewlines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "escaped n in double quotes",
			input:    `echo "hello\nworld"`,
			expected: []string{"echo", "hellonworld"}, // \n becomes just 'n' (backslash escapes n)
		},
		{
			name:     "escaped n in single quotes",
			input:    `echo 'hello\nworld'`,
			expected: []string{"echo", "hellonworld"}, // \n becomes just 'n' (backslash escapes n)
		},
		{
			name:     "actual newline in double quotes",
			input:    "echo \"hello\nworld\"",
			expected: []string{"echo", "hello\nworld"}, // Actual newline character
		},
		{
			name:     "actual newline in single quotes",
			input:    "echo 'hello\nworld'",
			expected: []string{"echo", "hello\nworld"}, // Actual newline character
		},
		{
			name:     "multiple actual newlines in string",
			input:    "echo \"line1\nline2\nline3\"",
			expected: []string{"echo", "line1\nline2\nline3"},
		},
		{
			name:     "newline between arguments",
			input:    "echo hello\nworld",
			expected: []string{"echo", "hello", "world"}, // Newline acts as separator
		},
		{
			name:     "escaped newline outside quotes",
			input:    "echo hello\\\nworld",
			expected: []string{"echo", "hello\nworld"}, // Backslash escapes the newline
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCommand(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseCommand_EmptyParts tests Issue #11: empty command parts.
func TestParseCommand_EmptyParts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty double quoted string",
			input:    `""`,
			expected: []string{""},
		},
		{
			name:     "empty single quoted string",
			input:    `''`,
			expected: []string{""},
		},
		{
			name:     "empty string as first argument",
			input:    `"" echo hello`,
			expected: []string{"", "echo", "hello"},
		},
		{
			name:     "empty string in middle",
			input:    `echo "" hello`,
			expected: []string{"echo", "", "hello"},
		},
		{
			name:     "empty string at end",
			input:    `echo hello ""`,
			expected: []string{"echo", "hello", ""},
		},
		{
			name:     "multiple empty strings",
			input:    `"" "" ""`,
			expected: []string{"", "", ""},
		},
		{
			name:     "mixed empty and non-empty",
			input:    `"" valid "" another ""`,
			expected: []string{"", "valid", "", "another", ""},
		},
		{
			name:     "empty with spaces",
			input:    `   ""   test   ""   `,
			expected: []string{"", "test", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCommand(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
