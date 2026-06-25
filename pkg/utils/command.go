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
	"fmt"
	"strings"
)

// ParseCommand parses a shell-like command string into individual arguments.
// It handles quotes (both single and double), escape sequences, and whitespace.
//
// Features:
//   - Splits on whitespace (space, tab, newline)
//   - Preserves spaces inside quoted strings
//   - Supports both single (') and double (") quotes
//   - Handles backslash escaping (\)
//   - Preserves empty quoted strings
//   - Different quote types don't affect each other (shell-like behavior)
//
// Returns an error if:
//   - Quotes are unclosed
//   - Command ends with a trailing backslash
//
// Examples:
//   - "echo hello world"           -> ["echo", "hello", "world"]
//   - "echo 'hello world'"         -> ["echo", "hello world"]
//   - `echo "hello world"`         -> ["echo", "hello world"]
//   - "echo ” test"               -> ["echo", "", "test"]
//   - `echo "it's working"`        -> ["echo", "it's working"]
//   - `echo 'he said "hi"'`        -> ["echo", "he said \"hi\""]
func ParseCommand(cmd string) ([]string, error) {
	parts := make([]string, 0)
	var current strings.Builder
	var inQuote rune
	var escaped bool

	for _, r := range cmd {
		// Handle escaped characters
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		// Check for escape character
		if r == '\\' {
			escaped = true
			continue
		}

		// Inside quotes - different quote types don't affect each other
		if inQuote != 0 {
			if r == inQuote {
				// Closing quote - append even if empty
				parts = append(parts, current.String())
				current.Reset()
				inQuote = 0
			} else {
				// Any other character (including other quote types) is literal
				current.WriteRune(r)
			}
			continue
		}

		// Not in quotes - check for special characters
		switch r {
		case '"', '\'':
			// Opening quote
			inQuote = r
		case ' ', '\t', '\n':
			// Whitespace - split argument
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			// Regular character
			current.WriteRune(r)
		}
	}

	// Validate state after parsing
	if inQuote != 0 {
		return nil, fmt.Errorf("unclosed quote: %c", inQuote)
	}

	if escaped {
		return nil, errors.New("trailing backslash at end of command")
	}

	// Add final argument if present
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts, nil
}
