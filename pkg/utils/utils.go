// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package utils provides utility functions.
package utils

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var (
	// ErrSocketNotFound indicates a socket/named pipe was not found.
	ErrSocketNotFound = errors.New("socket not found")
)

func IsAbsoluteURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

// SplitAndTransform splits a string by separator and transforms each part using the provided function.
// Parts that result in the zero value of T after transformation are filtered out.
// This generic function allows flexible string parsing and transformation.
//
// Example:
//
//	nums := SplitAndTransform("1, 2, 3", ",", func(s string) (int, bool) {
//	    val, err := strconv.Atoi(strings.TrimSpace(s))
//	    return val, err == nil
//	})
func SplitAndTransform[T any](s string, sep string, transform func(string) (T, bool)) []T {
	if s == "" {
		return []T{}
	}

	parts := strings.Split(s, sep)
	result := make([]T, 0, len(parts))

	for _, part := range parts {
		if val, ok := transform(part); ok {
			result = append(result, val)
		}
	}

	return result
}

// SplitAndTrim splits a string by separator and trims whitespace from each part.
// Empty parts (after trimming) are filtered out.
//
// Example:
//
//	tags := SplitAndTrim("go, rust,  python  ", ",")
func SplitAndTrim(s string, sep string) []string {
	return SplitAndTransform(s, sep, func(part string) (string, bool) {
		trimmed := strings.TrimSpace(part)
		return trimmed, trimmed != ""
	})
}

// ParseMultilineResponse parses responses that contain newline-separated values.
// It handles both Unix (\n) and Windows (\r\n) line endings, mixed line endings,
// and filters out empty lines (after trimming whitespace).
//
// This is commonly used for parsing IMDS responses, command outputs, and other
// text-based responses where each line represents a distinct value.
//
// Returns a slice of non-empty trimmed lines. Returns an empty slice for empty input.
//
// Example:
//
//	lines := ParseMultilineResponse("line1\nline2\r\nline3")
func ParseMultilineResponse(response string) []string {
	if response == "" {
		return []string{}
	}

	// Replace all \r\n with \n, then split by \n to handle mixed line endings
	normalized := strings.ReplaceAll(response, "\r\n", "\n")
	lines := []string{}

	for line := range strings.SplitSeq(normalized, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	return lines
}

// parseNumber parses a string as a float64, supporting integers, floats, and scientific notation.
func parseNumber(numStr string) (float64, error) {
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", numStr)
	}
	return num, nil
}
