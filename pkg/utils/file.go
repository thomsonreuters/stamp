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
	"fmt"
	"math"
	"path/filepath"
	"strings"
)

// NormalizePath normalizes a path for cross-platform compatibility.
// It resolves . and .. components and converts all path separators to forward slashes.
//
//	NormalizePath("C:\\Users\\..\\file.go") => "C:/file.go"
//	NormalizePath("./foo/../bar")           => "bar"
func NormalizePath(path string) string {
	normalized := filepath.Clean(path)

	normalized = filepath.ToSlash(normalized)

	return normalized
}

// IsSpecialDirectory checks if a directory name is a special directory (. or ..).
func IsSpecialDirectory(name string) bool {
	return name == "." || name == ".."
}

// Size constants for file sizes (binary units).
const (
	_        = iota // ignore first value by assigning to blank identifier
	KB int64 = 1 << (10 * iota)
	MB
	GB
	TB
	PB
)

// ParseSize parses human-readable size strings into bytes.
// Supports: B, KB, MB, GB, TB, PB (case insensitive).
func ParseSize(sizeStr string) (int64, error) {
	// Normalize input
	sizeStr = strings.TrimSpace(sizeStr)

	// Handle empty or zero (unlimited/disabled)
	if sizeStr == "" || sizeStr == "0" {
		return 0, nil
	}

	// Convert to uppercase for case-insensitive matching
	upperStr := strings.ToUpper(sizeStr)

	// Define suffixes with multipliers (longest first to avoid partial matches)
	suffixes := []struct {
		suffix     string
		multiplier int64
	}{
		{"PB", PB},
		{"TB", TB},
		{"GB", GB},
		{"MB", MB},
		{"KB", KB},
		{"B", 1},
	}

	// Try matching each suffix
	for _, s := range suffixes {
		if before, ok := strings.CutSuffix(upperStr, s.suffix); ok { //nolint:nestif // Size parsing requires nested checks for different formats
			numStr := before
			numStr = strings.TrimSpace(numStr)

			// Parse the numeric part (supports floats)
			num, err := parseNumber(numStr)
			if err != nil {
				return 0, fmt.Errorf("invalid size format '%s': %w", sizeStr, err)
			}

			// Check for negative values
			if num < 0 {
				return 0, fmt.Errorf("size cannot be negative: %s", sizeStr)
			}

			// Check for overflow before multiplication
			if num > 0 && s.multiplier > 0 {
				if num > float64(math.MaxInt64)/float64(s.multiplier) {
					return 0, fmt.Errorf("size too large (overflow): %s", sizeStr)
				}
			}

			result := int64(num * float64(s.multiplier))
			return result, nil
		}
	}

	// No suffix found - try parsing as raw bytes
	num, err := parseNumber(upperStr)
	if err != nil {
		return 0, fmt.Errorf("invalid size format '%s' (expected: 512KB, 1.5MB, 5GB, etc.): %w", sizeStr, err)
	}

	// Check for negative values
	if num < 0 {
		return 0, fmt.Errorf("size cannot be negative: %s", sizeStr)
	}

	// Check for overflow
	if num > float64(math.MaxInt64) {
		return 0, fmt.Errorf("size too large (overflow): %s", sizeStr)
	}

	return int64(num), nil
}
