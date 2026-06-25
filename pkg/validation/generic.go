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

package validation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// ValidateEnum checks if a value is within a set of allowed values.
// It performs exact comparison and returns an error if the value is not allowed.
func ValidateEnum[T comparable](value T, allowed []T, fieldName string) error {
	if slices.Contains(allowed, value) {
		return nil
	}
	return fmt.Errorf("invalid %s %v: must be one of %v", fieldName, value, allowed)
}

// ValidateEnumString checks if a string value is within a set of allowed values.
// It performs case-insensitive comparison and returns an error if the value is empty or not allowed.
func ValidateEnumString(value string, allowed []string, fieldName string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	for _, allowedValue := range allowed {
		if strings.ToLower(allowedValue) == normalizedValue {
			return nil
		}
	}

	return fmt.Errorf("invalid %s %q: must be one of %v", fieldName, value, allowed)
}

// ValidateRequiredString ensures a string value is not empty.
// It trims whitespace before checking to avoid accepting spaces-only values.
func ValidateRequiredString(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// ValidatePositiveInt ensures an integer value is positive (greater than 0).
func ValidatePositiveInt(value int, fieldName string) error {
	if value <= 0 {
		return fmt.Errorf("%s must be positive, got %d", fieldName, value)
	}
	return nil
}

// ValidateNonNegativeInt ensures an integer value is non-negative (0 or greater).
func ValidateNonNegativeInt(value int, fieldName string) error {
	if value < 0 {
		return fmt.Errorf("%s must be non-negative, got %d", fieldName, value)
	}
	return nil
}

// ValidateIntRange ensures an integer value is within a specified range (inclusive).
func ValidateIntRange(value, minVal, maxVal int, fieldName string) error {
	if value < minVal || value > maxVal {
		return fmt.Errorf("%s must be between %d and %d (inclusive), got %d", fieldName, minVal, maxVal, value)
	}
	return nil
}

// ValidateURLFormat validates URL format with insecure option handling.
func ValidateURLFormat(url string, insecure bool, fieldName string) error {
	if url == "" {
		return nil
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("invalid %s %q: URL must start with http:// or https://", fieldName, url)
	}

	if strings.HasPrefix(url, "http://") && !insecure {
		return fmt.Errorf("HTTP URL requires --insecure flag: %s", url)
	}

	return nil
}

// ValidateFileExists checks if a file exists and is readable.
func ValidateFileExists(path string) error {
	if path == "" {
		return nil
	}

	// Expand tilde home directory and environment variables
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return pkgerrors.Wrap(err, "failed to get home directory")
		}
		path = filepath.Join(home, path[2:])
	}
	path = os.ExpandEnv(path)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", path)
		}
		return pkgerrors.Wrap(err, "failed to access file")
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}

	// Verify file is readable
	file, err := os.Open(path)
	if err != nil {
		return pkgerrors.Wrap(err, "file is not readable")
	}
	_ = file.Close()

	return nil
}

// FileValidationOptions configures file validation behavior.
type FileValidationOptions struct {
	MaxSize       int64
	AllowEmpty    bool
	RequireExists bool
	FileType      string // Description for error messages (e.g., "public key", "config")
}

// ValidateRelativePath checks that a path field is safe:
// no absolute paths, no null bytes, and no traversal above the working directory.
func ValidateRelativePath(field, value string) error {
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("'%s' contains null bytes", field)
	}

	if filepath.IsAbs(value) || strings.HasPrefix(value, "/") {
		return fmt.Errorf("'%s' must be a relative path, got absolute: %q", field, value)
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("'%s': failed to get working directory: %w", field, err)
	}

	abs, err := filepath.Abs(value)
	if err != nil {
		return fmt.Errorf("'%s': failed to resolve absolute path: %w", field, err)
	}

	if !strings.HasPrefix(abs, wd+string(filepath.Separator)) && abs != wd {
		return fmt.Errorf("'%s' must not traverse above the working directory: %q resolves to %q (wd: %q)", field, value, abs, wd)
	}

	return nil
}

// ValidateAndResolvePath validates and resolves a file path, ensuring parent directory exists.
func ValidateAndResolvePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path cannot be empty")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", pkgerrors.Wrap(err, "failed to resolve path")
	}

	// Check if parent directory exists
	dir := filepath.Dir(absPath)
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		return "", fmt.Errorf("directory does not exist: %s", dir)
	}

	return absPath, nil
}

// CheckFileExists checks if a file exists and returns appropriate error.
func CheckFileExists(path string, fileType string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s file already exists: %s", fileType, path)
	}
	return nil
}

// ValidateFile performs comprehensive file validation based on options.
func ValidateFile(path string, opts FileValidationOptions) error {
	fileInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		if opts.RequireExists {
			return fmt.Errorf("%s file not found: %s", opts.FileType, path)
		}
		return nil // File doesn't exist but that's OK
	}
	if err != nil {
		return pkgerrors.Wrap(err, fmt.Sprintf("failed to access %s file", opts.FileType))
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}

	if !opts.AllowEmpty && fileInfo.Size() == 0 {
		return fmt.Errorf("%s file is empty", opts.FileType)
	}

	if opts.MaxSize > 0 && fileInfo.Size() > opts.MaxSize {
		return fmt.Errorf("%s file too large: %d bytes (max: %d)",
			opts.FileType, fileInfo.Size(), opts.MaxSize)
	}

	return nil
}
