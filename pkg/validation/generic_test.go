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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateEnum(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		allowed   []int
		fieldName string
		wantErr   bool
	}{
		{
			name:      "valid value",
			value:     2,
			allowed:   []int{1, 2, 3},
			fieldName: "number",
			wantErr:   false,
		},
		{
			name:      "invalid value",
			value:     4,
			allowed:   []int{1, 2, 3},
			fieldName: "number",
			wantErr:   true,
		},
		{
			name:      "empty allowed list",
			value:     1,
			allowed:   []int{},
			fieldName: "number",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEnum(tt.value, tt.allowed, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEnumString(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		allowed   []string
		fieldName string
		wantErr   bool
	}{
		{
			name:      "valid value exact match",
			value:     "info",
			allowed:   []string{"debug", "info", "warn", "error"},
			fieldName: "log-level",
			wantErr:   false,
		},
		{
			name:      "valid value case insensitive",
			value:     "INFO",
			allowed:   []string{"debug", "info", "warn", "error"},
			fieldName: "log-level",
			wantErr:   false,
		},
		{
			name:      "valid value with whitespace",
			value:     "  info  ",
			allowed:   []string{"debug", "info", "warn", "error"},
			fieldName: "log-level",
			wantErr:   false,
		},
		{
			name:      "invalid value",
			value:     "trace",
			allowed:   []string{"debug", "info", "warn", "error"},
			fieldName: "log-level",
			wantErr:   true,
		},
		{
			name:      "empty value",
			value:     "",
			allowed:   []string{"debug", "info"},
			fieldName: "log-level",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEnumString(tt.value, tt.allowed, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRequiredString(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		fieldName string
		wantErr   bool
	}{
		{
			name:      "valid non-empty string",
			value:     "test",
			fieldName: "name",
			wantErr:   false,
		},
		{
			name:      "empty string",
			value:     "",
			fieldName: "name",
			wantErr:   true,
		},
		{
			name:      "whitespace only",
			value:     "   ",
			fieldName: "name",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequiredString(tt.value, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePositiveInt(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		fieldName string
		wantErr   bool
	}{
		{
			name:      "positive value",
			value:     5,
			fieldName: "count",
			wantErr:   false,
		},
		{
			name:      "zero value",
			value:     0,
			fieldName: "count",
			wantErr:   true,
		},
		{
			name:      "negative value",
			value:     -1,
			fieldName: "count",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePositiveInt(tt.value, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNonNegativeInt(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		fieldName string
		wantErr   bool
	}{
		{
			name:      "positive value",
			value:     5,
			fieldName: "count",
			wantErr:   false,
		},
		{
			name:      "zero value",
			value:     0,
			fieldName: "count",
			wantErr:   false,
		},
		{
			name:      "negative value",
			value:     -1,
			fieldName: "count",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNonNegativeInt(tt.value, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIntRange(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		minVal    int
		maxVal    int
		fieldName string
		wantErr   bool
	}{
		{
			name:      "value in range",
			value:     5,
			minVal:    1,
			maxVal:    10,
			fieldName: "port",
			wantErr:   false,
		},
		{
			name:      "value at min boundary",
			value:     1,
			minVal:    1,
			maxVal:    10,
			fieldName: "port",
			wantErr:   false,
		},
		{
			name:      "value at max boundary",
			value:     10,
			minVal:    1,
			maxVal:    10,
			fieldName: "port",
			wantErr:   false,
		},
		{
			name:      "value below min",
			value:     0,
			minVal:    1,
			maxVal:    10,
			fieldName: "port",
			wantErr:   true,
		},
		{
			name:      "value above max",
			value:     11,
			minVal:    1,
			maxVal:    10,
			fieldName: "port",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIntRange(tt.value, tt.minVal, tt.maxVal, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURLFormat(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		insecure  bool
		fieldName string
		wantErr   bool
	}{
		{
			name:      "valid https url",
			url:       "https://example.com",
			insecure:  false,
			fieldName: "server-url",
			wantErr:   false,
		},
		{
			name:      "valid http url with insecure flag",
			url:       "http://localhost:8080",
			insecure:  true,
			fieldName: "server-url",
			wantErr:   false,
		},
		{
			name:      "http url without insecure flag",
			url:       "http://localhost:8080",
			insecure:  false,
			fieldName: "server-url",
			wantErr:   true,
		},
		{
			name:      "invalid url without protocol",
			url:       "example.com",
			insecure:  false,
			fieldName: "server-url",
			wantErr:   true,
		},
		{
			name:      "empty url",
			url:       "",
			insecure:  false,
			fieldName: "server-url",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLFormat(tt.url, tt.insecure, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFileExists(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err, "Failed to create test file")

	// Create a directory for testing
	testDir := filepath.Join(tmpDir, "testdir")
	err = os.Mkdir(testDir, 0755)
	require.NoError(t, err, "Failed to create test directory")

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "existing file",
			path:    testFile,
			wantErr: false,
		},
		{
			name:    "non-existent file",
			path:    filepath.Join(tmpDir, "nonexistent.txt"),
			wantErr: true,
		},
		{
			name:    "directory instead of file",
			path:    testDir,
			wantErr: true,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFileExists(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRelativePath(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"simple name", "testapp", true},
		{"subdirectory", "dist/testapp", true},
		{"dot-slash prefix", "./cmd/app", true},
		{"single dot", ".", true},
		{"double dot", "..", false},
		{"double dot slash", "../escape", false},
		{"deep traversal", "../../etc/passwd", false},
		{"mid-path double dot", "a/../../escape", false},
		{"absolute unix", "/tmp/app", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRelativePath("test", tt.value)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateAndResolvePath(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid path with existing parent",
			path:    filepath.Join(tmpDir, "newfile.txt"),
			wantErr: false,
		},
		{
			name:    "path with non-existent parent",
			path:    filepath.Join(tmpDir, "nonexistent", "newfile.txt"),
			wantErr: true,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAndResolvePath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.True(t, filepath.IsAbs(result), "returned path should be absolute")
			}
		})
	}
}

func TestCheckFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.txt")
	err := os.WriteFile(existingFile, []byte("test"), 0644)
	require.NoError(t, err, "Failed to create test file")

	tests := []struct {
		name     string
		path     string
		fileType string
		wantErr  bool
	}{
		{
			name:     "file exists",
			path:     existingFile,
			fileType: "test",
			wantErr:  true,
		},
		{
			name:     "file does not exist",
			path:     filepath.Join(tmpDir, "newfile.txt"),
			fileType: "test",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckFileExists(tt.path, tt.fileType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	normalFile := filepath.Join(tmpDir, "normal.txt")
	err := os.WriteFile(normalFile, []byte("test content"), 0644)
	require.NoError(t, err, "Failed to create normal file")

	emptyFile := filepath.Join(tmpDir, "empty.txt")
	err = os.WriteFile(emptyFile, []byte(""), 0644)
	require.NoError(t, err, "Failed to create empty file")

	largeFile := filepath.Join(tmpDir, "large.txt")
	err = os.WriteFile(largeFile, make([]byte, 1024), 0644)
	require.NoError(t, err, "Failed to create large file")

	testDir := filepath.Join(tmpDir, "dir")
	err = os.Mkdir(testDir, 0755)
	require.NoError(t, err, "Failed to create directory")

	tests := []struct {
		name    string
		path    string
		opts    FileValidationOptions
		wantErr bool
	}{
		{
			name: "valid file with all checks",
			path: normalFile,
			opts: FileValidationOptions{
				MaxSize:       1024,
				AllowEmpty:    false,
				RequireExists: true,
				FileType:      "test",
			},
			wantErr: false,
		},
		{
			name: "empty file not allowed",
			path: emptyFile,
			opts: FileValidationOptions{
				AllowEmpty:    false,
				RequireExists: true,
				FileType:      "test",
			},
			wantErr: true,
		},
		{
			name: "empty file allowed",
			path: emptyFile,
			opts: FileValidationOptions{
				AllowEmpty:    true,
				RequireExists: true,
				FileType:      "test",
			},
			wantErr: false,
		},
		{
			name: "file too large",
			path: largeFile,
			opts: FileValidationOptions{
				MaxSize:       512,
				RequireExists: true,
				FileType:      "test",
			},
			wantErr: true,
		},
		{
			name: "non-existent file not required",
			path: filepath.Join(tmpDir, "nonexistent.txt"),
			opts: FileValidationOptions{
				RequireExists: false,
				FileType:      "test",
			},
			wantErr: false,
		},
		{
			name: "non-existent file required",
			path: filepath.Join(tmpDir, "nonexistent.txt"),
			opts: FileValidationOptions{
				RequireExists: true,
				FileType:      "test",
			},
			wantErr: true,
		},
		{
			name: "directory instead of file",
			path: testDir,
			opts: FileValidationOptions{
				RequireExists: true,
				FileType:      "test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFile(tt.path, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
