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

package file

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/attestors/file/platform"
	"github.com/thomsonreuters/stamp/pkg/logger"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// TestExtractPermissions verifies permission extraction.
func TestExtractPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	fileInfo, err := os.Stat(testFile)
	require.NoError(t, err)

	tests := []struct {
		name               string
		capturePermissions bool
		expectNil          bool
	}{
		{
			name:               "capture_enabled",
			capturePermissions: true,
			expectNil:          false,
		},
		{
			name:               "capture_disabled",
			capturePermissions: false,
			expectNil:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					CapturePermissions: tt.capturePermissions,
				},
			}

			result := a.extractPermissions(fileInfo)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.Mode)
				assert.NotEmpty(t, result.Symbolic)
				assert.Contains(t, result.Mode, "0")
			}
		})
	}
}

// TestExtractPermissions_DifferentModes verifies different file modes.
func TestExtractPermissions_DifferentModes(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name string
		mode os.FileMode
	}{
		{
			name: "read_write_owner_only",
			mode: 0600,
		},
		{
			name: "read_execute_owner",
			mode: 0500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := filepath.Join(tmpDir, tt.name+".txt")
			require.NoError(t, os.WriteFile(testFile, []byte("test"), tt.mode))

			// Apply chmod to ensure permissions are set correctly
			require.NoError(t, os.Chmod(testFile, tt.mode))

			fileInfo, err := os.Stat(testFile)
			require.NoError(t, err)

			a := &Attestor{
				logger: logger.NewNoop(),
				config: Config{
					CapturePermissions: true,
				},
			}

			result := a.extractPermissions(fileInfo)
			assert.NotNil(t, result)
			// Verify mode format is correct (starts with 0 and has digits)
			assert.Contains(t, result.Mode, "0")
			assert.NotEmpty(t, result.Symbolic)
		})
	}
}

// TestExtractOwnership verifies ownership extraction.
func TestExtractOwnership(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	fileInfo, err := os.Stat(testFile)
	require.NoError(t, err)

	tests := []struct {
		name             string
		captureOwnership bool
		expectNil        bool
	}{
		{
			name:             "capture_enabled",
			captureOwnership: true,
			expectNil:        false,
		},
		{
			name:             "capture_disabled",
			captureOwnership: false,
			expectNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger:      logger.NewNoop(),
				platformOps: platform.New(),
				config: Config{
					CaptureOwnership: tt.captureOwnership,
				},
			}

			result := a.extractOwnership(testFile, fileInfo)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				// Platform-specific, so we just check it's not nil
			}
		})
	}
}

// TestExtractOwnership_WithMock verifies ownership extraction with mock.
func TestExtractOwnership_WithMock(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	fileInfo, err := os.Stat(testFile)
	require.NoError(t, err)

	mockPlatform := platform.NewMockOps()
	mockPlatform.On("ExtractOwnership", testFile, fileInfo).Return(&filepredicate.OwnershipInfo{
		UID:   1000,
		GID:   1000,
		User:  "testuser",
		Group: "testgroup",
	})

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: mockPlatform,
		config: Config{
			CaptureOwnership: true,
		},
	}

	result := a.extractOwnership(testFile, fileInfo)
	assert.NotNil(t, result)
	assert.Equal(t, 1000, result.UID)
	assert.Equal(t, 1000, result.GID)
	assert.Equal(t, "testuser", result.User)
	assert.Equal(t, "testgroup", result.Group)
	mockPlatform.AssertExpectations(t)
}

// TestExtractTimestamps verifies timestamp extraction.
func TestExtractTimestamps(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	fileInfo, err := os.Stat(testFile)
	require.NoError(t, err)

	tests := []struct {
		name              string
		captureTimestamps bool
		expectNil         bool
	}{
		{
			name:              "capture_enabled",
			captureTimestamps: true,
			expectNil:         false,
		},
		{
			name:              "capture_disabled",
			captureTimestamps: false,
			expectNil:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger:      logger.NewNoop(),
				platformOps: platform.New(),
				config: Config{
					CaptureTimestamps: tt.captureTimestamps,
				},
			}

			result := a.extractTimestamps(fileInfo)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				// Platform-specific, so we just check it's not nil
			}
		})
	}
}

// TestExtractTimestamps_WithMock verifies timestamp extraction with mock.
func TestExtractTimestamps_WithMock(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	fileInfo, err := os.Stat(testFile)
	require.NoError(t, err)

	mockPlatform := platform.NewMockOps()
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPlatform.On("ExtractTimestamps", fileInfo).Return(&filepredicate.TimestampInfo{
		Modified: testTime,
		Created:  testTime,
		Accessed: testTime,
	})

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: mockPlatform,
		config: Config{
			CaptureTimestamps: true,
		},
	}

	result := a.extractTimestamps(fileInfo)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Modified)
	mockPlatform.AssertExpectations(t)
}

// TestExtractSymlinkInfo verifies symlink information extraction.
func TestExtractSymlinkInfo(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping symlink test in CI environment")
	}

	tmpDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tmpDir, "regular.txt")
	require.NoError(t, os.WriteFile(regularFile, []byte("test"), 0644))

	// Create a symlink
	symlinkFile := filepath.Join(tmpDir, "link.txt")
	require.NoError(t, os.Symlink(regularFile, symlinkFile))

	tests := []struct {
		name        string
		filePath    string
		expectNil   bool
		expectError bool
	}{
		{
			name:        "regular_file",
			filePath:    regularFile,
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "symlink_file",
			filePath:    symlinkFile,
			expectNil:   false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileInfo, err := os.Lstat(tt.filePath)
			require.NoError(t, err)

			a := &Attestor{
				logger: logger.NewNoop(),
			}

			result, err := a.extractSymlinkInfo(tt.filePath, fileInfo)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.True(t, result.IsSymlink)
				assert.NotEmpty(t, result.Target)
			}
		})
	}
}

// TestExtractSymlinkInfo_BrokenSymlink verifies handling of broken symlinks.
func TestExtractSymlinkInfo_BrokenSymlink(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping symlink test in CI environment")
	}

	tmpDir := t.TempDir()

	// Create a symlink to a non-existent target
	symlinkFile := filepath.Join(tmpDir, "broken.txt")
	require.NoError(t, os.Symlink("/nonexistent/target", symlinkFile))

	fileInfo, err := os.Lstat(symlinkFile)
	require.NoError(t, err)

	a := &Attestor{
		logger: logger.NewNoop(),
	}

	result, err := a.extractSymlinkInfo(symlinkFile, fileInfo)
	require.NoError(t, err) // Reading the link should succeed
	assert.NotNil(t, result)
	assert.True(t, result.IsSymlink)
	assert.Equal(t, "/nonexistent/target", result.Target)
}

// TestExtractSymlinkInfo_Directory verifies directory handling.
func TestExtractSymlinkInfo_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	dirPath := filepath.Join(tmpDir, "testdir")
	require.NoError(t, os.Mkdir(dirPath, 0755))

	fileInfo, err := os.Lstat(dirPath)
	require.NoError(t, err)

	a := &Attestor{
		logger: logger.NewNoop(),
	}

	result, err := a.extractSymlinkInfo(dirPath, fileInfo)
	require.NoError(t, err)
	assert.Nil(t, result) // Directories are not symlinks
}
