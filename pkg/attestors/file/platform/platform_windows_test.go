//go:build windows

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

package platform

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWindowsOps tests Windows-specific platform operations (only runs on Windows).
func TestWindowsOps(t *testing.T) {
	ops := NewWindowsOps()

	t.Run("CheckCircularSymlink with path tracking", func(t *testing.T) {
		tmpDir := t.TempDir()

		fileInfo, err := os.Stat(tmpDir)
		require.NoError(t, err)

		seenDirs := make(map[string]bool)

		isCircular := ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs)
		assert.False(t, isCircular, "first visit should not be circular")

		isCircular = ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs)
		assert.True(t, isCircular, "second visit should detect circular reference")
	})

	t.Run("CheckFileDuplicate with file index tracking", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "windows-file-test-*")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		fileInfo, err := os.Stat(tmpFile.Name())
		require.NoError(t, err)

		seenInodes := make(map[string]bool)

		isDuplicate := ops.CheckFileDuplicate(tmpFile.Name(), fileInfo, seenInodes)
		assert.False(t, isDuplicate, "first check should not find duplicate")

		isDuplicate = ops.CheckFileDuplicate(tmpFile.Name(), fileInfo, seenInodes)
		assert.True(t, isDuplicate, "second check should detect duplicate")
	})

	t.Run("ExtractOwnership from file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "windows-ownership-test-*")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		fileInfo, err := os.Stat(tmpFile.Name())
		require.NoError(t, err)

		ownership := ops.ExtractOwnership(tmpFile.Name(), fileInfo)
		// On Windows, ownership extraction should now work and return SIDs
		if ownership != nil {
			assert.NotEmpty(t, ownership.User, "Owner SID should not be empty")
			assert.Contains(t, ownership.User, "S-1-", "Owner should be a SID string")
		}
	})

	t.Run("ExtractTimestamps from file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "windows-timestamp-test-*")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		fileInfo, err := os.Stat(tmpFile.Name())
		require.NoError(t, err)

		timestamps := ops.ExtractTimestamps(fileInfo)
		if timestamps != nil {
			assert.False(t, timestamps.Created.IsZero(), "creation time should be set on Windows")
			assert.False(t, timestamps.Modified.IsZero(), "modified time should be set")
			assert.False(t, timestamps.Accessed.IsZero(), "access time should be set")
		}
	})

	t.Run("shared state through seenDirInodes map", func(t *testing.T) {
		ops := NewWindowsOps()

		tmpDir := t.TempDir()

		fileInfo, err := os.Stat(tmpDir)
		require.NoError(t, err)

		seenDirs := make(map[string]bool)

		// First check should not detect circular reference
		isCircular := ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs)
		assert.False(t, isCircular, "first check should not detect circular reference")
		assert.Len(t, seenDirs, 1, "map should contain one entry")

		// Second check with same map should detect circular reference
		isCircular = ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs)
		assert.True(t, isCircular, "second check should detect circular reference via shared map")
	})

	t.Run("separate maps maintain independent state", func(t *testing.T) {
		ops := NewWindowsOps()

		tmpDir := t.TempDir()

		fileInfo, err := os.Stat(tmpDir)
		require.NoError(t, err)

		seenDirs1 := make(map[string]bool)
		seenDirs2 := make(map[string]bool)

		// Check with first map
		ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs1)

		// Check with different map should not detect circular reference
		isCircular := ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs2)
		assert.False(t, isCircular, "different maps should maintain independent state")
	})
}
