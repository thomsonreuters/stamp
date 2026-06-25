//go:build darwin

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

// TestOpsInterface verifies that all implementations satisfy the Ops interface.
func TestOpsInterface(t *testing.T) {
	t.Run("darwin implementation", func(t *testing.T) {
		var _ Ops = (*DarwinOps)(nil)
		ops := NewDarwinOps()
		assert.NotNil(t, ops)
	})

	t.Run("factory returns implementation", func(t *testing.T) {
		ops := New()
		assert.NotNil(t, ops, "factory should return non-nil implementation")
	})
}

// TestDarwinOps tests Darwin-specific platform operations.
func TestDarwinOps(t *testing.T) {
	ops := NewDarwinOps()

	t.Run("CheckCircularSymlink with valid directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		fileInfo, err := os.Stat(tmpDir)
		require.NoError(t, err)

		seenDirs := make(map[string]bool)

		isCircular := ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs)
		assert.False(t, isCircular, "first visit should not be circular")

		isCircular = ops.CheckCircularSymlink(tmpDir, fileInfo, seenDirs)
		assert.True(t, isCircular, "second visit should detect circular reference")
	})

	t.Run("CheckFileDuplicate detects hardlinks", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "darwin-file-test-*")
		require.NoError(t, err)
		_ = tmpFile.Close()

		fileInfo, err := os.Stat(tmpFile.Name())
		require.NoError(t, err)

		seenInodes := make(map[string]bool)

		isDuplicate := ops.CheckFileDuplicate(tmpFile.Name(), fileInfo, seenInodes)
		assert.False(t, isDuplicate, "first check should not be duplicate")

		isDuplicate = ops.CheckFileDuplicate(tmpFile.Name(), fileInfo, seenInodes)
		assert.True(t, isDuplicate, "second check should detect duplicate")
	})

	t.Run("ExtractOwnership from file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "darwin-ownership-test-*")
		require.NoError(t, err)
		_ = tmpFile.Close()

		fileInfo, err := os.Stat(tmpFile.Name())
		require.NoError(t, err)

		ownership := ops.ExtractOwnership(tmpFile.Name(), fileInfo)
		require.NotNil(t, ownership, "Darwin should extract ownership")
		assert.GreaterOrEqual(t, ownership.UID, 0, "UID should be non-negative")
		assert.GreaterOrEqual(t, ownership.GID, 0, "GID should be non-negative")
	})

	t.Run("ExtractTimestamps from file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(t.TempDir(), "darwin-timestamp-test-*")
		require.NoError(t, err)
		_ = tmpFile.Close()

		fileInfo, err := os.Stat(tmpFile.Name())
		require.NoError(t, err)

		timestamps := ops.ExtractTimestamps(fileInfo)
		require.NotNil(t, timestamps, "Darwin should extract timestamps")
		assert.False(t, timestamps.Accessed.IsZero(), "access time should be set")
		assert.False(t, timestamps.Modified.IsZero(), "modified time should be set")
		assert.False(t, timestamps.Created.IsZero(), "change time should be set")
	})
}

// TestOpsNilSafety tests that implementations handle nil/invalid inputs gracefully.
func TestOpsNilSafety(t *testing.T) {
	ops := NewDarwinOps()

	assert.NotPanics(t, func() {
		ops.CheckCircularSymlink("/tmp", nil, nil)
		ops.CheckFileDuplicate("/tmp/test", nil, nil)
	})
}
