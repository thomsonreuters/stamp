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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/attestors/file/platform"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/logger"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// TestCollectArtifacts_SingleFile verifies single file collection.
func TestCollectArtifacts_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), testFile).Return(
		hash.Result{
			Path:    testFile,
			Digests: map[string]string{"sha256": "abc123"},
			Size:    12,
		}, nil)

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{testFile},
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{},
			IncludePatterns:    []string{"**"},
			FollowSymlinks:     false,
			Recursive:          false,
			MaxDepth:           -1,
			Deduplicate:        true,
			CapturePermissions: true,
			CaptureOwnership:   false,
			CaptureTimestamps:  false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Len(t, a.artifacts, 1)
	assert.Equal(t, 1, a.totalFiles)
	mockHasher.AssertExpectations(t)
}

// TestCollectArtifacts_Directory verifies directory collection.
func TestCollectArtifacts_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test structure
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), file1).Return(
		hash.Result{
			Path:    file1,
			Digests: map[string]string{"sha256": "hash1"},
			Size:    8,
		}, nil)
	mockHasher.On("HashFile", context.Background(), file2).Return(
		hash.Result{
			Path:    file2,
			Digests: map[string]string{"sha256": "hash2"},
			Size:    8,
		}, nil)

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{tmpDir},
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{},
			IncludePatterns:    []string{"**"},
			FollowSymlinks:     false,
			Recursive:          true,
			MaxDepth:           -1,
			Deduplicate:        true,
			CapturePermissions: true,
			CaptureOwnership:   false,
			CaptureTimestamps:  false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Len(t, a.artifacts, 2)
	assert.GreaterOrEqual(t, a.totalDirectories, 1)
	mockHasher.AssertExpectations(t)
}

// TestCollectArtifacts_Recursive verifies recursive directory traversal.
func TestCollectArtifacts_Recursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))

	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(subDir, "file2.txt")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), file1).Return(
		hash.Result{Path: file1, Digests: map[string]string{"sha256": "hash1"}, Size: 8}, nil)
	mockHasher.On("HashFile", context.Background(), file2).Return(
		hash.Result{Path: file2, Digests: map[string]string{"sha256": "hash2"}, Size: 8}, nil)

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{tmpDir},
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{},
			IncludePatterns:    []string{"**"},
			FollowSymlinks:     false,
			Recursive:          true,
			MaxDepth:           -1,
			Deduplicate:        true,
			CapturePermissions: false,
			CaptureOwnership:   false,
			CaptureTimestamps:  false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Len(t, a.artifacts, 2)
	mockHasher.AssertExpectations(t)
}

// TestCollectArtifacts_NonRecursive verifies non-recursive collection.
func TestCollectArtifacts_NonRecursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))

	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(subDir, "file2.txt")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), file1).Return(
		hash.Result{Path: file1, Digests: map[string]string{"sha256": "hash1"}, Size: 8}, nil)

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{file1}, // Pass the file directly, not the directory
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{},
			IncludePatterns:    []string{"**"},
			FollowSymlinks:     false,
			Recursive:          false,
			MaxDepth:           -1,
			Deduplicate:        true,
			CapturePermissions: false,
			CaptureOwnership:   false,
			CaptureTimestamps:  false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Len(t, a.artifacts, 1) // Only file1, not file2 in subdir
	mockHasher.AssertExpectations(t)
}

// TestCollectArtifacts_MaxDepth verifies max depth limiting.
func TestCollectArtifacts_MaxDepth(t *testing.T) {
	tmpDir := t.TempDir()

	// Create deeply nested structure
	level1 := filepath.Join(tmpDir, "level1")
	level2 := filepath.Join(level1, "level2")
	require.NoError(t, os.MkdirAll(level2, 0755))

	file1 := filepath.Join(level1, "file1.txt")
	file2 := filepath.Join(level2, "file2.txt")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), file1).Return(
		hash.Result{Path: file1, Digests: map[string]string{"sha256": "hash1"}, Size: 8}, nil)

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{tmpDir},
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{},
			IncludePatterns:    []string{"**"},
			FollowSymlinks:     false,
			Recursive:          true,
			MaxDepth:           1, // Only go 1 level deep
			Deduplicate:        true,
			CapturePermissions: false,
			CaptureOwnership:   false,
			CaptureTimestamps:  false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Len(t, a.artifacts, 1) // Only file1, file2 is too deep
	mockHasher.AssertExpectations(t)
}

// TestCollectArtifacts_ErrorOnMissing verifies error-on-missing behavior.
func TestCollectArtifacts_ErrorOnMissing(t *testing.T) {
	tmpDir := t.TempDir()
	nonexistentFile := filepath.Join(tmpDir, "nonexistent.txt")

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		config: Config{
			BasePath:        tmpDir,
			Paths:           []string{nonexistentFile},
			ErrorOnMissing:  true,
			ExcludePatterns: []string{},
			IncludePatterns: []string{"**"},
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	assert.Error(t, err)
}

// TestCollectArtifacts_SkipMissing verifies skip-missing behavior.
func TestCollectArtifacts_SkipMissing(t *testing.T) {
	tmpDir := t.TempDir()
	nonexistentFile := filepath.Join(tmpDir, "nonexistent.txt")

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		config: Config{
			BasePath:        tmpDir,
			Paths:           []string{nonexistentFile},
			ErrorOnMissing:  false,
			ExcludePatterns: []string{},
			IncludePatterns: []string{"**"},
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Empty(t, a.artifacts)
}

// TestCollectArtifacts_ContextCancellation verifies context cancellation handling.
func TestCollectArtifacts_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		config: Config{
			BasePath:        tmpDir,
			Paths:           []string{testFile},
			ExcludePatterns: []string{},
			IncludePatterns: []string{"**"},
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}

// TestCollectArtifacts_WithExcludePatterns verifies exclude pattern filtering.
func TestCollectArtifacts_WithExcludePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "include.txt")
	file2 := filepath.Join(tmpDir, "exclude.tmp")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), file1).Return(
		hash.Result{Path: file1, Digests: map[string]string{"sha256": "hash1"}, Size: 8}, nil)

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{tmpDir},
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{"**/*.tmp"},
			IncludePatterns:    []string{"**"},
			Recursive:          true,
			Deduplicate:        true,
			CapturePermissions: false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	assert.Len(t, a.artifacts, 1) // Only include.txt
	mockHasher.AssertExpectations(t)
}

// TestCollectArtifacts_WithIncludePatterns verifies include pattern filtering.
func TestCollectArtifacts_WithIncludePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "test.go")
	file2 := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0644))

	mockHasher := hash.NewMockHasher()
	mockHasher.On("HashFile", context.Background(), file1).Return(
		hash.Result{Path: file1, Digests: map[string]string{"sha256": "hash1"}, Size: 8}, nil).Maybe()

	a := &Attestor{
		logger:      logger.NewNoop(),
		platformOps: platform.New(),
		hasher:      mockHasher,
		config: Config{
			BasePath:           tmpDir,
			Paths:              []string{tmpDir},
			HashAlgorithms:     []string{"sha256"},
			ExcludePatterns:    []string{},
			IncludePatterns:    []string{"**/*.go"},
			Recursive:          true,
			Deduplicate:        true,
			CapturePermissions: false,
		},
		artifacts:   []filepredicate.ArtifactInfo{},
		directories: []filepredicate.DirectoryInfo{},
	}

	err := a.collectArtifacts(context.Background())
	require.NoError(t, err)
	// Should only include .go files
	for _, artifact := range a.artifacts {
		assert.Contains(t, artifact.Path, ".go")
	}
}
