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

package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/file/v1", PredicateURI)
}

func TestPredicate_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := Predicate{
		AttestorConfig: AttestorConfig{
			BasePath:           "/workspace",
			FollowSymlinks:     false,
			HashAlgorithms:     []string{"sha256", "sha512"},
			CapturePermissions: true,
			CaptureTimestamps:  true,
			CaptureOwnership:   true,
			ExcludePatterns:    []string{"*.log", ".git/**"},
			IncludePatterns:    []string{"**/*.go"},
		},
		Artifacts: []ArtifactInfo{
			{
				Path: "main.go",
				Type: "file",
				Size: 1024,
				Digests: map[string]string{
					"sha256": "abc123",
					"sha512": "def456",
				},
				Permissions: &PermissionInfo{
					Mode:     "0644",
					Symbolic: "-rw-r--r--",
				},
				Ownership: &OwnershipInfo{
					UID:   1000,
					GID:   1000,
					User:  "developer",
					Group: "staff",
				},
				Timestamps: &TimestampInfo{
					Modified: now,
					Accessed: now,
					Created:  now,
				},
			},
		},
		Directories: []DirectoryInfo{
			{
				Path: "pkg",
				Type: "directory",
				Permissions: &PermissionInfo{
					Mode:     "0755",
					Symbolic: "drwxr-xr-x",
				},
				FileCount:      10,
				DirectoryCount: 2,
			},
		},
		Summary: Summary{
			TotalFiles:       50,
			TotalDirectories: 5,
			TotalSize:        102400,
			CaptureTime:      now,
			Duration:         "1.234s",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "attestor_config")
	assert.Contains(t, string(data), "artifacts")
	assert.Contains(t, string(data), "directories")
	assert.Contains(t, string(data), "summary")
}

func TestPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"attestor_config": {
			"base_path": "/test",
			"follow_symlinks": true,
			"hash_algorithms": ["sha256"],
			"capture_permissions": false,
			"capture_timestamps": false,
			"capture_ownership": false
		},
		"artifacts": [
			{
				"path": "file.txt",
				"type": "file",
				"size": 512,
				"digests": {
					"sha256": "hash123"
				}
			}
		],
		"summary": {
			"total_files": 1,
			"total_directories": 0,
			"total_size": 512,
			"capture_time": "2025-11-12T10:00:00Z",
			"duration": "0.5s"
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "/test", predicate.AttestorConfig.BasePath)
	assert.True(t, predicate.AttestorConfig.FollowSymlinks)
	assert.Len(t, predicate.Artifacts, 1)
	assert.Equal(t, "file.txt", predicate.Artifacts[0].Path)
	assert.Equal(t, 1, predicate.Summary.TotalFiles)
}

func TestAttestorConfig_Complete(t *testing.T) {
	config := AttestorConfig{
		BasePath:           "/project",
		FollowSymlinks:     true,
		HashAlgorithms:     []string{"sha256", "sha512", "md5"},
		CapturePermissions: true,
		CaptureTimestamps:  true,
		CaptureOwnership:   true,
		ExcludePatterns:    []string{"node_modules/**", "*.tmp"},
		IncludePatterns:    []string{"src/**/*.js", "test/**/*.js"},
	}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	var result AttestorConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, config.BasePath, result.BasePath)
	assert.True(t, result.FollowSymlinks)
	assert.Len(t, result.HashAlgorithms, 3)
	assert.Len(t, result.ExcludePatterns, 2)
	assert.Len(t, result.IncludePatterns, 2)
}

func TestAttestorConfig_Minimal(t *testing.T) {
	config := AttestorConfig{
		BasePath:           "/minimal",
		FollowSymlinks:     false,
		HashAlgorithms:     []string{"sha256"},
		CapturePermissions: false,
		CaptureTimestamps:  false,
		CaptureOwnership:   false,
	}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "excludePatterns")
	assert.NotContains(t, string(data), "includePatterns")
}

func TestArtifactInfo_File(t *testing.T) {
	now := time.Now()

	artifact := ArtifactInfo{
		Path: "src/main.go",
		Type: "file",
		Size: 2048,
		Digests: map[string]string{
			"sha256": "abc123def456",
			"sha512": "789012345678",
		},
		Permissions: &PermissionInfo{
			Mode:     "0644",
			Symbolic: "-rw-r--r--",
		},
		Ownership: &OwnershipInfo{
			UID:   1000,
			GID:   1000,
			User:  "user",
			Group: "group",
		},
		Timestamps: &TimestampInfo{
			Modified: now,
			Accessed: now,
			Created:  now,
		},
	}

	data, err := json.Marshal(artifact)
	require.NoError(t, err)

	var result ArtifactInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "file", result.Type)
	assert.Equal(t, int64(2048), result.Size)
	assert.NotNil(t, result.Permissions)
	assert.NotNil(t, result.Ownership)
	assert.NotNil(t, result.Timestamps)
	assert.Nil(t, result.Symlink)
}

func TestArtifactInfo_Symlink(t *testing.T) {
	artifact := ArtifactInfo{
		Path: "link.txt",
		Type: "symlink",
		Size: 0,
		Digests: map[string]string{
			"sha256": "linkdigest",
		},
		Symlink: &SymlinkInfo{
			IsSymlink: true,
			Target:    "/target/file.txt",
		},
	}

	data, err := json.Marshal(artifact)
	require.NoError(t, err)

	var result ArtifactInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "symlink", result.Type)
	assert.Equal(t, int64(0), result.Size)
	assert.NotNil(t, result.Symlink)
	assert.True(t, result.Symlink.IsSymlink)
	assert.Equal(t, "/target/file.txt", result.Symlink.Target)
}

func TestArtifactInfo_OmitEmptyFields(t *testing.T) {
	artifact := ArtifactInfo{
		Path: "simple.txt",
		Type: "file",
		Size: 100,
		Digests: map[string]string{
			"sha256": "simple123",
		},
	}

	data, err := json.Marshal(artifact)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "permissions")
	assert.NotContains(t, string(data), "ownership")
	assert.NotContains(t, string(data), "timestamps")
	assert.NotContains(t, string(data), "symlink")
}

func TestDirectoryInfo_Complete(t *testing.T) {
	dir := DirectoryInfo{
		Path: "src/pkg",
		Type: "directory",
		Permissions: &PermissionInfo{
			Mode:     "0755",
			Symbolic: "drwxr-xr-x",
		},
		FileCount:      15,
		DirectoryCount: 3,
	}

	data, err := json.Marshal(dir)
	require.NoError(t, err)

	var result DirectoryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "directory", result.Type)
	assert.NotNil(t, result.Permissions)
	assert.Equal(t, 15, result.FileCount)
	assert.Equal(t, 3, result.DirectoryCount)
}

func TestDirectoryInfo_OmitEmptyPermissions(t *testing.T) {
	dir := DirectoryInfo{
		Path:           "simple",
		Type:           "directory",
		FileCount:      5,
		DirectoryCount: 1,
	}

	data, err := json.Marshal(dir)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "permissions")
}

func TestPermissionInfo_FilePermissions(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		symbolic string
	}{
		{
			name:     "Read-only",
			mode:     "0444",
			symbolic: "-r--r--r--",
		},
		{
			name:     "Standard file",
			mode:     "0644",
			symbolic: "-rw-r--r--",
		},
		{
			name:     "Executable",
			mode:     "0755",
			symbolic: "-rwxr-xr-x",
		},
		{
			name:     "Private",
			mode:     "0600",
			symbolic: "-rw-------",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := PermissionInfo{
				Mode:     tt.mode,
				Symbolic: tt.symbolic,
			}

			data, err := json.Marshal(perm)
			require.NoError(t, err)

			var result PermissionInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.mode, result.Mode)
			assert.Equal(t, tt.symbolic, result.Symbolic)
		})
	}
}

func TestPermissionInfo_DirectoryPermissions(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		symbolic string
	}{
		{
			name:     "Standard directory",
			mode:     "0755",
			symbolic: "drwxr-xr-x",
		},
		{
			name:     "Private directory",
			mode:     "0700",
			symbolic: "drwx------",
		},
		{
			name:     "Group writable",
			mode:     "0775",
			symbolic: "drwxrwxr-x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := PermissionInfo{
				Mode:     tt.mode,
				Symbolic: tt.symbolic,
			}

			data, err := json.Marshal(perm)
			require.NoError(t, err)

			var result PermissionInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.mode, result.Mode)
			assert.Contains(t, result.Symbolic, "d")
		})
	}
}

func TestOwnershipInfo_WithNames(t *testing.T) {
	owner := OwnershipInfo{
		UID:   1000,
		GID:   1000,
		User:  "developer",
		Group: "staff",
	}

	data, err := json.Marshal(owner)
	require.NoError(t, err)

	var result OwnershipInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, 1000, result.UID)
	assert.Equal(t, 1000, result.GID)
	assert.Equal(t, "developer", result.User)
	assert.Equal(t, "staff", result.Group)
}

func TestOwnershipInfo_WithoutNames(t *testing.T) {
	owner := OwnershipInfo{
		UID: 501,
		GID: 20,
	}

	data, err := json.Marshal(owner)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "user")
	assert.NotContains(t, string(data), "group")
}

func TestOwnershipInfo_Root(t *testing.T) {
	owner := OwnershipInfo{
		UID:   0,
		GID:   0,
		User:  "root",
		Group: "root",
	}

	data, err := json.Marshal(owner)
	require.NoError(t, err)

	var result OwnershipInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, 0, result.UID)
	assert.Equal(t, 0, result.GID)
	assert.Equal(t, "root", result.User)
}

func TestTimestampInfo_AllFields(t *testing.T) {
	modified := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)
	accessed := time.Date(2025, 11, 12, 11, 0, 0, 0, time.UTC)
	created := time.Date(2025, 11, 12, 9, 0, 0, 0, time.UTC)

	ts := TimestampInfo{
		Modified: modified,
		Accessed: accessed,
		Created:  created,
	}

	data, err := json.Marshal(ts)
	require.NoError(t, err)

	var result TimestampInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, modified.Unix(), result.Modified.Unix())
	assert.Equal(t, accessed.Unix(), result.Accessed.Unix())
	assert.Equal(t, created.Unix(), result.Created.Unix())
}

func TestTimestampInfo_ZeroValues(t *testing.T) {
	ts := TimestampInfo{}

	data, err := json.Marshal(ts)
	require.NoError(t, err)

	var result TimestampInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.Modified.IsZero() || result.Modified.Year() == 1)
	assert.True(t, result.Accessed.IsZero() || result.Accessed.Year() == 1)
	assert.True(t, result.Created.IsZero() || result.Created.Year() == 1)
}

func TestSymlinkInfo_Complete(t *testing.T) {
	symlink := SymlinkInfo{
		IsSymlink: true,
		Target:    "../target/file.txt",
	}

	data, err := json.Marshal(symlink)
	require.NoError(t, err)

	var result SymlinkInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.IsSymlink)
	assert.Equal(t, "../target/file.txt", result.Target)
}

func TestSymlinkInfo_AbsolutePath(t *testing.T) {
	symlink := SymlinkInfo{
		IsSymlink: true,
		Target:    "/usr/local/bin/git",
	}

	data, err := json.Marshal(symlink)
	require.NoError(t, err)

	var result SymlinkInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.IsSymlink)
	assert.Contains(t, result.Target, "/usr/local")
}

func TestSymlinkInfo_OmitEmptyTarget(t *testing.T) {
	symlink := SymlinkInfo{
		IsSymlink: false,
	}

	data, err := json.Marshal(symlink)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "target")
}

func TestSummary_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	summary := Summary{
		TotalFiles:       100,
		TotalDirectories: 10,
		TotalSize:        1048576,
		CaptureTime:      now,
		Duration:         "2.345s",
	}

	data, err := json.Marshal(summary)
	require.NoError(t, err)

	var result Summary
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, 100, result.TotalFiles)
	assert.Equal(t, 10, result.TotalDirectories)
	assert.Equal(t, int64(1048576), result.TotalSize)
	assert.Equal(t, "2.345s", result.Duration)
}

func TestSummary_Empty(t *testing.T) {
	now := time.Now()

	summary := Summary{
		TotalFiles:       0,
		TotalDirectories: 0,
		TotalSize:        0,
		CaptureTime:      now,
		Duration:         "0.001s",
	}

	data, err := json.Marshal(summary)
	require.NoError(t, err)

	var result Summary
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, 0, result.TotalFiles)
	assert.Equal(t, 0, result.TotalDirectories)
	assert.Equal(t, int64(0), result.TotalSize)
}

func TestPredicate_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := Predicate{
		AttestorConfig: AttestorConfig{
			BasePath:           "/workspace/project",
			FollowSymlinks:     false,
			HashAlgorithms:     []string{"sha256", "sha512"},
			CapturePermissions: true,
			CaptureTimestamps:  true,
			CaptureOwnership:   true,
			ExcludePatterns:    []string{".git/**", "node_modules/**", "*.log"},
			IncludePatterns:    []string{"**/*.go", "**/*.proto"},
		},
		Artifacts: []ArtifactInfo{
			{
				Path: "main.go",
				Type: "file",
				Size: 1024,
				Digests: map[string]string{
					"sha256": "main-sha256",
					"sha512": "main-sha512",
				},
				Permissions: &PermissionInfo{
					Mode:     "0644",
					Symbolic: "-rw-r--r--",
				},
				Ownership: &OwnershipInfo{
					UID:   1000,
					GID:   1000,
					User:  "dev",
					Group: "staff",
				},
				Timestamps: &TimestampInfo{
					Modified: now,
					Accessed: now,
					Created:  now,
				},
			},
			{
				Path: "link.txt",
				Type: "symlink",
				Size: 0,
				Digests: map[string]string{
					"sha256": "link-sha256",
				},
				Symlink: &SymlinkInfo{
					IsSymlink: true,
					Target:    "target.txt",
				},
			},
		},
		Directories: []DirectoryInfo{
			{
				Path: "pkg",
				Type: "directory",
				Permissions: &PermissionInfo{
					Mode:     "0755",
					Symbolic: "drwxr-xr-x",
				},
				FileCount:      10,
				DirectoryCount: 2,
			},
		},
		Summary: Summary{
			TotalFiles:       25,
			TotalDirectories: 5,
			TotalSize:        51200,
			CaptureTime:      now,
			Duration:         "1.5s",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.AttestorConfig.BasePath, result.AttestorConfig.BasePath)
	assert.Len(t, result.Artifacts, 2)
	assert.Len(t, result.Directories, 1)
	assert.Equal(t, 25, result.Summary.TotalFiles)
}

func TestPredicate_Minimal(t *testing.T) {
	now := time.Now()

	predicate := Predicate{
		AttestorConfig: AttestorConfig{
			BasePath:           "/test",
			FollowSymlinks:     false,
			HashAlgorithms:     []string{"sha256"},
			CapturePermissions: false,
			CaptureTimestamps:  false,
			CaptureOwnership:   false,
		},
		Artifacts: []ArtifactInfo{
			{
				Path: "file.txt",
				Type: "file",
				Size: 100,
				Digests: map[string]string{
					"sha256": "minimal",
				},
			},
		},
		Summary: Summary{
			TotalFiles:       1,
			TotalDirectories: 0,
			TotalSize:        100,
			CaptureTime:      now,
			Duration:         "0.1s",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Artifacts, 1)
	assert.Empty(t, result.Directories)
	assert.Nil(t, result.Artifacts[0].Permissions)
}

func TestArtifactInfo_MultipleDigests(t *testing.T) {
	artifact := ArtifactInfo{
		Path: "test.bin",
		Type: "file",
		Size: 4096,
		Digests: map[string]string{
			"md5":    "md5hash",
			"sha1":   "sha1hash",
			"sha256": "sha256hash",
			"sha512": "sha512hash",
		},
	}

	data, err := json.Marshal(artifact)
	require.NoError(t, err)

	var result ArtifactInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Digests, 4)
	assert.Equal(t, "md5hash", result.Digests["md5"])
	assert.Equal(t, "sha256hash", result.Digests["sha256"])
}

func TestAttestorConfig_HashAlgorithms(t *testing.T) {
	tests := []struct {
		name       string
		algorithms []string
	}{
		{
			name:       "SHA256 only",
			algorithms: []string{"sha256"},
		},
		{
			name:       "Multiple algorithms",
			algorithms: []string{"sha256", "sha512", "md5"},
		},
		{
			name:       "All common algorithms",
			algorithms: []string{"md5", "sha1", "sha256", "sha512"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := AttestorConfig{
				BasePath:           "/test",
				FollowSymlinks:     false,
				HashAlgorithms:     tt.algorithms,
				CapturePermissions: false,
				CaptureTimestamps:  false,
				CaptureOwnership:   false,
			}

			data, err := json.Marshal(config)
			require.NoError(t, err)

			var result AttestorConfig
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.algorithms, result.HashAlgorithms)
		})
	}
}

func TestAttestorConfig_ExcludePatterns(t *testing.T) {
	patterns := []string{
		"*.log",
		"*.tmp",
		".git/**",
		"node_modules/**",
		"**/.DS_Store",
		"**/*.swp",
	}

	config := AttestorConfig{
		BasePath:           "/project",
		FollowSymlinks:     false,
		HashAlgorithms:     []string{"sha256"},
		CapturePermissions: false,
		CaptureTimestamps:  false,
		CaptureOwnership:   false,
		ExcludePatterns:    patterns,
	}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	var result AttestorConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.ExcludePatterns, 6)
	assert.Contains(t, result.ExcludePatterns, "*.log")
	assert.Contains(t, result.ExcludePatterns, ".git/**")
}

func TestDirectoryInfo_NestedStructure(t *testing.T) {
	dirs := []DirectoryInfo{
		{
			Path:           ".",
			Type:           "directory",
			FileCount:      5,
			DirectoryCount: 3,
		},
		{
			Path:           "src",
			Type:           "directory",
			FileCount:      10,
			DirectoryCount: 2,
		},
		{
			Path:           "src/pkg",
			Type:           "directory",
			FileCount:      8,
			DirectoryCount: 0,
		},
	}

	for _, dir := range dirs {
		data, err := json.Marshal(dir)
		require.NoError(t, err)

		var result DirectoryInfo
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, dir.Path, result.Path)
		assert.Equal(t, dir.FileCount, result.FileCount)
		assert.Equal(t, dir.DirectoryCount, result.DirectoryCount)
	}
}

func TestArtifactInfo_LargeFile(t *testing.T) {
	artifact := ArtifactInfo{
		Path: "large.bin",
		Type: "file",
		Size: 10737418240, // 10GB
		Digests: map[string]string{
			"sha256": "largefile256",
		},
	}

	data, err := json.Marshal(artifact)
	require.NoError(t, err)

	var result ArtifactInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, int64(10737418240), result.Size)
}

func TestSummary_LargeProject(t *testing.T) {
	now := time.Now()

	summary := Summary{
		TotalFiles:       10000,
		TotalDirectories: 500,
		TotalSize:        53687091200, // 50GB
		CaptureTime:      now,
		Duration:         "45.678s",
	}

	data, err := json.Marshal(summary)
	require.NoError(t, err)

	var result Summary
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, 10000, result.TotalFiles)
	assert.Equal(t, 500, result.TotalDirectories)
	assert.Equal(t, int64(53687091200), result.TotalSize)
}

func TestTimestampInfo_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"modified":"2025-11-12T10:00:00Z"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"modified":"2025-11-12T10:00:00+05:30"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"modified":"2025-11-12T10:00:00.123456Z"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts TimestampInfo
			err := json.Unmarshal([]byte(tt.jsonTime), &ts)

			if tt.valid {
				require.NoError(t, err)
				assert.False(t, ts.Modified.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestPredicate_MixedArtifacts(t *testing.T) {
	now := time.Now()

	predicate := Predicate{
		AttestorConfig: AttestorConfig{
			BasePath:           "/mixed",
			FollowSymlinks:     false,
			HashAlgorithms:     []string{"sha256"},
			CapturePermissions: true,
			CaptureTimestamps:  false,
			CaptureOwnership:   false,
		},
		Artifacts: []ArtifactInfo{
			{
				Path: "file1.txt",
				Type: "file",
				Size: 100,
				Digests: map[string]string{
					"sha256": "file1",
				},
				Permissions: &PermissionInfo{
					Mode:     "0644",
					Symbolic: "-rw-r--r--",
				},
			},
			{
				Path: "executable",
				Type: "file",
				Size: 200,
				Digests: map[string]string{
					"sha256": "exec",
				},
				Permissions: &PermissionInfo{
					Mode:     "0755",
					Symbolic: "-rwxr-xr-x",
				},
			},
			{
				Path: "link",
				Type: "symlink",
				Size: 0,
				Digests: map[string]string{
					"sha256": "link",
				},
				Symlink: &SymlinkInfo{
					IsSymlink: true,
					Target:    "file1.txt",
				},
			},
		},
		Summary: Summary{
			TotalFiles:       3,
			TotalDirectories: 0,
			TotalSize:        300,
			CaptureTime:      now,
			Duration:         "0.5s",
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Artifacts, 3)
	assert.Equal(t, "file", result.Artifacts[0].Type)
	assert.Equal(t, "file", result.Artifacts[1].Type)
	assert.Equal(t, "symlink", result.Artifacts[2].Type)
}
