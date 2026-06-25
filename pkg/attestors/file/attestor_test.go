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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/attestors/file/platform"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/logger"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// TestID verifies the attestor ID is correct.
func TestID(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "file", a.ID())
}

// TestName verifies the attestor name is correct.
func TestName(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "File/Folder Attestor", a.Name())
}

// TestDescription verifies the attestor description is correct.
func TestDescription(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, "Captures file and directory hashes and metadata for artifact provenance", a.Description())
}

// TestPredicateURI verifies the predicate URI is correct.
func TestPredicateURI(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	assert.Equal(t, filepredicate.PredicateURI, a.PredicateURI())
}

// TestConfigSchema verifies config schema is returned correctly.
func TestConfigSchema(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	schema := a.ConfigSchema()

	assert.NotEmpty(t, schema)

	// Verify required fields are present
	fieldNames := make(map[string]bool)
	for _, field := range schema {
		fieldNames[field.Name] = true
	}

	requiredFields := []string{
		"paths", "base-path", "exclude-patterns", "include-patterns",
		"follow-symlinks", "hash-algorithms", "recursive", "max-depth",
		"capture-permissions", "capture-ownership", "capture-timestamps",
		"deduplicate", "error-on-missing", "normalize-paths",
		"subject-mode", "subject-include", "size-warning-threshold",
	}

	for _, field := range requiredFields {
		assert.True(t, fieldNames[field], "Expected field %s to be present in schema", field)
	}
}

// TestParseConfig verifies configuration parsing.
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         core.Config
		expectedConfig Config
	}{
		{
			name: "default_values",
			config: core.Config{
				"paths": []string{"/tmp/test"},
			},
			expectedConfig: Config{
				BasePath:             ".",
				Paths:                []string{"/tmp/test"},
				ExcludePatterns:      []string{},
				IncludePatterns:      []string{"**"},
				FollowSymlinks:       false,
				HashAlgorithms:       []string{"sha256"},
				CapturePermissions:   true,
				CaptureOwnership:     false,
				CaptureTimestamps:    false,
				Recursive:            true,
				MaxDepth:             -1,
				Deduplicate:          true,
				ErrorOnMissing:       false,
				NormalizePaths:       true,
				SubjectMode:          "manifest-only",
				SubjectInclude:       []string{},
				SizeWarningThreshold: defaultSizeWarningThreshold,
			},
		},
		{
			name: "custom_values",
			config: core.Config{
				"paths":                  []string{"/tmp/test"},
				"base-path":              "/workspace",
				"exclude-patterns":       []string{"**/.git/**"},
				"include-patterns":       []string{"**/*.go"},
				"follow-symlinks":        true,
				"hash-algorithms":        []string{"SHA256", "SHA512"},
				"capture-permissions":    false,
				"capture-ownership":      true,
				"capture-timestamps":     true,
				"recursive":              false,
				"max-depth":              5,
				"deduplicate":            false,
				"error-on-missing":       true,
				"normalize-paths":        false,
				"subject-mode":           "all-files",
				"subject-include":        []string{"bin/**"},
				"size-warning-threshold": int64(20971520),
			},
			expectedConfig: Config{
				BasePath:             "/workspace",
				Paths:                []string{"/tmp/test"},
				ExcludePatterns:      []string{"**/.git/**"},
				IncludePatterns:      []string{"**/*.go"},
				FollowSymlinks:       true,
				HashAlgorithms:       []string{"sha256", "sha512"},
				CapturePermissions:   false,
				CaptureOwnership:     true,
				CaptureTimestamps:    true,
				Recursive:            false,
				MaxDepth:             5,
				Deduplicate:          false,
				ErrorOnMissing:       true,
				NormalizePaths:       false,
				SubjectMode:          "all-files",
				SubjectInclude:       []string{"bin/**"},
				SizeWarningThreshold: 20971520,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{logger: logger.NewNoop()}
			a.parseConfig(tt.config)

			assert.Equal(t, tt.expectedConfig.BasePath, a.config.BasePath)
			assert.Equal(t, tt.expectedConfig.Paths, a.config.Paths)
			assert.Equal(t, tt.expectedConfig.ExcludePatterns, a.config.ExcludePatterns)
			assert.Equal(t, tt.expectedConfig.IncludePatterns, a.config.IncludePatterns)
			assert.Equal(t, tt.expectedConfig.FollowSymlinks, a.config.FollowSymlinks)
			assert.Equal(t, tt.expectedConfig.HashAlgorithms, a.config.HashAlgorithms)
			assert.Equal(t, tt.expectedConfig.CapturePermissions, a.config.CapturePermissions)
			assert.Equal(t, tt.expectedConfig.CaptureOwnership, a.config.CaptureOwnership)
			assert.Equal(t, tt.expectedConfig.CaptureTimestamps, a.config.CaptureTimestamps)
			assert.Equal(t, tt.expectedConfig.Recursive, a.config.Recursive)
			assert.Equal(t, tt.expectedConfig.MaxDepth, a.config.MaxDepth)
			assert.Equal(t, tt.expectedConfig.Deduplicate, a.config.Deduplicate)
			assert.Equal(t, tt.expectedConfig.ErrorOnMissing, a.config.ErrorOnMissing)
			assert.Equal(t, tt.expectedConfig.NormalizePaths, a.config.NormalizePaths)
			assert.Equal(t, tt.expectedConfig.SubjectMode, a.config.SubjectMode)
			assert.Equal(t, tt.expectedConfig.SubjectInclude, a.config.SubjectInclude)
			assert.Equal(t, tt.expectedConfig.SizeWarningThreshold, a.config.SizeWarningThreshold)
		})
	}
}

// TestPreAttest verifies the pre-attestation setup.
func TestPreAttest(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	tests := []struct {
		name        string
		config      core.Config
		setupMock   func(*hash.MockHasher)
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful_setup",
			config: core.Config{
				"paths":           []string{testFile},
				"base-path":       tmpDir,
				"hash-algorithms": []string{"sha256"},
			},
			setupMock:   func(m *hash.MockHasher) {},
			expectError: false,
		},
		{
			name: "invalid_base_path",
			config: core.Config{
				"paths":     []string{testFile},
				"base-path": string([]byte{0}), // Invalid path character
			},
			setupMock:   func(m *hash.MockHasher) {},
			expectError: true,
		},
		{
			name: "missing_required_path",
			config: core.Config{
				"paths":            []string{filepath.Join(tmpDir, "nonexistent.txt")},
				"base-path":        tmpDir,
				"error-on-missing": true,
			},
			setupMock:   func(m *hash.MockHasher) {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHasher := hash.NewMockHasher()
			tt.setupMock(mockHasher)

			a := &Attestor{
				logger:      logger.NewNoop(),
				platformOps: platform.New(),
				hasher:      mockHasher,
			}

			err := a.PreAttest(context.Background(), tt.config)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, a.hasher)
			}
		})
	}
}

// TestAttest verifies the attestation collection process.
func TestAttest(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	tests := []struct {
		name        string
		setupAttest func(*Attestor)
		expectError bool
	}{
		{
			name: "successful_collection",
			setupAttest: func(a *Attestor) {
				a.config.BasePath = tmpDir
				a.config.Paths = []string{testFile}
				a.config.HashAlgorithms = []string{"sha256"}
				a.config.FollowSymlinks = false
				a.config.Recursive = true
				a.config.MaxDepth = -1
				a.config.ExcludePatterns = []string{}
				a.config.IncludePatterns = []string{"**"}
				a.config.Deduplicate = true

				mockHasher := hash.NewMockHasher()
				mockHasher.On("HashFile", context.Background(), testFile).Return(
					hash.Result{
						Path:    testFile,
						Digests: map[string]string{"sha256": "abc123"},
						Size:    12,
					}, nil)
				a.hasher = mockHasher
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Attestor{
				logger:      logger.NewNoop(),
				platformOps: platform.New(),
			}
			tt.setupAttest(a)

			err := a.Attest(context.Background(), core.Config{})

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotZero(t, a.captureTime)
				assert.GreaterOrEqual(t, a.duration, time.Duration(0))
			}
		})
	}
}

// TestPostAttest verifies post-attestation cleanup.
func TestPostAttest(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	err := a.PostAttest(context.Background(), core.Config{})
	assert.NoError(t, err)
}

// TestGeneratePredicate verifies predicate generation.
func TestGeneratePredicate(t *testing.T) {
	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			BasePath:           "/workspace",
			HashAlgorithms:     []string{"sha256"},
			CapturePermissions: true,
			CaptureTimestamps:  false,
			CaptureOwnership:   false,
			ExcludePatterns:    []string{"**/.git/**"},
			IncludePatterns:    []string{"**"},
			FollowSymlinks:     false,
		},
		artifacts: []filepredicate.ArtifactInfo{
			{
				Path: "/workspace/test.txt",
				Digests: map[string]string{
					"sha256": "abc123",
				},
				Size: 100,
			},
		},
		directories:      []filepredicate.DirectoryInfo{},
		totalFiles:       1,
		totalDirectories: 0,
		totalSize:        100,
	}

	pred, err := a.GeneratePredicate(core.Config{})
	require.NoError(t, err)
	assert.NotNil(t, pred)

	filePred, ok := pred.(filepredicate.Predicate)
	assert.True(t, ok)
	assert.Equal(t, "/workspace", filePred.AttestorConfig.BasePath)
	assert.Len(t, filePred.Artifacts, 1)
	assert.Equal(t, 1, filePred.Summary.TotalFiles)
}

// TestSubjects verifies subject generation in different modes.
func TestSubjects(t *testing.T) {
	tests := []struct {
		name           string
		subjectMode    string
		subjectInclude []string
		artifacts      []filepredicate.ArtifactInfo
		expectedCount  int
		checkManifest  bool
	}{
		{
			name:        "manifest_only",
			subjectMode: "manifest-only",
			artifacts: []filepredicate.ArtifactInfo{
				{Path: "test1.txt", Digests: map[string]string{"sha256": "abc"}},
				{Path: "test2.txt", Digests: map[string]string{"sha256": "def"}},
			},
			expectedCount: 1,
			checkManifest: true,
		},
		{
			name:        "all_files",
			subjectMode: "all-files",
			artifacts: []filepredicate.ArtifactInfo{
				{Path: "test1.txt", Digests: map[string]string{"sha256": "abc"}},
				{Path: "test2.txt", Digests: map[string]string{"sha256": "def"}},
			},
			expectedCount: 3, // manifest + 2 files
			checkManifest: true,
		},
		{
			name:           "hybrid_with_includes",
			subjectMode:    "hybrid",
			subjectInclude: []string{"**/*.txt"},
			artifacts: []filepredicate.ArtifactInfo{
				{Path: "test1.txt", Digests: map[string]string{"sha256": "abc"}},
				{Path: "test2.go", Digests: map[string]string{"sha256": "def"}},
			},
			expectedCount: 2, // manifest + 1 matching file
			checkManifest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHasher := hash.NewMockHasher()
			mockHasher.On("HashBytes", context.Background(), mock.Anything, "manifest").Return(
				hash.Result{
					Digests: map[string]string{"sha256": "manifestHash"},
				}, nil).Maybe()

			a := &Attestor{
				logger:    logger.NewNoop(),
				hasher:    mockHasher,
				artifacts: tt.artifacts,
				config: Config{
					BasePath:       "/workspace",
					HashAlgorithms: []string{"sha256"},
					SubjectMode:    tt.subjectMode,
					SubjectInclude: tt.subjectInclude,
				},
			}

			subjects := a.Subjects(core.Config{})
			assert.Len(t, subjects, tt.expectedCount)

			if tt.checkManifest {
				assert.Contains(t, subjects[0].Name, "file-manifest+")
			}
		})
	}
}

// TestGenerateHybridSubjects verifies hybrid subject generation.
func TestGenerateHybridSubjects(t *testing.T) {
	a := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			SubjectInclude: []string{"**/*.txt"},
		},
		artifacts: []filepredicate.ArtifactInfo{
			{Path: "test1.txt", Digests: map[string]string{"sha256": "abc"}},
			{Path: "test2.go", Digests: map[string]string{"sha256": "def"}},
			{Path: "test3.txt", Digests: map[string]string{"sha256": "ghi"}},
		},
	}

	subjects := a.generateHybridSubjects()
	assert.Len(t, subjects, 2)
	assert.Equal(t, "test1.txt", subjects[0].Name)
	assert.Equal(t, "test3.txt", subjects[1].Name)
}

// TestGenerateAllFileSubjects verifies all-files subject generation.
func TestGenerateAllFileSubjects(t *testing.T) {
	a := &Attestor{
		logger: logger.NewNoop(),
		artifacts: []filepredicate.ArtifactInfo{
			{Path: "z.txt", Digests: map[string]string{"sha256": "abc"}},
			{Path: "a.txt", Digests: map[string]string{"sha256": "def"}},
			{Path: "m.txt", Digests: map[string]string{"sha256": "ghi"}},
		},
	}

	subjects := a.generateAllFileSubjects()
	assert.Len(t, subjects, 3)
	// Verify sorted order
	assert.Equal(t, "a.txt", subjects[0].Name)
	assert.Equal(t, "m.txt", subjects[1].Name)
	assert.Equal(t, "z.txt", subjects[2].Name)
}

// TestSchema verifies schema generation.
func TestSchema(t *testing.T) {
	a := &Attestor{logger: logger.NewNoop()}
	schema := a.Schema()

	assert.NotNil(t, schema)
	assert.Equal(t, "File Attestation", schema.Title)
	// Schema ID is generated by jsonschema and contains the package path
	assert.Contains(t, schema.ID.String(), "github.com/thomsonreuters/stamp/pkg/predicates/file/v1")
}
