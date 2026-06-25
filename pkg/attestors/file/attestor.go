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

// Package file provides comprehensive file and directory attestation for generating
// file-specific attestation predicates. It captures cryptographic hashes, metadata,
// and directory structures for artifact provenance tracking.
//
// The attestor uses a custom predicate type (https://github.com/thomsonreuters/stamp/file/v1)
// specifically designed for file artifact attestations, supporting both Material and Product
// attestation patterns as used in Witness and in-toto frameworks.
//
// The attestor supports various configuration options for controlling information
// collection depth and provides robust filtering capabilities for managing large
// directory structures.
//
// Key features:
//   - Multi-algorithm file hashing (SHA256, SHA512, BLAKE3, SHA-3/Keccak)
//   - Flexible include/exclude pattern matching with gitignore syntax
//   - Comprehensive metadata capture (permissions, ownership, timestamps, xattrs)
//   - Symlink handling (follow or record as symlink)
//   - Configurable subject generation (manifest-only, hybrid, all-files modes)
//   - Parallel file hashing for performance
//   - Security-focused path validation and traversal protection

package file

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/attestors/file/platform"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

const (
	id          = "file"
	name        = "File/Folder Attestor"
	description = "Captures file and directory hashes and metadata for artifact provenance"
)

const (
	subjectModeManifestOnly = "manifest-only"
	subjectModeHybrid       = "hybrid"
	subjectModeAllFiles     = "all-files"

	defaultSizeWarningThreshold = 15728640 // 15MB
)

var (
	validSubjectModes   = []string{subjectModeManifestOnly, subjectModeHybrid, subjectModeAllFiles}
	validHashAlgorithms = hash.SupportedAlgorithms
)

// Config holds the configuration for the file attestor.
type Config struct {
	// Path Configuration
	BasePath string
	Paths    []string

	// Filtering Configuration
	ExcludePatterns []string
	IncludePatterns []string

	// Symlink Handling
	FollowSymlinks bool

	// Hashing Configuration
	HashAlgorithms []string

	// Traversal Configuration
	Recursive bool
	MaxDepth  int

	// Metadata Capture Flags
	CapturePermissions bool
	CaptureOwnership   bool
	CaptureTimestamps  bool

	// Behavior Flags
	Deduplicate    bool
	ErrorOnMissing bool
	NormalizePaths bool

	// Subject Configuration
	SubjectMode          string
	SubjectInclude       []string
	SizeWarningThreshold int64
}

func init() {
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			platformOps: platform.New(),
			logger:      log.With("attestor_id", id),
		}
	})
}

type Attestor struct {
	platformOps platform.Ops
	hasher      hash.Hasher
	logger      logger.Logger
	config      Config

	artifacts        []filepredicate.ArtifactInfo
	directories      []filepredicate.DirectoryInfo
	totalSize        int64
	totalFiles       int
	totalDirectories int
	captureTime      time.Time
	duration         time.Duration
}

func (a *Attestor) ID() string           { return id }
func (a *Attestor) PredicateURI() string { return filepredicate.PredicateURI }
func (a *Attestor) Name() string         { return name }
func (a *Attestor) Description() string  { return description }

func (a *Attestor) ValidateConfig(config core.Config) error {
	return a.validateConfig(config)
}

func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		// Path Configuration
		{
			Name:        "paths",
			Type:        "[]string",
			Default:     nil,
			Required:    true,
			Description: "List of file paths or directory paths to attest (absolute or relative to base-path)",
			Example:     []string{"src/", "bin/exampleapp", "*.jar"},
		},
		{
			Name:        "base-path",
			Type:        "string",
			Default:     ".",
			Required:    false,
			Description: "Base directory from which relative paths are resolved",
			Example:     "/workspace",
		},

		// Filtering Configuration
		{
			Name:        "exclude-patterns",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Glob patterns for files/folders to exclude (gitignore syntax)",
			Example:     []string{"**/.git/**", "**/node_modules/**", "**/*.tmp"},
		},
		{
			Name:        "include-patterns",
			Type:        "[]string",
			Default:     []string{"**"},
			Required:    false,
			Description: "Glob patterns for files to explicitly include (evaluated after exclusions)",
			Example:     []string{"**/*.go", "**/*.java"},
		},

		// Symlink Handling
		{
			Name:        "follow-symlinks",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Whether to follow symbolic links or record them as symlinks",
			Example:     true,
		},

		// Hashing Configuration
		{
			Name:        "hash-algorithms",
			Type:        "[]string",
			Default:     []string{hash.AlgorithmSHA256},
			Required:    false,
			Description: "Cryptographic hash algorithms to use (sha256, sha512, blake3, sha3-256, sha3-512)",
			Example:     []string{hash.AlgorithmSHA256, hash.AlgorithmSHA512, hash.AlgorithmBLAKE3},
		},

		// Traversal Configuration
		{
			Name:        "recursive",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Whether to recursively traverse directories",
			Example:     false,
		},
		{
			Name:        "max-depth",
			Type:        "int",
			Default:     -1,
			Required:    false,
			Description: "Maximum directory traversal depth (-1 = unlimited)",
			Example:     3,
		},

		// Metadata Capture Flags
		{
			Name:        "capture-permissions",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Record Unix file permissions (mode bits)",
			Example:     false,
		},
		{
			Name:        "capture-ownership",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Record file owner UID/GID and names (may not be portable)",
			Example:     true,
		},
		{
			Name:        "capture-timestamps",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Record modification, access, and change times (reduces reproducibility)",
			Example:     true,
		},

		// Behavior Flags
		{
			Name:        "deduplicate",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "If multiple paths reference the same inode, record only once",
			Example:     false,
		},
		{
			Name:        "error-on-missing",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Fail if any specified path doesn't exist (if false, missing paths are logged but not failed)",
			Example:     true,
		},
		{
			Name:        "normalize-paths",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Convert paths to forward slashes and resolve . and .. for cross-platform compatibility",
			Example:     false,
		},

		// Subject Configuration
		{
			Name:        "subject-mode",
			Type:        "string",
			Default:     subjectModeManifestOnly,
			Required:    false,
			Description: "How to generate in-toto subjects: 'manifest-only' (single manifest digest), 'hybrid' (manifest + selected files), 'all-files' (every file as subject)",
			Example:     subjectModeHybrid,
		},
		{
			Name:        "subject-include",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Patterns for files to include as individual subjects (only used when subject-mode is 'hybrid')",
			Example:     []string{"bin/**", "*.jar", "dist/*.exe"},
		},

		// Performance/Size Configuration
		{
			Name:        "size-warning-threshold",
			Type:        "int",
			Default:     defaultSizeWarningThreshold,
			Required:    false,
			Description: "Attestation size in bytes above which to emit a warning (default: 15MB). Set to 0 to disable warnings.",
			Example:     20971520, // 20MB
		},
	}
}

func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		BasePath:             config.GetString("base-path", "."),
		Paths:                config.GetStringSlice("paths"),
		ExcludePatterns:      config.GetStringSlice("exclude-patterns"),
		IncludePatterns:      config.GetStringSlice("include-patterns"),
		FollowSymlinks:       config.GetBool("follow-symlinks", false),
		HashAlgorithms:       config.GetStringSlice("hash-algorithms"),
		CapturePermissions:   config.GetBool("capture-permissions", true),
		CaptureOwnership:     config.GetBool("capture-ownership", false),
		CaptureTimestamps:    config.GetBool("capture-timestamps", false),
		Recursive:            config.GetBool("recursive", true),
		MaxDepth:             config.GetInt("max-depth", -1),
		Deduplicate:          config.GetBool("deduplicate", true),
		ErrorOnMissing:       config.GetBool("error-on-missing", false),
		NormalizePaths:       config.GetBool("normalize-paths", true),
		SubjectMode:          config.GetString("subject-mode", subjectModeManifestOnly),
		SubjectInclude:       config.GetStringSlice("subject-include"),
		SizeWarningThreshold: config.GetInt64("size-warning-threshold", defaultSizeWarningThreshold),
	}

	if len(a.config.IncludePatterns) == 0 {
		a.config.IncludePatterns = []string{"**"}
	}
	if len(a.config.HashAlgorithms) == 0 {
		a.config.HashAlgorithms = []string{hash.AlgorithmSHA256}
	}

	for i, alg := range a.config.HashAlgorithms {
		a.config.HashAlgorithms[i] = strings.ToLower(alg)
	}
}

func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.logger.InfoContext(ctx, "starting file attestor pre-attestation setup")

	a.parseConfig(config)

	if a.hasher == nil {
		a.hasher = hash.New(hash.Config{
			Algorithms: a.config.HashAlgorithms,
			BufferSize: hash.DefaultBufferSize,
		})
	}

	absBasePath, err := filepath.Abs(a.config.BasePath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "pre-attest", "failed to resolve base path")
	}
	a.config.BasePath = absBasePath

	if err := a.validateAndResolvePaths(); err != nil {
		return err
	}

	a.logger.InfoContext(ctx, "file attestor pre-attestation setup completed",
		"base_path", a.config.BasePath,
		"path_count", len(a.config.Paths),
		"hash_algorithms", a.config.HashAlgorithms,
		"duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	start := time.Now()
	a.captureTime = start

	a.logger.InfoContext(ctx, "starting file attestation collection", "base_path", a.config.BasePath)

	a.artifacts = []filepredicate.ArtifactInfo{}
	a.directories = []filepredicate.DirectoryInfo{}
	a.totalSize = 0
	a.totalFiles = 0
	a.totalDirectories = 0

	if err := a.collectArtifacts(ctx); err != nil {
		a.logger.ErrorContext(ctx, "artifact collection failed", "error", err.Error())
		return err
	}

	a.duration = time.Since(start)

	a.logger.InfoContext(ctx, "file attestation collection completed",
		"total_files", a.totalFiles,
		"total_directories", a.totalDirectories,
		"total_size_bytes", a.totalSize,
		"duration_ms", a.duration.Milliseconds())

	return nil
}

func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	if a.config.SizeWarningThreshold > 0 && a.totalSize > a.config.SizeWarningThreshold {
		a.logger.WarnContext(ctx, "attestation size exceeds warning threshold",
			"total_size_bytes", a.totalSize,
			"threshold_bytes", a.config.SizeWarningThreshold,
			"total_files", a.totalFiles)
	}
	return nil
}

func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	start := time.Now()
	a.logger.Info("generating file predicate")

	predicate := filepredicate.Predicate{
		AttestorConfig: filepredicate.AttestorConfig{
			BasePath:           a.config.BasePath,
			FollowSymlinks:     a.config.FollowSymlinks,
			HashAlgorithms:     a.config.HashAlgorithms,
			CapturePermissions: a.config.CapturePermissions,
			CaptureTimestamps:  a.config.CaptureTimestamps,
			CaptureOwnership:   a.config.CaptureOwnership,
			ExcludePatterns:    a.config.ExcludePatterns,
			IncludePatterns:    a.config.IncludePatterns,
		},
		Artifacts:   a.artifacts,
		Directories: a.directories,
		Summary: filepredicate.Summary{
			TotalFiles:       a.totalFiles,
			TotalDirectories: a.totalDirectories,
			TotalSize:        a.totalSize,
			CaptureTime:      a.captureTime,
			Duration:         fmt.Sprintf("%.3fs", a.duration.Seconds()),
		},
	}

	a.logger.Info("file predicate generated", "artifact_count", len(a.artifacts),
		"directory_count", len(a.directories), "duration_ms", time.Since(start).Milliseconds())

	return predicate, nil
}

func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	subjects := []intoto.Subject{
		{
			Name:   fmt.Sprintf("file-manifest+%s", a.config.BasePath),
			Digest: a.generateManifestDigest(),
		},
	}

	switch a.config.SubjectMode {
	case subjectModeManifestOnly:
		// Only manifest digest, no individual files

	case subjectModeHybrid:
		subjects = append(subjects, a.generateHybridSubjects()...)
	case subjectModeAllFiles:
		subjects = append(subjects, a.generateAllFileSubjects()...)
	}

	return subjects
}

func (a *Attestor) generateHybridSubjects() []intoto.Subject {
	subjects := []intoto.Subject{}
	for _, artifact := range a.artifacts {
		if a.matchesSubjectIncludePattern(artifact.Path) {
			subjects = append(subjects, intoto.Subject{
				Name:   artifact.Path,
				Digest: artifact.Digests,
			})
		}
	}
	return subjects
}

func (a *Attestor) generateAllFileSubjects() []intoto.Subject {
	sortedArtifacts := make([]filepredicate.ArtifactInfo, len(a.artifacts))
	copy(sortedArtifacts, a.artifacts)
	sort.Slice(sortedArtifacts, func(i, j int) bool {
		return sortedArtifacts[i].Path < sortedArtifacts[j].Path
	})

	subjects := make([]intoto.Subject, 0, len(sortedArtifacts))
	for _, artifact := range sortedArtifacts {
		subjects = append(subjects, intoto.Subject{
			Name:   artifact.Path,
			Digest: artifact.Digests,
		})
	}
	return subjects
}

func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}
	schema := reflector.Reflect(&filepredicate.Predicate{})
	schema.Title = "File Attestation"
	schema.Description = "Evidence of file and directory hashes and metadata for artifact provenance"
	return schema
}
