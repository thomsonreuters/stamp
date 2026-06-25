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

// Package git provides comprehensive Git repository attestation for generating
// Git-specific attestation predicates. It collects commit metadata, repository status,
// branch information, remote configurations, and optional data such as refs and tags.
//
// The attestor uses a custom predicate type (https://github.com/thomsonreuters/stamp/git/v1)
// specifically designed for source control attestations, NOT SLSA build provenance.
//
// The attestor supports various configuration options for controlling information
// collection depth and provides robust redaction capabilities for handling sensitive
// data in attestations.
//
// Key features:
//   - Complete commit metadata (hash, tree, parents, author, committer, message, GPG signature)
//   - Repository status tracking with file-by-file change detection
//   - Edge case handling (detached HEAD, shallow clones, empty repositories)
//   - Multi-algorithm commit hashing (SHA1, SHA256, SHA512)
//   - Configurable behavior for dirty repositories (allow, warn, fail)
//   - Security-focused field redaction capabilities
//   - Optional collection of refs, remotes, and annotated tags
package git

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/invopop/jsonschema"
	gitclient "github.com/thomsonreuters/stamp/pkg/clients/git"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	gitpredicate "github.com/thomsonreuters/stamp/pkg/predicates/git/v1"
)

// Attestor identification constants.
const (
	id          = "git"
	name        = "Git Attestor"
	description = "Generates Git repository attestation with source control metadata"
)

func init() {
	// Auto-register this attestor with custom Git predicate URI
	_ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		return &Attestor{
			logger: log.With("attestor_id", id),
		}
	})
}

// Config holds parsed configuration values for the Git attestor.
type Config struct {
	WorkingDir        string
	DirtyBehavior     string
	IncludeBinaryHash bool
	IncludeSignature  bool
	IncludeRefs       bool
	IncludeAllRemotes bool
	IncludeTags       bool
	IncludeSubmodules bool
	HashAlgorithms    []string
	RedactIdentity    bool
	SensitiveFields   []string
}

// Attestor implements the core.Attestor interface for Git source control attestation.
type Attestor struct {
	logger           logger.Logger
	gitClient        gitclient.ClientIface
	config           Config
	workingDir       string
	commitMetadata   gitpredicate.CommitMetadata
	branch           string
	repoURL          string
	repositoryStatus gitpredicate.RepositoryStatus
	gitBinary        gitpredicate.GitBinaryInfo
	refs             []string
	remotes          []gitpredicate.RemoteInfo
	tags             []gitpredicate.TagInfo
	submodules       []gitpredicate.SubmoduleInfo
}

// ID returns the unique identifier for this attestor.
func (a *Attestor) ID() string { return id }

// PredicateURI returns the custom Git predicate type URI.
func (a *Attestor) PredicateURI() string { return gitpredicate.PredicateURI }

// Name returns the human-readable name.
func (a *Attestor) Name() string { return name }

// Description returns the description.
func (a *Attestor) Description() string { return description }

// ConfigSchema returns the configuration schema for this attestor.
// The schema defines all available configuration options including their types,
// defaults, and validation requirements.
func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        "git-working-dir",
			Type:        "string",
			Default:     defaultWorkingDir,
			Required:    false,
			Description: "Git repository working directory",
			Example:     "/path/to/repo",
		},
		{
			Name:        "dirty-behavior",
			Type:        "string",
			Default:     defaultDirtyBehavior,
			Required:    false,
			Description: "How to handle uncommitted changes: 'allow' (collect and continue), 'warn' (collect and log warning), 'fail' (error on dirty repo)",
			Example:     "warn",
		},
		{
			Name:        "include-binary-hash",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Include hash of git binary (adds startup cost)",
			Example:     true,
		},
		{
			Name:        "include-signature",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Include GPG signature from commit if present",
			Example:     false,
		},
		{
			Name:        "include-refs",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Include all refs pointing to commits",
			Example:     true,
		},
		{
			Name:        "include-all-remotes",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Include all remotes (default: only origin)",
			Example:     true,
		},
		{
			Name:        "include-tags",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Include annotated tag information",
			Example:     true,
		},
		{
			Name:        "include-submodules",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Include Git submodule status and metadata",
			Example:     true,
		},
		{
			Name:        "hash-algorithms",
			Type:        "[]string",
			Default:     defaultHashAlgorithms,
			Required:    false,
			Description: "Hash algorithms for commit digest (e.g., sha1, sha256, sha512)",
			Example:     []string{HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA512},
		},
		{
			Name:        "redact-identity",
			Type:        "bool",
			Default:     false,
			Required:    false,
			Description: "Redact author and committer identity information from predicate",
			Example:     true,
		},
		{
			Name:        "sensitive-fields",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Fields to redact from predicate (e.g., author.name, author.email, repository)",
			Example:     []string{"author.email", "repository"},
		},
	}
}

// parseConfig extracts and normalizes configuration values from core.Config.
func (a *Attestor) parseConfig(config core.Config) {
	a.config = Config{
		WorkingDir:        config.GetString("git-working-dir", defaultWorkingDir),
		DirtyBehavior:     config.GetString("dirty-behavior", defaultDirtyBehavior),
		IncludeBinaryHash: config.GetBool("include-binary-hash", false),
		IncludeSignature:  config.GetBool("include-signature", true),
		IncludeRefs:       config.GetBool("include-refs", false),
		IncludeAllRemotes: config.GetBool("include-all-remotes", false),
		IncludeTags:       config.GetBool("include-tags", false),
		IncludeSubmodules: config.GetBool("include-submodules", false),
		HashAlgorithms:    config.GetStringSlice("hash-algorithms", defaultHashAlgorithms),
		RedactIdentity:    config.GetBool("redact-identity", false),
		SensitiveFields:   config.GetStringSlice("sensitive-fields"),
	}
}

// buildClientOptions converts attestor config to git client options.
func (a *Attestor) buildClientOptions() []gitclient.Option {
	// Map attestor hash algorithms to client hash algorithms
	hashAlgos := make([]string, 0, len(a.config.HashAlgorithms))
	for _, algo := range a.config.HashAlgorithms {
		switch algo {
		case HashAlgorithmSHA256:
			hashAlgos = append(hashAlgos, hash.AlgorithmSHA256)
		case HashAlgorithmSHA512:
			hashAlgos = append(hashAlgos, hash.AlgorithmSHA512)
			// SHA1 is handled separately as commit hash
		}
	}

	return []gitclient.Option{
		gitclient.WithLogger(a.logger),
		gitclient.WithIncludeSignature(a.config.IncludeSignature),
		gitclient.WithIncludeAllRemotes(a.config.IncludeAllRemotes),
		gitclient.WithIncludeTags(a.config.IncludeTags),
		gitclient.WithIncludeSubmodules(a.config.IncludeSubmodules),
		gitclient.WithIncludeBinaryHash(a.config.IncludeBinaryHash),
		gitclient.WithIncludeRefs(a.config.IncludeRefs),
		gitclient.WithIncludeCommitDigest(len(hashAlgos) > 0),
		gitclient.WithHashAlgorithms(hashAlgos),
	}
}

// PreAttest performs pre-attestation setup including working directory validation
// and Git repository state discovery.
func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	a.parseConfig(config)
	a.workingDir = a.config.WorkingDir

	absWorkingDir, err := filepath.Abs(a.workingDir)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "git_attestor", "validate", "failed to get absolute path for working directory")
	}
	a.workingDir = absWorkingDir

	if _, statErr := os.Stat(a.workingDir); statErr != nil {
		if os.IsNotExist(statErr) {
			a.logger.ErrorContext(ctx, "working directory does not exist", "working_dir", a.workingDir)
			return pkgerrors.WrapWithContext(statErr, id, "validate", "working directory does not exist: "+a.workingDir)
		}
		return pkgerrors.WrapWithContext(statErr, id, "validate", "failed to access working directory: "+a.workingDir)
	}

	client, err := gitclient.New(ctx, a.buildClientOptions()...)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "git_attestor", "init", "failed to create git client")
	}
	a.gitClient = client

	if !a.gitClient.IsGitRepository(ctx, a.workingDir) {
		a.logger.ErrorContext(ctx, "not in a Git repository", "working_dir", a.workingDir)
		return pkgerrors.WrapWithContext(ErrNotGitRepository, id, "validate", "working directory is not a Git repository")
	}

	return nil
}

// Attest performs the main attestation logic by collecting all Git repository information.
func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	if err := a.collect(ctx); err != nil {
		return err
	}

	if a.repositoryStatus.IsDirty {
		if err := a.handleDirtyRepository(ctx, len(a.repositoryStatus.FileStatus)); err != nil {
			return err
		}
	}

	a.logger.InfoContext(ctx, "Git information collection completed",
		"commit_hash", a.commitMetadata.Hash,
		"branch", a.branch,
		"repository_url", a.repoURL,
		"author", a.commitMetadata.Author.Name,
		"committer", a.commitMetadata.Committer.Name,
		"is_dirty", a.repositoryStatus.IsDirty,
		"parent_count", len(a.commitMetadata.ParentHashes),
		"detached_head", a.repositoryStatus.DetachedHead,
		"shallow_clone", a.repositoryStatus.ShallowClone)

	return nil
}

func (a *Attestor) collect(ctx context.Context) error {
	info, err := a.gitClient.GetInfo(ctx, a.workingDir)
	if err != nil {
		return pkgerrors.WrapWithContext(err, id, "collect", "failed to collect git repository information")
	}

	if err := info.Validate(); err != nil {
		return pkgerrors.WrapWithContext(ErrEmptyRepository, id, "validate", "repository must have at least one commit")
	}

	a.commitMetadata = gitpredicate.CommitMetadata{
		Hash:         info.CommitHash,
		TreeHash:     info.TreeHash,
		ParentHashes: info.ParentHashes,
		Author: gitpredicate.PersonInfo{
			Name:      info.AuthorName,
			Email:     info.AuthorEmail,
			Timestamp: info.AuthorTimestamp,
		},
		Committer: gitpredicate.PersonInfo{
			Name:      info.CommitterName,
			Email:     info.CommitterEmail,
			Timestamp: info.CommitterTimestamp,
		},
		Message:   info.Message,
		Signature: info.Signature,
	}

	if len(info.CommitDigest) > 0 {
		a.commitMetadata.CommitDigest = make(gitpredicate.DigestSet)
		maps.Copy(a.commitMetadata.CommitDigest, info.CommitDigest)
	}

	if slices.Contains(a.config.HashAlgorithms, HashAlgorithmSHA1) {
		if a.commitMetadata.CommitDigest == nil {
			a.commitMetadata.CommitDigest = make(gitpredicate.DigestSet)
		}
		a.commitMetadata.CommitDigest[HashAlgorithmSHA1] = info.CommitHash
	}

	a.branch = info.Branch

	if info.RemoteOriginURL != "" {
		a.repoURL = a.gitClient.GetHTMLURL(info.RemoteOriginURL)
	} else {
		a.repoURL = fmt.Sprintf("file://%s", a.workingDir)
	}

	a.repositoryStatus = gitpredicate.RepositoryStatus{
		IsDirty:      info.IsDirty,
		DetachedHead: info.IsDetachedHead,
		ShallowClone: info.IsShallowClone,
	}

	if len(info.FileStatus) > 0 {
		a.repositoryStatus.FileStatus = make(map[string]gitpredicate.FileStatus)
		for path, status := range info.FileStatus {
			a.repositoryStatus.FileStatus[path] = gitpredicate.FileStatus{
				Staging:  status.Staging,
				Worktree: status.Worktree,
			}
		}
	}

	a.gitBinary = gitpredicate.GitBinaryInfo{
		Tool: info.GitVersion,
		Path: info.GitPath,
		Hash: maps.Clone(info.GitBinaryHash),
	}

	a.refs = info.Refs

	if len(info.Remotes) > 0 {
		a.remotes = make([]gitpredicate.RemoteInfo, len(info.Remotes))
		for i, remote := range info.Remotes {
			a.remotes[i] = gitpredicate.RemoteInfo{
				Name:     remote.Name,
				FetchURL: remote.FetchURL,
				PushURL:  remote.PushURL,
			}
		}
	}

	if len(info.Tags) > 0 {
		a.tags = make([]gitpredicate.TagInfo, len(info.Tags))
		for i, tag := range info.Tags {
			a.tags[i] = gitpredicate.TagInfo{
				Name:         tag.Name,
				TaggerName:   tag.TaggerName,
				TaggerEmail:  tag.TaggerEmail,
				When:         tag.When,
				PGPSignature: tag.PGPSignature,
				Message:      tag.Message,
			}
		}
	}

	if len(info.Submodules) > 0 {
		a.submodules = make([]gitpredicate.SubmoduleInfo, len(info.Submodules))
		for i, sub := range info.Submodules {
			a.submodules[i] = gitpredicate.SubmoduleInfo{
				Path:   sub.Path,
				Commit: sub.Commit,
				URL:    sub.URL,
				Branch: sub.Branch,
				Status: sub.Status,
			}
		}
	}

	return nil
}

func (a *Attestor) handleDirtyRepository(ctx context.Context, fileCount int) error {
	switch a.config.DirtyBehavior {
	case DirtyBehaviorAllow:
		a.logger.DebugContext(ctx, "repository is dirty, continuing per configuration")
		return nil
	case DirtyBehaviorWarn:
		a.logger.WarnContext(ctx, "repository has uncommitted changes", "file_count", fileCount)
		return nil
	case DirtyBehaviorFail:
		a.logger.ErrorContext(ctx, "failing due to dirty repository", "file_count", fileCount)
		return pkgerrors.WrapWithContext(ErrRepositoryDirty, id, "validate",
			fmt.Sprintf("repository has %d uncommitted change(s)", fileCount))
	default:
		a.logger.WarnContext(ctx, "invalid dirty-behavior value, defaulting to allow", "value", a.config.DirtyBehavior)
		return nil
	}
}

// PostAttest performs post-attestation cleanup. The Git attestor requires no cleanup.
func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	return nil
}

// GeneratePredicate generates the Git source control predicate with redaction support.
func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	predicate := gitpredicate.Predicate{
		Repository: gitpredicate.RepositoryInfo{
			URL:    a.repoURL,
			Branch: a.branch,
		},
		Commit:           a.commitMetadata,
		RepositoryStatus: a.repositoryStatus,
		GitBinary:        &a.gitBinary,
		Refs:             a.refs,
		Remotes:          a.remotes,
		Tags:             a.tags,
		Submodules:       a.submodules,
	}

	if a.gitBinary.Path == "" {
		predicate.GitBinary = nil
	}

	if a.config.RedactIdentity {
		predicate.Commit.Author = gitpredicate.PersonInfo{
			Name:      "[REDACTED]",
			Email:     "[REDACTED]",
			Timestamp: predicate.Commit.Author.Timestamp,
		}
		predicate.Commit.Committer = gitpredicate.PersonInfo{
			Name:      "[REDACTED]",
			Email:     "[REDACTED]",
			Timestamp: predicate.Commit.Committer.Timestamp,
		}
	}

	if len(a.config.SensitiveFields) > 0 {
		predicate = a.redactSensitiveFields(predicate, a.config.SensitiveFields)
	}

	return predicate, nil
}

// Subjects returns the subjects for this attestation.
func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	digest := make(map[string]string, len(a.commitMetadata.CommitDigest)+1)
	maps.Copy(digest, a.commitMetadata.CommitDigest)
	digest["sha1"] = a.commitMetadata.Hash

	return []intoto.Subject{{
		Name:   fmt.Sprintf("git+%s@%s", a.repoURL, a.commitMetadata.Hash),
		Digest: digest,
	}}
}

// Schema returns the JSON schema for this attestor's configuration.
func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}

	schema := reflector.Reflect(&gitpredicate.Predicate{})
	schema.Title = "Git Source Control Attestation"
	schema.Description = "Evidence of Git repository state and commit metadata for source control attestation"

	return schema
}
