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

package git

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNew(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err, "New() should not return error")
	require.NotNil(t, client, "New() should return a client")
}

func TestNewWithAllOptions(t *testing.T) {
	client, err := New(t.Context(),
		WithLogger(logger.NewNoop()),
		WithExecutor(executor.NewOSCommandExecutor()),
		WithIncludeSignature(true),
		WithIncludeAllRemotes(true),
		WithIncludeTags(true),
		WithIncludeSubmodules(true),
		WithIncludeBinaryHash(true),
		WithIncludeRefs(true),
		WithIncludeCommitDigest(true),
		WithHashAlgorithms([]string{hash.AlgorithmSHA256, hash.AlgorithmSHA512}),
	)
	require.NoError(t, err, "New() with options should not return error")
	require.NotNil(t, client, "New() with options should return a client")
}

func TestNewWithMinimalOptions(t *testing.T) {
	client, err := New(t.Context(),
		WithIncludeSignature(false),
	)
	require.NoError(t, err, "New() with minimal options should not return error")
	require.NotNil(t, client, "New() with minimal options should return a client")
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	tests := []struct {
		name     string
		got      any
		expected any
	}{
		{"IncludeSignature", opts.IncludeSignature, true},
		{"IncludeAllRemotes", opts.IncludeAllRemotes, false},
		{"IncludeTags", opts.IncludeTags, false},
		{"IncludeSubmodules", opts.IncludeSubmodules, false},
		{"IncludeBinaryHash", opts.IncludeBinaryHash, false},
		{"IncludeRefs", opts.IncludeRefs, false},
		{"IncludeCommitDigest", opts.IncludeCommitDigest, false},
		{"HashAlgorithms length", len(opts.HashAlgorithms), 1},
		{"HashAlgorithms[0]", opts.HashAlgorithms[0], hash.AlgorithmSHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.got, tt.name)
		})
	}
}

func TestWithLogger(t *testing.T) {
	opts := DefaultOptions()
	log := logger.NewNoop()
	WithLogger(log)(&opts)
	assert.Equal(t, log, opts.Logger, "WithLogger should set logger")
}

func TestWithExecutor(t *testing.T) {
	opts := DefaultOptions()
	exec := executor.NewOSCommandExecutor()
	WithExecutor(exec)(&opts)
	assert.Equal(t, exec, opts.Executor, "WithExecutor should set executor")
}

func TestWithIncludeSignature(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeSignature(false)(&opts)
	assert.False(t, opts.IncludeSignature, "WithIncludeSignature(false) should set to false")
	WithIncludeSignature(true)(&opts)
	assert.True(t, opts.IncludeSignature, "WithIncludeSignature(true) should set to true")
}

func TestWithIncludeAllRemotes(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeAllRemotes(true)(&opts)
	assert.True(t, opts.IncludeAllRemotes, "WithIncludeAllRemotes(true) should set to true")
}

func TestWithIncludeTags(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeTags(true)(&opts)
	assert.True(t, opts.IncludeTags, "WithIncludeTags(true) should set to true")
}

func TestWithIncludeSubmodules(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeSubmodules(true)(&opts)
	assert.True(t, opts.IncludeSubmodules, "WithIncludeSubmodules(true) should set to true")
}

func TestWithIncludeBinaryHash(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeBinaryHash(true)(&opts)
	assert.True(t, opts.IncludeBinaryHash, "WithIncludeBinaryHash(true) should set to true")
}

func TestWithIncludeRefs(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeRefs(true)(&opts)
	assert.True(t, opts.IncludeRefs, "WithIncludeRefs(true) should set to true")
}

func TestWithIncludeCommitDigest(t *testing.T) {
	opts := DefaultOptions()
	WithIncludeCommitDigest(true)(&opts)
	assert.True(t, opts.IncludeCommitDigest, "WithIncludeCommitDigest(true) should set to true")
}

func TestWithHashAlgorithms(t *testing.T) {
	opts := DefaultOptions()
	algos := []string{hash.AlgorithmSHA256, hash.AlgorithmSHA512, hash.AlgorithmBLAKE3}
	WithHashAlgorithms(algos)(&opts)
	assert.Len(t, opts.HashAlgorithms, 3, "WithHashAlgorithms should set 3 algorithms")
}

func TestIsGitRepository(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	assert.True(t, client.IsGitRepository(t.Context(), repoRoot), "should return true for valid repo")
}

func TestIsGitRepositoryNotRepo(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	tempDir := t.TempDir()
	assert.False(t, client.IsGitRepository(t.Context(), tempDir), "should return false for non-repo")
}

func TestGetCommitHash(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	commitHash, err := client.GetCommitHash(t.Context(), repoRoot)
	require.NoError(t, err)
	assert.NotEmpty(t, commitHash, "commit hash should not be empty")
	assert.Len(t, commitHash, 40, "commit hash should be 40 characters")
}

func TestGetCommitHashNotRepo(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	tempDir := t.TempDir()
	_, err = client.GetCommitHash(t.Context(), tempDir)
	assert.Error(t, err, "should return error for non-repo")
}

func TestGetBranch(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	// Branch might be empty if detached HEAD, so we just check no error
	_, err = client.GetBranch(t.Context(), repoRoot)
	require.NoError(t, err)
}

func TestGetBranchNotRepo(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	tempDir := t.TempDir()
	_, err = client.GetBranch(t.Context(), tempDir)
	assert.Error(t, err, "should return error for non-repo")
}

func TestIsDirty(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	// Just check that it doesn't error
	_, err = client.IsDirty(t.Context(), repoRoot)
	require.NoError(t, err)
}

func TestIsDirtyNotRepo(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	tempDir := t.TempDir()
	_, err = client.IsDirty(t.Context(), tempDir)
	assert.Error(t, err, "should return error for non-repo")
}

func TestGetHTMLURL(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SSH URL",
			input:    "git@github.com:user/repo.git",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "SSH URL without .git",
			input:    "git@github.com:user/repo",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "SSH protocol URL",
			input:    "ssh://git@github.com/user/repo.git",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "SSH protocol URL without .git",
			input:    "ssh://git@github.com/user/repo",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "HTTPS URL with .git",
			input:    "https://github.com/user/repo.git",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "HTTPS URL without .git",
			input:    "https://github.com/user/repo",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "HTTP URL with .git",
			input:    "http://github.com/user/repo.git",
			expected: "http://github.com/user/repo",
		},
		{
			name:     "HTTP URL without .git",
			input:    "http://github.com/user/repo",
			expected: "http://github.com/user/repo",
		},
		{
			name:     "file URL",
			input:    "file:///path/to/repo",
			expected: "file:///path/to/repo",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "GitLab SSH URL",
			input:    "git@gitlab.com:group/project.git",
			expected: "https://gitlab.com/group/project",
		},
		{
			name:     "Bitbucket SSH URL",
			input:    "git@bitbucket.org:team/repo.git",
			expected: "https://bitbucket.org/team/repo",
		},
		{
			name:     "SSH URL with port",
			input:    "ssh://git@github.com:22/user/repo.git",
			expected: "https://github.com:22/user/repo",
		},
		{
			name:     "HTTPS URL with embedded credentials",
			input:    "https://ghp_token123@github.com/user/repo.git",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "HTTPS URL with user:pass credentials",
			input:    "https://user:password@github.com/org/repo.git",
			expected: "https://github.com/org/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.GetHTMLURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSourceURI(t *testing.T) {
	tests := []struct {
		name     string
		info     *GitInfo
		expected string
	}{
		{
			name:     "nil info",
			info:     nil,
			expected: "",
		},
		{
			name:     "empty remote URL",
			info:     &GitInfo{},
			expected: "",
		},
		{
			name: "with refs",
			info: &GitInfo{
				RemoteOriginURL: "git@github.com:user/repo.git",
				Refs:            []string{"refs/heads/main"},
			},
			expected: "git+https://github.com/user/repo@refs/heads/main",
		},
		{
			name: "with branch only",
			info: &GitInfo{
				RemoteOriginURL: "git@github.com:user/repo.git",
				Branch:          "develop",
			},
			expected: "git+https://github.com/user/repo@refs/heads/develop",
		},
		{
			name: "with commit hash only",
			info: &GitInfo{
				RemoteOriginURL: "git@github.com:user/repo.git",
				CommitHash:      "abc123def456",
			},
			expected: "git+https://github.com/user/repo@abc123def456",
		},
		{
			name: "prefer refs over branch",
			info: &GitInfo{
				RemoteOriginURL: "git@github.com:user/repo.git",
				Refs:            []string{"refs/tags/v1.0.0"},
				Branch:          "main",
			},
			expected: "git+https://github.com/user/repo@refs/tags/v1.0.0",
		},
		{
			name: "HTTPS URL",
			info: &GitInfo{
				RemoteOriginURL: "https://github.com/user/repo.git",
				Branch:          "main",
			},
			expected: "git+https://github.com/user/repo@refs/heads/main",
		},
		{
			name: "no ref information",
			info: &GitInfo{
				RemoteOriginURL: "https://github.com/user/repo.git",
			},
			expected: "git+https://github.com/user/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSourceURI(tt.info)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetInfo(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	info, err := client.GetInfo(t.Context(), repoRoot)
	require.NoError(t, err)

	assert.NotEmpty(t, info.CommitHash, "CommitHash should not be empty")
	assert.Len(t, info.CommitHash, 40, "CommitHash should be 40 characters")
	assert.NotEmpty(t, info.TreeHash, "TreeHash should not be empty")
	assert.NotEmpty(t, info.AuthorName, "AuthorName should not be empty")
	assert.NotEmpty(t, info.AuthorEmail, "AuthorEmail should not be empty")
	assert.False(t, info.AuthorTimestamp.IsZero(), "AuthorTimestamp should not be zero")
	assert.NotEmpty(t, info.CommitterName, "CommitterName should not be empty")
	assert.NotEmpty(t, info.CommitterEmail, "CommitterEmail should not be empty")
	assert.False(t, info.CommitterTimestamp.IsZero(), "CommitterTimestamp should not be zero")
	assert.NotEmpty(t, info.GitVersion, "GitVersion should not be empty")
	assert.NotEmpty(t, info.GitPath, "GitPath should not be empty")
}

func TestGetInfoWithAllOptions(t *testing.T) {
	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	client, err := New(t.Context(),
		WithIncludeSignature(true),
		WithIncludeAllRemotes(true),
		WithIncludeTags(true),
		WithIncludeSubmodules(true),
		WithIncludeBinaryHash(true),
		WithIncludeRefs(true),
		WithIncludeCommitDigest(true),
		WithHashAlgorithms([]string{hash.AlgorithmSHA256, hash.AlgorithmSHA512}),
	)
	require.NoError(t, err)

	info, err := client.GetInfo(t.Context(), repoRoot)
	require.NoError(t, err)

	assert.NotEmpty(t, info.CommitHash, "CommitHash should not be empty")

	assert.NotEmpty(t, info.CommitDigest, "CommitDigest should not be empty with IncludeCommitDigest=true")

	assert.NotEmpty(t, info.GitBinaryHash, "GitBinaryHash should not be empty with IncludeBinaryHash=true")
}

func TestGetInfoNotGitRepo(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	tempDir := t.TempDir()
	_, err = client.GetInfo(t.Context(), tempDir)
	assert.ErrorIs(t, err, ErrNotGitRepository)
}

func TestGetInfoPathNotFound(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)

	_, err = client.GetInfo(t.Context(), "/nonexistent/path/that/does/not/exist")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPathNotFound)
}

func TestGetInfoWithSignature(t *testing.T) {
	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	client, err := New(t.Context(), WithIncludeSignature(true))
	require.NoError(t, err)

	info, err := client.GetInfo(t.Context(), repoRoot)
	require.NoError(t, err)

	// Signature may or may not be present depending on commit
	// Just ensure no error occurred
	assert.NotEmpty(t, info.CommitHash, "CommitHash should not be empty")
}

func TestGetInfoWithoutSignature(t *testing.T) {
	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	client, err := New(t.Context(), WithIncludeSignature(false))
	require.NoError(t, err)

	info, err := client.GetInfo(t.Context(), repoRoot)
	require.NoError(t, err)

	// Signature should be empty when not requested
	assert.Empty(t, info.Signature, "Signature should be empty when IncludeSignature=false")
}

func TestParseCommitLog(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantErr   bool
		wantErrIs error
		validate  func(*testing.T, *GitInfo)
	}{
		{
			name:      "empty output",
			output:    "",
			wantErr:   true,
			wantErrIs: ErrEmptyRepository,
		},
		{
			name:      "invalid format - too few fields",
			output:    "abc123",
			wantErr:   true,
			wantErrIs: ErrInvalidCommitFormat,
		},
		{
			name:    "invalid format - 9 fields",
			output:  "a" + commitFieldSeparator + "b" + commitFieldSeparator + "c" + commitFieldSeparator + "d" + commitFieldSeparator + "e" + commitFieldSeparator + "f" + commitFieldSeparator + "g" + commitFieldSeparator + "h" + commitFieldSeparator + "i",
			wantErr: true,
		},
		{
			name: "valid output with all fields",
			output: "abc123def456789012345678901234567890abcd" + commitFieldSeparator +
				"tree789012345678901234567890abcdef123456" + commitFieldSeparator +
				"parent1abc parent2def" + commitFieldSeparator +
				"Author Name" + commitFieldSeparator +
				"author@example.com" + commitFieldSeparator +
				"1699999999" + commitFieldSeparator +
				"Committer Name" + commitFieldSeparator +
				"committer@example.com" + commitFieldSeparator +
				"1700000000" + commitFieldSeparator +
				"Commit message here",
			wantErr: false,
			validate: func(t *testing.T, info *GitInfo) {
				assert.Equal(t, "abc123def456789012345678901234567890abcd", info.CommitHash)
				assert.Equal(t, "tree789012345678901234567890abcdef123456", info.TreeHash)
				assert.Len(t, info.ParentHashes, 2)
				assert.Equal(t, "Author Name", info.AuthorName)
				assert.Equal(t, "author@example.com", info.AuthorEmail)
				assert.Equal(t, "Committer Name", info.CommitterName)
				assert.Equal(t, "committer@example.com", info.CommitterEmail)
				assert.Equal(t, "Commit message here", info.Message)
			},
		},
		{
			name: "valid output with no parents (initial commit)",
			output: "abc123" + commitFieldSeparator +
				"def456" + commitFieldSeparator +
				"" + commitFieldSeparator +
				"Author" + commitFieldSeparator +
				"author@test.com" + commitFieldSeparator +
				"1699999999" + commitFieldSeparator +
				"Committer" + commitFieldSeparator +
				"committer@test.com" + commitFieldSeparator +
				"1700000000" + commitFieldSeparator +
				"Initial commit",
			wantErr: false,
			validate: func(t *testing.T, info *GitInfo) {
				assert.Empty(t, info.ParentHashes, "ParentHashes should be empty for initial commit")
			},
		},
		{
			name: "valid output with invalid timestamp",
			output: "abc123" + commitFieldSeparator +
				"def456" + commitFieldSeparator +
				"" + commitFieldSeparator +
				"Author" + commitFieldSeparator +
				"author@test.com" + commitFieldSeparator +
				"invalid" + commitFieldSeparator +
				"Committer" + commitFieldSeparator +
				"committer@test.com" + commitFieldSeparator +
				"also_invalid" + commitFieldSeparator +
				"Message",
			wantErr: false,
			validate: func(t *testing.T, info *GitInfo) {
				assert.True(t, info.AuthorTimestamp.IsZero(), "AuthorTimestamp should be zero for invalid timestamp")
				assert.True(t, info.CommitterTimestamp.IsZero(), "CommitterTimestamp should be zero for invalid timestamp")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseCommitLog(tt.output)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					require.ErrorIs(t, err, tt.wantErrIs)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, info)
			if tt.validate != nil {
				tt.validate(t, info)
			}
		})
	}
}

func TestParseRepositoryStatus(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantDirty  bool
		wantFiles  int
		validateFn func(*testing.T, map[string]FileStatus)
	}{
		{
			name:      "clean repository",
			output:    "",
			wantDirty: false,
			wantFiles: 0,
		},
		{
			name:      "modified file in worktree",
			output:    " M file.txt",
			wantDirty: true,
			wantFiles: 1,
			validateFn: func(t *testing.T, status map[string]FileStatus) {
				s, ok := status["file.txt"]
				require.True(t, ok, "file.txt not found in status")
				assert.Equal(t, "M", s.Worktree)
			},
		},
		{
			name:      "staged file",
			output:    "A  newfile.txt",
			wantDirty: true,
			wantFiles: 1,
			validateFn: func(t *testing.T, status map[string]FileStatus) {
				s, ok := status["newfile.txt"]
				require.True(t, ok, "newfile.txt not found in status")
				assert.Equal(t, "A", s.Staging)
			},
		},
		{
			name:      "untracked file",
			output:    "?? untracked.txt",
			wantDirty: true,
			wantFiles: 1,
		},
		{
			name:      "deleted file",
			output:    " D deleted.txt",
			wantDirty: true,
			wantFiles: 1,
		},
		{
			name:      "multiple changes",
			output:    " M file1.txt\nA  file2.txt\n?? file3.txt\n D file4.txt",
			wantDirty: true,
			wantFiles: 4,
		},
		{
			name:      "renamed file",
			output:    "R  old.txt -> new.txt",
			wantDirty: true,
			wantFiles: 1,
			validateFn: func(t *testing.T, status map[string]FileStatus) {
				_, ok := status["new.txt"]
				assert.True(t, ok, "new.txt not found in status after rename")
			},
		},
		{
			name:      "short line ignored",
			output:    "AB",
			wantDirty: false,
			wantFiles: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isDirty, fileStatus := parseRepositoryStatus(tt.output)
			assert.Equal(t, tt.wantDirty, isDirty)
			assert.Len(t, fileStatus, tt.wantFiles)
			if tt.validateFn != nil {
				tt.validateFn(t, fileStatus)
			}
		})
	}
}

func TestParseRemoteInfo(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantRemotes int
		validateFn  func(*testing.T, []RemoteInfo)
	}{
		{
			name:        "empty output",
			output:      "",
			wantRemotes: 0,
		},
		{
			name:        "origin with fetch and push",
			output:      "origin\thttps://github.com/user/repo.git (fetch)\norigin\thttps://github.com/user/repo.git (push)",
			wantRemotes: 1,
			validateFn: func(t *testing.T, remotes []RemoteInfo) {
				assert.Equal(t, "origin", remotes[0].Name)
				assert.Equal(t, "https://github.com/user/repo.git", remotes[0].FetchURL)
				assert.Equal(t, "https://github.com/user/repo.git", remotes[0].PushURL)
			},
		},
		{
			name:        "multiple remotes",
			output:      "origin\thttps://github.com/user/repo.git (fetch)\norigin\thttps://github.com/user/repo.git (push)\nupstream\thttps://github.com/other/repo.git (fetch)\nupstream\thttps://github.com/other/repo.git (push)",
			wantRemotes: 2,
		},
		{
			name:        "different fetch and push URLs",
			output:      "origin\thttps://github.com/user/repo.git (fetch)\norigin\tgit@github.com:user/repo.git (push)",
			wantRemotes: 1,
			validateFn: func(t *testing.T, remotes []RemoteInfo) {
				assert.Equal(t, "https://github.com/user/repo.git", remotes[0].FetchURL)
				assert.Equal(t, "git@github.com:user/repo.git", remotes[0].PushURL)
			},
		},
		{
			name:        "URL without type",
			output:      "origin\thttps://github.com/user/repo.git",
			wantRemotes: 1,
		},
		{
			name:        "malformed line - single field",
			output:      "origin",
			wantRemotes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remotes := parseRemoteInfo(tt.output)
			assert.Len(t, remotes, tt.wantRemotes)
			if tt.validateFn != nil && len(remotes) > 0 {
				tt.validateFn(t, remotes)
			}
		})
	}
}

func TestParseBranch(t *testing.T) {
	tests := []struct {
		name           string
		currentBranch  string
		wantBranch     string
		wantIsDetached bool
	}{
		{
			name:           "normal branch",
			currentBranch:  "main",
			wantBranch:     "main",
			wantIsDetached: false,
		},
		{
			name:           "feature branch",
			currentBranch:  "feature/example-feature",
			wantBranch:     "feature/example-feature",
			wantIsDetached: false,
		},
		{
			name:           "detached HEAD",
			currentBranch:  "",
			wantBranch:     "",
			wantIsDetached: true,
		},
		{
			name:           "detached HEAD with whitespace",
			currentBranch:  "  ",
			wantBranch:     "",
			wantIsDetached: true,
		},
		{
			name:           "branch with whitespace",
			currentBranch:  "  main  ",
			wantBranch:     "main",
			wantIsDetached: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			branch, isDetached := parseBranch(tt.currentBranch)
			assert.Equal(t, tt.wantBranch, branch)
			assert.Equal(t, tt.wantIsDetached, isDetached)
		})
	}
}

func TestParseOriginURL(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "https URL",
			output: "https://github.com/user/repo.git",
			want:   "https://github.com/user/repo.git",
		},
		{
			name:   "ssh URL",
			output: "git@github.com:user/repo.git",
			want:   "git@github.com:user/repo.git",
		},
		{
			name:   "with whitespace",
			output: "  https://github.com/user/repo.git  \n",
			want:   "https://github.com/user/repo.git",
		},
		{
			name:   "empty",
			output: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOriginURL(tt.output)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseTagInfo(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantTags   int
		validateFn func(*testing.T, []TagInfo)
	}{
		{
			name:     "empty output",
			output:   "",
			wantTags: 0,
		},
		{
			name:     "single tag with all fields",
			output:   "v1.0.0|Tagger Name|tagger@example.com|1700000000|-----BEGIN PGP SIGNATURE-----|Initial release",
			wantTags: 1,
			validateFn: func(t *testing.T, tags []TagInfo) {
				tag := tags[0]
				assert.Equal(t, "v1.0.0", tag.Name)
				assert.Equal(t, "Tagger Name", tag.TaggerName)
				assert.Equal(t, "tagger@example.com", tag.TaggerEmail)
				assert.False(t, tag.When.IsZero(), "When should not be zero")
				assert.Equal(t, "-----BEGIN PGP SIGNATURE-----", tag.PGPSignature)
				assert.Equal(t, "Initial release", tag.Message)
			},
		},
		{
			name:     "multiple tags",
			output:   "v1.0.0|Author|author@example.com|1700000000||Release 1\nv1.1.0|Author|author@example.com|1700100000||Release 2",
			wantTags: 2,
		},
		{
			name:     "lightweight tag (name only)",
			output:   "v1.0.0",
			wantTags: 1,
			validateFn: func(t *testing.T, tags []TagInfo) {
				assert.Equal(t, "v1.0.0", tags[0].Name)
			},
		},
		{
			name:     "tag with invalid timestamp",
			output:   "v1.0.0|Author|author@example.com|invalid||Message",
			wantTags: 1,
			validateFn: func(t *testing.T, tags []TagInfo) {
				assert.True(t, tags[0].When.IsZero(), "When should be zero for invalid timestamp")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := parseTagInfo(tt.output)
			assert.Len(t, tags, tt.wantTags)
			if tt.validateFn != nil && len(tags) > 0 {
				tt.validateFn(t, tags)
			}
		})
	}
}

func TestParseSubmoduleStatus(t *testing.T) {
	tests := []struct {
		name           string
		output         string
		wantSubmodules int
		validateFn     func(*testing.T, []SubmoduleInfo)
	}{
		{
			name:           "empty output",
			output:         "",
			wantSubmodules: 0,
		},
		{
			name:           "single up-to-date submodule",
			output:         " abc123def456789012345678901234567890abcd path/to/submodule (v1.0.0)",
			wantSubmodules: 1,
			validateFn: func(t *testing.T, subs []SubmoduleInfo) {
				assert.Equal(t, "abc123def456789012345678901234567890abcd", subs[0].Commit)
				assert.Equal(t, "path/to/submodule", subs[0].Path)
				assert.Equal(t, " ", subs[0].Status)
			},
		},
		{
			name:           "uninitialized submodule",
			output:         "-abc123def456 path/to/submodule",
			wantSubmodules: 1,
			validateFn: func(t *testing.T, subs []SubmoduleInfo) {
				assert.Equal(t, "-", subs[0].Status)
			},
		},
		{
			name:           "modified submodule",
			output:         "+abc123def456 path/to/submodule",
			wantSubmodules: 1,
			validateFn: func(t *testing.T, subs []SubmoduleInfo) {
				assert.Equal(t, "+", subs[0].Status)
			},
		},
		{
			name:           "submodule with merge conflicts",
			output:         "Uabc123def456 path/to/submodule",
			wantSubmodules: 1,
			validateFn: func(t *testing.T, subs []SubmoduleInfo) {
				assert.Equal(t, "U", subs[0].Status)
			},
		},
		{
			name:           "multiple submodules",
			output:         " abc123 sub1\n-def456 sub2\n+ghi789 sub3",
			wantSubmodules: 3,
		},
		{
			name:           "empty line in output",
			output:         " abc123 sub1\n\n def456 sub2",
			wantSubmodules: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submodules := parseSubmoduleStatus(tt.output)
			assert.Len(t, submodules, tt.wantSubmodules)
			if tt.validateFn != nil && len(submodules) > 0 {
				tt.validateFn(t, submodules)
			}
		})
	}
}

func TestParseGitVersion(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "standard format",
			output: "git version 2.39.0",
			want:   "2.39.0",
		},
		{
			name:   "with platform info",
			output: "git version 2.39.0 (Apple Git-143)",
			want:   "2.39.0 (Apple Git-143)",
		},
		{
			name:   "just version number",
			output: "2.39.0",
			want:   "2.39.0",
		},
		{
			name:   "with whitespace",
			output: "  git version 2.39.0  ",
			want:   "2.39.0",
		},
		{
			name:   "empty",
			output: "",
			want:   "",
		},
		{
			name:   "git version with windows info",
			output: "git version 2.42.0.windows.2",
			want:   "2.42.0.windows.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGitVersion(tt.output)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsShallowClone(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "is shallow",
			output: "true",
			want:   true,
		},
		{
			name:   "not shallow",
			output: "false",
			want:   false,
		},
		{
			name:   "with whitespace - true",
			output: "  true  ",
			want:   true,
		},
		{
			name:   "with whitespace - false",
			output: "  false  ",
			want:   false,
		},
		{
			name:   "with newline",
			output: "true\n",
			want:   true,
		},
		{
			name:   "empty",
			output: "",
			want:   false,
		},
		{
			name:   "invalid value",
			output: "maybe",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isShallowClone(tt.output)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGitInfoValidate(t *testing.T) {
	tests := []struct {
		name      string
		info      *GitInfo
		wantErr   bool
		wantErrIs error
	}{
		{
			name:    "valid info with commit hash",
			info:    &GitInfo{CommitHash: "abc123def456789012345678901234567890abcd"},
			wantErr: false,
		},
		{
			name:      "empty commit hash",
			info:      &GitInfo{},
			wantErr:   true,
			wantErrIs: ErrEmptyRepository,
		},
		{
			name:      "whitespace commit hash",
			info:      &GitInfo{CommitHash: ""},
			wantErr:   true,
			wantErrIs: ErrEmptyRepository,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					require.ErrorIs(t, err, tt.wantErrIs)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGitInfoIsClean(t *testing.T) {
	tests := []struct {
		name string
		info *GitInfo
		want bool
	}{
		{
			name: "clean repository",
			info: &GitInfo{IsDirty: false},
			want: true,
		},
		{
			name: "dirty repository",
			info: &GitInfo{IsDirty: true},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.info.IsClean())
		})
	}
}

func TestGitInfoHasRemote(t *testing.T) {
	tests := []struct {
		name string
		info *GitInfo
		want bool
	}{
		{
			name: "no remote",
			info: &GitInfo{},
			want: false,
		},
		{
			name: "with origin URL",
			info: &GitInfo{RemoteOriginURL: "https://github.com/user/repo.git"},
			want: true,
		},
		{
			name: "with remotes list",
			info: &GitInfo{Remotes: []RemoteInfo{{Name: "origin"}}},
			want: true,
		},
		{
			name: "with both",
			info: &GitInfo{
				RemoteOriginURL: "https://github.com/user/repo.git",
				Remotes:         []RemoteInfo{{Name: "origin"}},
			},
			want: true,
		},
		{
			name: "empty origin URL",
			info: &GitInfo{RemoteOriginURL: ""},
			want: false,
		},
		{
			name: "empty remotes list",
			info: &GitInfo{Remotes: []RemoteInfo{}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.info.HasRemote())
		})
	}
}

func TestMockClient(t *testing.T) {
	expectedInfo := &GitInfo{
		CommitHash: "test123abc456def789012345678901234567890",
		Branch:     "main",
	}

	mockClient := NewMockClient()

	mockClient.On("GetInfo", t.Context(), "/test").Return(expectedInfo, nil)
	mockClient.On("IsGitRepository", t.Context(), "/test").Return(true)
	mockClient.On("GetCommitHash", t.Context(), "/test").Return("test123abc456def789012345678901234567890", nil)
	mockClient.On("GetBranch", t.Context(), "/test").Return("main", nil)
	mockClient.On("IsDirty", t.Context(), "/test").Return(false, nil)
	mockClient.On("GetHTMLURL", "git@github.com:user/repo.git").Return("https://github.com/user/repo")

	t.Run("GetInfo", func(t *testing.T) {
		info, err := mockClient.GetInfo(t.Context(), "/test")
		require.NoError(t, err)
		assert.Equal(t, expectedInfo.CommitHash, info.CommitHash)
	})

	t.Run("IsGitRepository", func(t *testing.T) {
		assert.True(t, mockClient.IsGitRepository(t.Context(), "/test"))
	})

	t.Run("GetCommitHash", func(t *testing.T) {
		hash, err := mockClient.GetCommitHash(t.Context(), "/test")
		require.NoError(t, err)
		assert.Equal(t, "test123abc456def789012345678901234567890", hash)
	})

	t.Run("GetBranch", func(t *testing.T) {
		branch, err := mockClient.GetBranch(t.Context(), "/test")
		require.NoError(t, err)
		assert.Equal(t, "main", branch)
	})

	t.Run("IsDirty", func(t *testing.T) {
		dirty, err := mockClient.IsDirty(t.Context(), "/test")
		require.NoError(t, err)
		assert.False(t, dirty)
	})

	t.Run("GetHTMLURL", func(t *testing.T) {
		url := mockClient.GetHTMLURL("git@github.com:user/repo.git")
		assert.Equal(t, "https://github.com/user/repo", url)
	})

	mockClient.AssertExpectations(t)
}

func TestMockClientWithErrors(t *testing.T) {
	testErr := errors.New("test error")

	mockClient := NewMockClient()

	mockClient.On("GetInfo", t.Context(), "/test").Return(nil, testErr)
	mockClient.On("GetCommitHash", t.Context(), "/test").Return("", testErr)
	mockClient.On("GetBranch", t.Context(), "/test").Return("", testErr)
	mockClient.On("IsDirty", t.Context(), "/test").Return(false, testErr)

	t.Run("GetInfo error", func(t *testing.T) {
		_, err := mockClient.GetInfo(t.Context(), "/test")
		assert.ErrorIs(t, err, testErr)
	})

	t.Run("GetCommitHash error", func(t *testing.T) {
		_, err := mockClient.GetCommitHash(t.Context(), "/test")
		assert.ErrorIs(t, err, testErr)
	})

	t.Run("GetBranch error", func(t *testing.T) {
		_, err := mockClient.GetBranch(t.Context(), "/test")
		assert.ErrorIs(t, err, testErr)
	})

	t.Run("IsDirty error", func(t *testing.T) {
		_, err := mockClient.IsDirty(t.Context(), "/test")
		assert.ErrorIs(t, err, testErr)
	})

	mockClient.AssertExpectations(t)
}

func TestMockClientWithAnyArgs(t *testing.T) {
	expectedInfo := &GitInfo{
		CommitHash: "abc123",
		Branch:     "develop",
	}

	mockClient := NewMockClient()

	mockClient.On("GetInfo", mock.Anything, mock.Anything).Return(expectedInfo, nil)
	mockClient.On("IsGitRepository", mock.Anything, mock.Anything).Return(true)
	mockClient.On("GetCommitHash", mock.Anything, mock.Anything).Return("abc123", nil)
	mockClient.On("GetBranch", mock.Anything, mock.Anything).Return("develop", nil)
	mockClient.On("IsDirty", mock.Anything, mock.Anything).Return(true, nil)
	mockClient.On("GetHTMLURL", mock.Anything).Return("https://example.com/repo")

	info, _ := mockClient.GetInfo(t.Context(), "/any/path")
	assert.Equal(t, "abc123", info.CommitHash)

	isRepo := mockClient.IsGitRepository(t.Context(), "/another/path")
	assert.True(t, isRepo)

	commitHash, _ := mockClient.GetCommitHash(t.Context(), "/some/path")
	assert.Equal(t, "abc123", commitHash)

	branch, _ := mockClient.GetBranch(t.Context(), "/some/path")
	assert.Equal(t, "develop", branch)

	dirty, _ := mockClient.IsDirty(t.Context(), "/yet/another")
	assert.True(t, dirty)

	url := mockClient.GetHTMLURL("any-url")
	assert.Equal(t, "https://example.com/repo", url)

	mockClient.AssertExpectations(t)
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrNotGitRepository", ErrNotGitRepository, "not a git repository"},
		{"ErrEmptyRepository", ErrEmptyRepository, "repository has no commits"},
		{"ErrInvalidCommitFormat", ErrInvalidCommitFormat, "invalid commit log format"},
		{"ErrPathNotFound", ErrPathNotFound, "path does not exist"},
		{"ErrGitNotFound", ErrGitNotFound, "git binary not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestGetInfoIntegration(t *testing.T) {
	repoRoot := findGitRoot(t)
	if repoRoot == "" {
		t.Skip("Not in a git repository")
	}

	tests := []struct {
		name     string
		opts     []Option
		validate func(*testing.T, *GitInfo)
	}{
		{
			name: "default options",
			opts: nil,
			validate: func(t *testing.T, info *GitInfo) {
				assert.NotEmpty(t, info.CommitHash)
			},
		},
		{
			name: "with all remotes",
			opts: []Option{WithIncludeAllRemotes(true)},
			validate: func(t *testing.T, info *GitInfo) {
				// Remotes may or may not be present
				assert.NotEmpty(t, info.CommitHash)
			},
		},
		{
			name: "with refs",
			opts: []Option{WithIncludeRefs(true)},
			validate: func(t *testing.T, info *GitInfo) {
				// Refs should be present (at least the current branch)
				assert.NotEmpty(t, info.CommitHash)
			},
		},
		{
			name: "with commit digest",
			opts: []Option{
				WithIncludeCommitDigest(true),
				WithHashAlgorithms([]string{hash.AlgorithmSHA256}),
			},
			validate: func(t *testing.T, info *GitInfo) {
				assert.NotEmpty(t, info.CommitDigest)
				_, ok := info.CommitDigest[hash.AlgorithmSHA256]
				assert.True(t, ok, "CommitDigest should contain sha256")
			},
		},
		{
			name: "with binary hash",
			opts: []Option{
				WithIncludeBinaryHash(true),
				WithHashAlgorithms([]string{hash.AlgorithmSHA256}),
			},
			validate: func(t *testing.T, info *GitInfo) {
				assert.NotEmpty(t, info.GitBinaryHash)
			},
		},
		{
			name: "without signature",
			opts: []Option{WithIncludeSignature(false)},
			validate: func(t *testing.T, info *GitInfo) {
				assert.Empty(t, info.Signature)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(t.Context(), tt.opts...)
			require.NoError(t, err)

			info, err := client.GetInfo(t.Context(), repoRoot)
			require.NoError(t, err)

			tt.validate(t, info)
		})
	}
}

// findGitRoot finds the root of the git repository.
func findGitRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	path := cwd
	for {
		if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return ""
		}
		path = parent
	}
}

var _ = time.Now
