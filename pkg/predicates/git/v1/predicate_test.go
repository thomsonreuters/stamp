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
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/git/v1", PredicateURI)
}

func TestPredicate_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := Predicate{
		Repository: RepositoryInfo{
			URL:    "https://github.com/org/repo.git",
			Branch: "main",
		},
		Commit: CommitMetadata{
			Hash:     "abc123def456",
			TreeHash: "tree789",
			ParentHashes: []string{
				"parent1",
				"parent2",
			},
			Author: PersonInfo{
				Name:      "John Doe",
				Email:     "john@example.com",
				Timestamp: now,
			},
			Committer: PersonInfo{
				Name:      "Jane Smith",
				Email:     "jane@example.com",
				Timestamp: now,
			},
			Message:   "Initial commit",
			Signature: "-----BEGIN PGP SIGNATURE-----",
			CommitDigest: DigestSet{
				"sha1":   "abc123",
				"sha256": "def456",
			},
		},
		RepositoryStatus: RepositoryStatus{
			IsDirty: false,
			FileStatus: map[string]FileStatus{
				"file1.txt": {Staging: "M", Worktree: " "},
			},
			DetachedHead: false,
			ShallowClone: false,
		},
		GitBinary: &GitBinaryInfo{
			Tool: "git version 2.39.0",
			Path: "/usr/bin/git",
			Hash: DigestSet{
				"sha256": "git-sha256",
			},
		},
		Refs: []string{"refs/heads/main", "refs/tags/v1.0.0"},
		Remotes: []RemoteInfo{
			{
				Name:     "origin",
				FetchURL: "https://github.com/org/repo.git",
				PushURL:  "https://github.com/org/repo.git",
			},
		},
		Tags: []TagInfo{
			{
				Name:        "v1.0.0",
				TaggerName:  "Release Bot",
				TaggerEmail: "bot@example.com",
				When:        now,
				Message:     "Release 1.0.0",
			},
		},
		Submodules: []SubmoduleInfo{
			{
				Path:   "vendor/lib",
				Commit: "submodule123",
				URL:    "https://github.com/vendor/lib.git",
				Branch: "main",
				Status: " ",
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "repository")
	assert.Contains(t, string(data), "commit")
	assert.Contains(t, string(data), "repository_status")
	assert.Contains(t, string(data), "git_binary")
}

func TestPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"repository": {
			"url": "https://github.com/test/repo.git",
			"branch": "develop"
		},
		"commit": {
			"hash": "commit123",
			"tree_hash": "tree456",
			"author": {
				"name": "Author",
				"email": "author@example.com",
				"timestamp": "2025-11-12T10:00:00Z"
			},
			"committer": {
				"name": "Committer",
				"email": "committer@example.com",
				"timestamp": "2025-11-12T10:05:00Z"
			},
			"message": "Test commit"
		},
		"repository_status": {
			"is_dirty": true,
			"file_status": {
				"test.txt": {"staging": "A", "worktree": " "}
			},
			"detached_head": false,
			"shallow_clone": false
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "https://github.com/test/repo.git", predicate.Repository.URL)
	assert.Equal(t, "develop", predicate.Repository.Branch)
	assert.Equal(t, "commit123", predicate.Commit.Hash)
	assert.True(t, predicate.RepositoryStatus.IsDirty)
}

func TestRepositoryInfo_Complete(t *testing.T) {
	repository := RepositoryInfo{
		URL:    "https://github.com/org/project.git",
		Branch: "feature/new-feature",
	}

	data, err := json.Marshal(repository)
	require.NoError(t, err)

	var result RepositoryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, repository.URL, result.URL)
	assert.Equal(t, repository.Branch, result.Branch)
}

func TestRepositoryInfo_DetachedHead(t *testing.T) {
	repository := RepositoryInfo{
		URL: "https://github.com/org/repo.git",
	}

	data, err := json.Marshal(repository)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "branch")
}

func TestCommitMetadata_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	commit := CommitMetadata{
		Hash:     "1a2b3c4d5e6f",
		TreeHash: "tree9876",
		ParentHashes: []string{
			"parent1abc",
			"parent2def",
		},
		Author: PersonInfo{
			Name:      "Alice",
			Email:     "alice@example.com",
			Timestamp: now,
		},
		Committer: PersonInfo{
			Name:      "Bob",
			Email:     "bob@example.com",
			Timestamp: now.Add(5 * time.Minute),
		},
		Message:   "Fix critical bug",
		Signature: "-----BEGIN PGP SIGNATURE-----\nfoo\n-----END PGP SIGNATURE-----",
		CommitDigest: DigestSet{
			"sha1":   "1a2b3c",
			"sha256": "def456",
			"sha512": "789abc",
		},
	}

	data, err := json.Marshal(commit)
	require.NoError(t, err)

	var result CommitMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, commit.Hash, result.Hash)
	assert.Equal(t, commit.TreeHash, result.TreeHash)
	assert.Len(t, result.ParentHashes, 2)
	assert.Equal(t, commit.Message, result.Message)
}

func TestCommitMetadata_OmitEmptyFields(t *testing.T) {
	now := time.Now()

	commit := CommitMetadata{
		Hash:     "abc123",
		TreeHash: "tree456",
		Author: PersonInfo{
			Name:      "Author",
			Email:     "author@test.com",
			Timestamp: now,
		},
		Committer: PersonInfo{
			Name:      "Committer",
			Email:     "committer@test.com",
			Timestamp: now,
		},
		Message: "Simple commit",
	}

	data, err := json.Marshal(commit)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "parenthashes")
	assert.NotContains(t, string(data), "signature")
	assert.NotContains(t, string(data), "commitdigest")
}

func TestPersonInfo_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 15, 30, 0, 0, time.UTC)

	person := PersonInfo{
		Name:      "Test User",
		Email:     "test@example.com",
		Timestamp: now,
	}

	data, err := json.Marshal(person)
	require.NoError(t, err)

	var result PersonInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "Test User", result.Name)
	assert.Equal(t, "test@example.com", result.Email)
	assert.Equal(t, now.Unix(), result.Timestamp.Unix())
}

func TestDigestSet_MultipleAlgorithms(t *testing.T) {
	digests := DigestSet{
		"sha1":   "abc123",
		"sha256": "def456789",
		"sha512": "0123456789abcdef",
		"md5":    "fedcba",
	}

	data, err := json.Marshal(digests)
	require.NoError(t, err)

	var result DigestSet
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result, 4)
	assert.Equal(t, "abc123", result["sha1"])
	assert.Equal(t, "def456789", result["sha256"])
	assert.Equal(t, "0123456789abcdef", result["sha512"])
	assert.Equal(t, "fedcba", result["md5"])
}

func TestDigestSet_Empty(t *testing.T) {
	digests := DigestSet{}

	data, err := json.Marshal(digests)
	require.NoError(t, err)

	var result DigestSet
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.NotNil(t, result)
}

func TestRepositoryStatus_Clean(t *testing.T) {
	status := RepositoryStatus{
		IsDirty:      false,
		FileStatus:   make(map[string]FileStatus),
		DetachedHead: false,
		ShallowClone: false,
	}

	data, err := json.Marshal(status)
	require.NoError(t, err)

	var result RepositoryStatus
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.False(t, result.IsDirty)
	assert.False(t, result.DetachedHead)
	assert.False(t, result.ShallowClone)
}

func TestRepositoryStatus_Dirty(t *testing.T) {
	status := RepositoryStatus{
		IsDirty: true,
		FileStatus: map[string]FileStatus{
			"modified.txt":  {Staging: "M", Worktree: " "},
			"new.txt":       {Staging: "A", Worktree: " "},
			"deleted.txt":   {Staging: "D", Worktree: " "},
			"untracked.txt": {Staging: "?", Worktree: "?"},
		},
		DetachedHead: false,
		ShallowClone: false,
	}

	data, err := json.Marshal(status)
	require.NoError(t, err)

	var result RepositoryStatus
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.IsDirty)
	assert.Len(t, result.FileStatus, 4)
	assert.Equal(t, "M", result.FileStatus["modified.txt"].Staging)
	assert.Equal(t, "A", result.FileStatus["new.txt"].Staging)
}

func TestRepositoryStatus_DetachedHead(t *testing.T) {
	status := RepositoryStatus{
		IsDirty:      false,
		FileStatus:   make(map[string]FileStatus),
		DetachedHead: true,
		ShallowClone: false,
	}

	data, err := json.Marshal(status)
	require.NoError(t, err)

	var result RepositoryStatus
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.DetachedHead)
}

func TestRepositoryStatus_ShallowClone(t *testing.T) {
	status := RepositoryStatus{
		IsDirty:      false,
		FileStatus:   make(map[string]FileStatus),
		DetachedHead: false,
		ShallowClone: true,
	}

	data, err := json.Marshal(status)
	require.NoError(t, err)

	var result RepositoryStatus
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.True(t, result.ShallowClone)
}

func TestFileStatus_Staging(t *testing.T) {
	tests := []struct {
		name     string
		staging  string
		worktree string
		desc     string
	}{
		{
			name:     "Modified",
			staging:  "M",
			worktree: " ",
			desc:     "Modified in staging",
		},
		{
			name:     "Added",
			staging:  "A",
			worktree: " ",
			desc:     "Added to staging",
		},
		{
			name:     "Deleted",
			staging:  "D",
			worktree: " ",
			desc:     "Deleted from staging",
		},
		{
			name:     "Renamed",
			staging:  "R",
			worktree: " ",
			desc:     "Renamed in staging",
		},
		{
			name:     "Copied",
			staging:  "C",
			worktree: " ",
			desc:     "Copied in staging",
		},
		{
			name:     "Updated",
			staging:  "U",
			worktree: " ",
			desc:     "Updated but unmerged",
		},
		{
			name:     "Untracked",
			staging:  "?",
			worktree: "?",
			desc:     "Untracked file",
		},
		{
			name:     "Ignored",
			staging:  "!",
			worktree: "!",
			desc:     "Ignored file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileStatus := FileStatus{
				Staging:  tt.staging,
				Worktree: tt.worktree,
			}

			data, err := json.Marshal(fileStatus)
			require.NoError(t, err)

			var result FileStatus
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.staging, result.Staging)
			assert.Equal(t, tt.worktree, result.Worktree)
		})
	}
}

func TestGitBinaryInfo_Complete(t *testing.T) {
	gitBinaryInfo := GitBinaryInfo{
		Tool: "git version 2.42.0",
		Path: "/usr/local/bin/git",
		Hash: DigestSet{
			"sha256": "abc123def456",
			"sha512": "789012345678",
		},
	}

	data, err := json.Marshal(gitBinaryInfo)
	require.NoError(t, err)

	var result GitBinaryInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "git version 2.42.0", result.Tool)
	assert.Equal(t, "/usr/local/bin/git", result.Path)
	assert.Len(t, result.Hash, 2)
}

func TestRemoteInfo_Complete(t *testing.T) {
	remoteInfo := RemoteInfo{
		Name:     "origin",
		FetchURL: "https://github.com/org/repo.git",
		PushURL:  "git@github.com:org/repo.git",
	}

	data, err := json.Marshal(remoteInfo)
	require.NoError(t, err)

	var result RemoteInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "origin", result.Name)
	assert.Equal(t, "https://github.com/org/repo.git", result.FetchURL)
	assert.Equal(t, "git@github.com:org/repo.git", result.PushURL)
}

func TestRemoteInfo_SameURLs(t *testing.T) {
	remoteInfo := RemoteInfo{
		Name:     "upstream",
		FetchURL: "https://github.com/upstream/repo.git",
		PushURL:  "https://github.com/upstream/repo.git",
	}

	data, err := json.Marshal(remoteInfo)
	require.NoError(t, err)

	var result RemoteInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, result.FetchURL, result.PushURL)
}

func TestTagInfo_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	tagInfo := TagInfo{
		Name:         "v2.0.0",
		TaggerName:   "Release Manager",
		TaggerEmail:  "release@example.com",
		When:         now,
		PGPSignature: "-----BEGIN PGP SIGNATURE-----\ndata\n-----END PGP SIGNATURE-----",
		Message:      "Major release 2.0.0\n\nBreaking changes included.",
	}

	data, err := json.Marshal(tagInfo)
	require.NoError(t, err)

	var result TagInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "v2.0.0", result.Name)
	assert.Equal(t, "Release Manager", result.TaggerName)
	assert.Contains(t, result.Message, "Major release")
	assert.NotEmpty(t, result.PGPSignature)
}

func TestTagInfo_OmitEmptySignature(t *testing.T) {
	now := time.Now()

	tagInfo := TagInfo{
		Name:        "v1.0.0",
		TaggerName:  "Developer",
		TaggerEmail: "dev@example.com",
		When:        now,
		Message:     "First release",
	}

	data, err := json.Marshal(tagInfo)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "pgpsignature")
}

func TestSubmoduleInfo_Complete(t *testing.T) {
	submoduleInfo := SubmoduleInfo{
		Path:   "vendor/module",
		Commit: "abc123def456",
		URL:    "https://github.com/vendor/module.git",
		Branch: "stable",
		Status: " ",
	}

	data, err := json.Marshal(submoduleInfo)
	require.NoError(t, err)

	var result SubmoduleInfo
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "vendor/module", result.Path)
	assert.Equal(t, "abc123def456", result.Commit)
	assert.Equal(t, "https://github.com/vendor/module.git", result.URL)
	assert.Equal(t, "stable", result.Branch)
}

func TestSubmoduleInfo_OmitEmptyFields(t *testing.T) {
	submoduleInfo := SubmoduleInfo{
		Path:   "submodule",
		Commit: "commit123",
		Status: "+",
	}

	data, err := json.Marshal(submoduleInfo)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "url")
	assert.NotContains(t, string(data), "branch")
}

func TestSubmoduleInfo_StatusValues(t *testing.T) {
	tests := []struct {
		name   string
		status string
		desc   string
	}{
		{
			name:   "Clean",
			status: " ",
			desc:   "Submodule is clean",
		},
		{
			name:   "Not initialized",
			status: "-",
			desc:   "Submodule not initialized",
		},
		{
			name:   "Changed",
			status: "+",
			desc:   "Submodule has new commits",
		},
		{
			name:   "Conflict",
			status: "U",
			desc:   "Submodule has merge conflicts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submoduleInfo := SubmoduleInfo{
				Path:   "path/to/sub",
				Commit: "commit123",
				Status: tt.status,
			}

			data, err := json.Marshal(submoduleInfo)
			require.NoError(t, err)

			var result SubmoduleInfo
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.status, result.Status)
		})
	}
}

func TestPredicate_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := Predicate{
		Repository: RepositoryInfo{
			URL:    "https://github.com/org/project.git",
			Branch: "main",
		},
		Commit: CommitMetadata{
			Hash:     "complete123",
			TreeHash: "tree456",
			ParentHashes: []string{
				"parent1",
			},
			Author: PersonInfo{
				Name:      "Author Name",
				Email:     "author@example.com",
				Timestamp: now,
			},
			Committer: PersonInfo{
				Name:      "Committer Name",
				Email:     "committer@example.com",
				Timestamp: now,
			},
			Message: "Complete test",
			CommitDigest: DigestSet{
				"sha256": "digest256",
			},
		},
		RepositoryStatus: RepositoryStatus{
			IsDirty: true,
			FileStatus: map[string]FileStatus{
				"file.txt": {Staging: "M", Worktree: "M"},
			},
			DetachedHead: false,
			ShallowClone: false,
		},
		GitBinary: &GitBinaryInfo{
			Tool: "git version 2.40.0",
			Path: "/usr/bin/git",
			Hash: DigestSet{
				"sha256": "binary256",
			},
		},
		Refs: []string{
			"refs/heads/main",
			"refs/heads/develop",
			"refs/tags/v1.0.0",
		},
		Remotes: []RemoteInfo{
			{
				Name:     "origin",
				FetchURL: "https://github.com/org/project.git",
				PushURL:  "https://github.com/org/project.git",
			},
			{
				Name:     "upstream",
				FetchURL: "https://github.com/upstream/project.git",
				PushURL:  "https://github.com/upstream/project.git",
			},
		},
		Tags: []TagInfo{
			{
				Name:        "v1.0.0",
				TaggerName:  "Tagger",
				TaggerEmail: "tagger@example.com",
				When:        now,
				Message:     "Version 1.0.0",
			},
		},
		Submodules: []SubmoduleInfo{
			{
				Path:   "vendor/lib",
				Commit: "sub123",
				URL:    "https://github.com/vendor/lib.git",
				Status: " ",
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Repository.URL, result.Repository.URL)
	assert.Equal(t, predicate.Commit.Hash, result.Commit.Hash)
	assert.True(t, result.RepositoryStatus.IsDirty)
	assert.NotNil(t, result.GitBinary)
	assert.Len(t, result.Refs, 3)
	assert.Len(t, result.Remotes, 2)
	assert.Len(t, result.Tags, 1)
	assert.Len(t, result.Submodules, 1)
}

func TestPredicate_Minimal(t *testing.T) {
	now := time.Now()

	predicate := Predicate{
		Repository: RepositoryInfo{
			URL:    "https://github.com/test/repo.git",
			Branch: "main",
		},
		Commit: CommitMetadata{
			Hash:     "min123",
			TreeHash: "tree123",
			Author: PersonInfo{
				Name:      "A",
				Email:     "a@test.com",
				Timestamp: now,
			},
			Committer: PersonInfo{
				Name:      "C",
				Email:     "c@test.com",
				Timestamp: now,
			},
			Message: "msg",
		},
		RepositoryStatus: RepositoryStatus{
			IsDirty:      false,
			FileStatus:   make(map[string]FileStatus),
			DetachedHead: false,
			ShallowClone: false,
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "min123", result.Commit.Hash)
	assert.Nil(t, result.GitBinary)
	assert.Empty(t, result.Refs)
	assert.Empty(t, result.Remotes)
	assert.Empty(t, result.Tags)
	assert.Empty(t, result.Submodules)
}

func TestCommitMetadata_MergeCommit(t *testing.T) {
	now := time.Now()

	commit := CommitMetadata{
		Hash:     "merge123",
		TreeHash: "tree789",
		ParentHashes: []string{
			"parent1abc",
			"parent2def",
		},
		Author: PersonInfo{
			Name:      "Merger",
			Email:     "merge@example.com",
			Timestamp: now,
		},
		Committer: PersonInfo{
			Name:      "Merger",
			Email:     "merge@example.com",
			Timestamp: now,
		},
		Message: "Merge branch 'feature' into main",
	}

	data, err := json.Marshal(commit)
	require.NoError(t, err)

	var result CommitMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.ParentHashes, 2, "Merge commit should have 2 parents")
	assert.Contains(t, result.Message, "Merge")
}

func TestCommitMetadata_InitialCommit(t *testing.T) {
	now := time.Now()

	commit := CommitMetadata{
		Hash:     "initial123",
		TreeHash: "tree000",
		Author: PersonInfo{
			Name:      "First",
			Email:     "first@example.com",
			Timestamp: now,
		},
		Committer: PersonInfo{
			Name:      "First",
			Email:     "first@example.com",
			Timestamp: now,
		},
		Message: "Initial commit",
	}

	data, err := json.Marshal(commit)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "parenthashes")

	var result CommitMetadata
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Empty(t, result.ParentHashes, "Initial commit should have no parents")
}

func TestPersonInfo_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"name":"User","email":"user@test.com","timestamp":"2025-11-12T10:00:00Z"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"name":"User","email":"user@test.com","timestamp":"2025-11-12T10:00:00+05:30"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"name":"User","email":"user@test.com","timestamp":"2025-11-12T10:00:00.123456Z"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var person PersonInfo
			err := json.Unmarshal([]byte(tt.jsonTime), &person)

			if tt.valid {
				require.NoError(t, err)
				assert.False(t, person.Timestamp.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestPredicate_OmitEmptyGitBinary(t *testing.T) {
	now := time.Now()

	predicate := Predicate{
		Repository: RepositoryInfo{
			URL:    "https://github.com/test/repo.git",
			Branch: "main",
		},
		Commit: CommitMetadata{
			Hash:     "test123",
			TreeHash: "tree123",
			Author: PersonInfo{
				Name:      "Author",
				Email:     "author@test.com",
				Timestamp: now,
			},
			Committer: PersonInfo{
				Name:      "Committer",
				Email:     "committer@test.com",
				Timestamp: now,
			},
			Message: "Test",
		},
		RepositoryStatus: RepositoryStatus{
			IsDirty:    false,
			FileStatus: make(map[string]FileStatus),
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "gitBinary")
}

func TestRepositoryStatus_MultipleFiles(t *testing.T) {
	status := RepositoryStatus{
		IsDirty: true,
		FileStatus: map[string]FileStatus{
			"file1.go":     {Staging: "M", Worktree: " "},
			"file2.go":     {Staging: "A", Worktree: " "},
			"file3.go":     {Staging: "D", Worktree: " "},
			"README.md":    {Staging: " ", Worktree: "M"},
			"config.yaml":  {Staging: "R", Worktree: " "},
			".gitignore":   {Staging: "M", Worktree: "M"},
			"untracked.go": {Staging: "?", Worktree: "?"},
		},
		DetachedHead: false,
		ShallowClone: false,
	}

	data, err := json.Marshal(status)
	require.NoError(t, err)

	var result RepositoryStatus
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.FileStatus, 7)
	assert.Equal(t, "M", result.FileStatus["file1.go"].Staging)
	assert.Equal(t, "A", result.FileStatus["file2.go"].Staging)
	assert.Equal(t, "M", result.FileStatus["README.md"].Worktree)
}
