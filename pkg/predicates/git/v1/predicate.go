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

// Package v1 provides version 1 predicate definitions for Git repository attestations.
package v1

import (
	"time"
)

const (
	// PredicateURI is the custom predicate type URI for Git repository attestations.
	// Following in-toto specification for custom predicate types.
	PredicateURI = "https://github.com/thomsonreuters/stamp/git/v1"
)

type Predicate struct {
	Repository       RepositoryInfo   `json:"repository"`
	Commit           CommitMetadata   `json:"commit"`
	RepositoryStatus RepositoryStatus `json:"repository_status"`
	GitBinary        *GitBinaryInfo   `json:"git_binary,omitempty"`
	Refs             []string         `json:"refs,omitempty"`
	Remotes          []RemoteInfo     `json:"remotes,omitempty"`
	Tags             []TagInfo        `json:"tags,omitempty"`
	Submodules       []SubmoduleInfo  `json:"submodules,omitempty"`
}

// RepositoryInfo contains identifying information about the Git repository.
type RepositoryInfo struct {
	URL    string `json:"url"`
	Branch string `json:"branch,omitempty"`
}

// CommitMetadata holds complete Git commit information.
type CommitMetadata struct {
	Hash         string     `json:"hash"`
	TreeHash     string     `json:"tree_hash"`
	ParentHashes []string   `json:"parent_hashes,omitempty"`
	Author       PersonInfo `json:"author"`
	Committer    PersonInfo `json:"committer"`
	Message      string     `json:"message"`
	Signature    string     `json:"signature,omitempty"`
	CommitDigest DigestSet  `json:"commit_digest,omitempty"`
}

// PersonInfo represents a person in Git (author or committer) with timestamp.
type PersonInfo struct {
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
}

// DigestSet represents multiple hash digests of content.
// Key is algorithm name (e.g., "sha1", "sha256", "sha512").
// Value is hex-encoded hash.
type DigestSet map[string]string

// RepositoryStatus represents the overall repository state.
type RepositoryStatus struct {
	IsDirty      bool                  `json:"is_dirty"`
	FileStatus   map[string]FileStatus `json:"file_status"`
	DetachedHead bool                  `json:"detached_head"`
	ShallowClone bool                  `json:"shallow_clone"`
}

// FileStatus represents the status of a single file in the repository.
// Follows git status --porcelain format.
type FileStatus struct {
	Staging  string `json:"staging"`
	Worktree string `json:"worktree"`
}

// GitBinaryInfo contains information about the Git binary being used.
type GitBinaryInfo struct {
	Tool string    `json:"tool"`
	Path string    `json:"path"`
	Hash DigestSet `json:"hash"`
}

// RemoteInfo represents a Git remote configuration.
type RemoteInfo struct {
	Name     string `json:"name"`
	FetchURL string `json:"fetch_url"`
	PushURL  string `json:"push_url"`
}

// TagInfo represents an annotated Git tag with full metadata.
type TagInfo struct {
	Name         string    `json:"name"`
	TaggerName   string    `json:"tagger_name"`
	TaggerEmail  string    `json:"tagger_email"`
	When         time.Time `json:"when"`
	PGPSignature string    `json:"pgp_signature,omitempty"`
	Message      string    `json:"message"`
}

// SubmoduleInfo represents a Git submodule with its status and metadata.
type SubmoduleInfo struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
	URL    string `json:"url,omitempty"`
	Branch string `json:"branch,omitempty"`
	Status string `json:"status"`
}
