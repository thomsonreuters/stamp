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
	"time"
)

// GitInfo contains comprehensive information about a Git repository.
type GitInfo struct {
	// Commit Information
	CommitHash         string    `json:"commit_hash"`
	TreeHash           string    `json:"tree_hash"`
	ParentHashes       []string  `json:"parent_hashes,omitempty"`
	AuthorName         string    `json:"author_name"`
	AuthorEmail        string    `json:"author_email"`
	AuthorTimestamp    time.Time `json:"author_timestamp"`
	CommitterName      string    `json:"committer_name"`
	CommitterEmail     string    `json:"committer_email"`
	CommitterTimestamp time.Time `json:"committer_timestamp"`
	Message            string    `json:"message"`
	Signature          string    `json:"signature,omitempty"`

	// Repository State
	Branch         string                `json:"branch"`
	IsDetachedHead bool                  `json:"is_detached_head"`
	IsShallowClone bool                  `json:"is_shallow_clone"`
	IsDirty        bool                  `json:"is_dirty"`
	FileStatus     map[string]FileStatus `json:"file_status,omitempty"`

	// Remote Information
	RemoteOriginURL string       `json:"remote_origin_url,omitempty"`
	Remotes         []RemoteInfo `json:"remotes,omitempty"`

	// Tags
	Tags []TagInfo `json:"tags,omitempty"`

	// Submodules
	Submodules []SubmoduleInfo `json:"submodules,omitempty"`

	// Refs pointing to current commit (e.g., refs/heads/main, refs/tags/v1.0)
	Refs []string `json:"refs,omitempty"`

	// CommitDigest contains multiple hash digests of the commit
	CommitDigest map[string]string `json:"commit_digest,omitempty"`

	// Git Binary Information
	GitVersion    string            `json:"git_version"`
	GitPath       string            `json:"git_path"`
	GitBinaryHash map[string]string `json:"git_binary_hash,omitempty"`
}

// FileStatus represents the status of a file in the working directory.
type FileStatus struct {
	Staging  string `json:"staging"`
	Worktree string `json:"worktree"`
}

// RemoteInfo represents a Git remote configuration.
type RemoteInfo struct {
	Name     string `json:"name"`
	FetchURL string `json:"fetch_url"`
	PushURL  string `json:"push_url"`
}

// TagInfo represents a Git tag with its metadata.
type TagInfo struct {
	Name         string    `json:"name"`
	TaggerName   string    `json:"tagger_name,omitempty"`
	TaggerEmail  string    `json:"tagger_email,omitempty"`
	When         time.Time `json:"when,omitzero"`
	PGPSignature string    `json:"pgp_signature,omitempty"`
	Message      string    `json:"message,omitempty"`
}

// SubmoduleInfo represents a Git submodule.
type SubmoduleInfo struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
	URL    string `json:"url,omitempty"`
	Branch string `json:"branch,omitempty"`
	Status string `json:"status"`
}

// Validate checks if the GitInfo has all required fields.
func (g *GitInfo) Validate() error {
	if g.CommitHash == "" {
		return ErrEmptyRepository
	}
	return nil
}

// IsClean returns true if the repository has no uncommitted changes.
func (g *GitInfo) IsClean() bool {
	return !g.IsDirty
}

// HasRemote returns true if the repository has at least one remote configured.
func (g *GitInfo) HasRemote() bool {
	return g.RemoteOriginURL != "" || len(g.Remotes) > 0
}
