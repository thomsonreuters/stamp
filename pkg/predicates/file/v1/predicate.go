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

// Package v1 provides type definitions for file/folder attestation predicates.
// These types represent file and directory metadata, hashes, and capture
// configuration for generating file attestations.
//
// The predicate structure follows the custom attestation format with support
// for Material/Product attestation patterns as used in Witness and in-toto.
package v1

import "time"

const (
	// PredicateURI is the unique identifier for the file attestation predicate type.
	// This URI distinguishes file attestations from other attestation types in the framework.
	PredicateURI = "https://github.com/thomsonreuters/stamp/file/v1"
)

type Predicate struct {
	AttestorConfig AttestorConfig  `json:"attestor_config"`
	Artifacts      []ArtifactInfo  `json:"artifacts"`
	Directories    []DirectoryInfo `json:"directories,omitempty"`
	Summary        Summary         `json:"summary"`
}

// AttestorConfig captures the configuration used during attestation.
// This allows verification tools to understand how the attestation was
// performed and what options were used.
type AttestorConfig struct {
	// BasePath is the base directory from which relative paths are resolved.
	BasePath string `json:"base_path"`

	// FollowSymlinks indicates whether symbolic links were followed or
	// recorded as symlinks during collection.
	FollowSymlinks bool `json:"follow_symlinks"`

	// HashAlgorithms lists the cryptographic hash algorithms used to
	// compute file digests (e.g., ["sha256", "sha512"]).
	HashAlgorithms []string `json:"hash_algorithms"`

	// CapturePermissions indicates whether Unix file permissions were captured.
	CapturePermissions bool `json:"capture_permissions"`

	// CaptureTimestamps indicates whether file timestamps were captured.
	CaptureTimestamps bool `json:"capture_timestamps"`

	// CaptureOwnership indicates whether file ownership (UID/GID) was captured.
	CaptureOwnership bool `json:"capture_ownership"`

	// ExcludePatterns contains the glob patterns used to exclude files
	// and directories from attestation (can be empty).
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`

	// IncludePatterns contains the glob patterns used to explicitly include
	// files during attestation (can be empty if all files included).
	IncludePatterns []string `json:"include_patterns,omitempty"`
}

// ArtifactInfo represents a single file artifact with its metadata,
// hashes, and optional attributes.
type ArtifactInfo struct {
	// Path is the file path relative to the base path.
	Path string `json:"path"`

	// Type indicates the artifact type: "file" or "symlink".
	Type string `json:"type"`

	// Size is the file size in bytes (0 for symlinks).
	Size int64 `json:"size"`

	// Digests contains cryptographic hashes of the file content,
	// keyed by algorithm name (e.g., "sha256", "sha512").
	Digests map[string]string `json:"digests"`

	// Permissions contains Unix file permission information
	// (included only if capture-permissions was enabled).
	Permissions *PermissionInfo `json:"permissions,omitempty"`

	// Ownership contains file ownership information
	// (included only if capture-ownership was enabled).
	Ownership *OwnershipInfo `json:"ownership,omitempty"`

	// Timestamps contains file timestamp information
	// (included only if capture-timestamps was enabled).
	Timestamps *TimestampInfo `json:"timestamps,omitempty"`

	// Symlink contains symbolic link target information
	// (included only for symlink artifacts).
	Symlink *SymlinkInfo `json:"symlink,omitempty"`
}

// DirectoryInfo represents a directory with its metadata and contents summary.
type DirectoryInfo struct {
	// Path is the directory path relative to the base path.
	Path string `json:"path"`

	// Type is always "directory" for directory entries.
	Type string `json:"type"`

	// Permissions contains Unix directory permission information
	// (included only if capture-permissions was enabled).
	Permissions *PermissionInfo `json:"permissions,omitempty"`

	// FileCount is the number of files directly in this directory.
	FileCount int `json:"file_count"`

	// DirectoryCount is the number of subdirectories directly in this directory.
	DirectoryCount int `json:"directory_count"`
}

// PermissionInfo represents Unix file permissions in multiple formats
// for both machine and human readability.
type PermissionInfo struct {
	// Mode is the permission bits in octal format (e.g., "0644", "0755").
	Mode string `json:"mode"`

	// Symbolic is the permission bits in symbolic format for human readability
	// (e.g., "-rw-r--r--", "drwxr-xr-x").
	Symbolic string `json:"symbolic"`
}

// OwnershipInfo represents file ownership with both numeric IDs and names.
// Name fields may be empty if the UID/GID cannot be resolved to a name.
type OwnershipInfo struct {
	// UID is the user ID that owns the file.
	UID int `json:"uid"`

	// GID is the group ID that owns the file.
	GID int `json:"gid"`

	// User is the username corresponding to UID (empty if not resolvable).
	User string `json:"user,omitempty"`

	// Group is the group name corresponding to GID (empty if not resolvable).
	Group string `json:"group,omitempty"`
}

// TimestampInfo represents file timestamps.
// Timestamp availability and semantics may vary by platform.
type TimestampInfo struct {
	// Modified is the file modification time (mtime).
	Modified time.Time `json:"modified,omitzero"`

	// Accessed is the file access time (atime).
	Accessed time.Time `json:"accessed,omitzero"`

	// Created is the file creation or change time (ctime or btime depending on platform).
	Created time.Time `json:"created,omitzero"`
}

// SymlinkInfo represents symbolic link information.
// This is only present for artifacts of type "symlink".
type SymlinkInfo struct {
	// IsSymlink is true if the artifact is a symbolic link.
	IsSymlink bool `json:"is_symlink"`

	// Target is the path that the symbolic link points to
	// (may be relative or absolute depending on the symlink).
	Target string `json:"target,omitempty"`
}

// Summary contains aggregate statistics about the file attestation.
type Summary struct {
	// TotalFiles is the total number of files captured in the attestation.
	TotalFiles int `json:"total_files"`

	// TotalDirectories is the total number of directories captured.
	TotalDirectories int `json:"total_directories"`

	// TotalSize is the total size in bytes of all captured files.
	TotalSize int64 `json:"total_size"`

	// CaptureTime is the timestamp when the attestation capture began.
	CaptureTime time.Time `json:"capture_time"`

	// Duration is the time taken to complete the attestation capture
	// (formatted as a string, e.g., "1.234s").
	Duration string `json:"duration"`
}
