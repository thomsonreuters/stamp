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

import "errors"

var (
	// ErrNotGitRepository indicates the path is not a git repository.
	ErrNotGitRepository = errors.New("not a git repository")

	// ErrEmptyRepository indicates the repository has no commits.
	ErrEmptyRepository = errors.New("repository has no commits")

	// ErrInvalidCommitFormat indicates the git log output could not be parsed.
	ErrInvalidCommitFormat = errors.New("invalid commit log format")

	// ErrPathNotFound indicates the specified path does not exist.
	ErrPathNotFound = errors.New("path does not exist")

	// ErrGitNotFound indicates the git binary was not found in PATH.
	ErrGitNotFound = errors.New("git binary not found")

	// ErrGitCommand indicates a git command execution failed.
	ErrGitCommand = errors.New("git command failed")

	// ErrBranchNotFound indicates the current branch could not be determined.
	ErrBranchNotFound = errors.New("could not determine current branch")

	// ErrCommitNotFound indicates the commit could not be found.
	ErrCommitNotFound = errors.New("could not find commit")
)
