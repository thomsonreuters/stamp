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

// Git repository state errors.
var (
	ErrNotGitRepository    = errors.New("not in a Git repository")
	ErrEmptyRepository     = errors.New("repository has no commits")
	ErrInvalidCommitFormat = errors.New("invalid git log output format")
	ErrRepositoryDirty     = errors.New("repository has uncommitted changes")
)

// DirtyBehavior values control how the attestor handles uncommitted changes.
const (
	DirtyBehaviorAllow = "allow"
	DirtyBehaviorWarn  = "warn"
	DirtyBehaviorFail  = "fail"
)

var validDirtyBehaviors = []string{
	DirtyBehaviorAllow,
	DirtyBehaviorWarn,
	DirtyBehaviorFail,
}

// Hash algorithm constants.
const (
	HashAlgorithmSHA1   = "sha1"
	HashAlgorithmSHA256 = "sha256"
	HashAlgorithmSHA512 = "sha512"
)

var validHashAlgorithms = []string{
	HashAlgorithmSHA1,
	HashAlgorithmSHA256,
	HashAlgorithmSHA512,
}

// Default configuration values.
var (
	defaultWorkingDir     = "."
	defaultDirtyBehavior  = DirtyBehaviorAllow
	defaultHashAlgorithms = []string{HashAlgorithmSHA1, HashAlgorithmSHA256}
)
