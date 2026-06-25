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
	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Options configures the Git client.
type Options struct {
	// Logger for logging operations (optional)
	Logger logger.Logger

	// Executor for running git commands (optional, defaults to OS executor)
	Executor executor.CommandExecutor

	// IncludeSignature includes GPG signature in commit info (default: true)
	IncludeSignature bool

	// IncludeAllRemotes includes all remotes, not just origin (default: false)
	IncludeAllRemotes bool

	// IncludeTags includes tag information (default: false)
	IncludeTags bool

	// IncludeSubmodules includes submodule information (default: false)
	IncludeSubmodules bool

	// IncludeBinaryHash includes hash of git binary (default: false)
	IncludeBinaryHash bool

	// IncludeRefs includes git refs pointing to HEAD (default: false)
	IncludeRefs bool

	// IncludeCommitDigest includes multiple hash digests of commit (default: false)
	IncludeCommitDigest bool

	// HashAlgorithms specifies which hash algorithms to use for git binary and commit digest.
	// Supported: sha256, sha512, blake3, sha3-256, sha3-512 (plus sha1 for commit digest only).
	// (default: ["sha256"])
	HashAlgorithms []string
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions() Options {
	return Options{
		IncludeSignature:  true,
		IncludeAllRemotes: false,
		IncludeTags:       false,
		IncludeSubmodules: false,
		IncludeBinaryHash: false,
		HashAlgorithms:    []string{hash.AlgorithmSHA256},
	}
}

// Option is a function that modifies Options.
type Option func(*Options)

// WithLogger sets the logger.
func WithLogger(l logger.Logger) Option {
	return func(o *Options) {
		o.Logger = l
	}
}

// WithExecutor sets the command executor.
func WithExecutor(e executor.CommandExecutor) Option {
	return func(o *Options) {
		o.Executor = e
	}
}

// WithIncludeSignature enables/disables GPG signature collection.
func WithIncludeSignature(include bool) Option {
	return func(o *Options) {
		o.IncludeSignature = include
	}
}

// WithIncludeAllRemotes enables/disables collection of all remotes.
func WithIncludeAllRemotes(include bool) Option {
	return func(o *Options) {
		o.IncludeAllRemotes = include
	}
}

// WithIncludeTags enables/disables tag collection.
func WithIncludeTags(include bool) Option {
	return func(o *Options) {
		o.IncludeTags = include
	}
}

// WithIncludeSubmodules enables/disables submodule collection.
func WithIncludeSubmodules(include bool) Option {
	return func(o *Options) {
		o.IncludeSubmodules = include
	}
}

// WithIncludeBinaryHash enables/disables git binary hash collection.
func WithIncludeBinaryHash(include bool) Option {
	return func(o *Options) {
		o.IncludeBinaryHash = include
	}
}

// WithHashAlgorithms sets the hash algorithms to use.
func WithHashAlgorithms(algorithms []string) Option {
	return func(o *Options) {
		o.HashAlgorithms = algorithms
	}
}

// WithIncludeRefs enables/disables ref collection.
func WithIncludeRefs(include bool) Option {
	return func(o *Options) {
		o.IncludeRefs = include
	}
}

// WithIncludeCommitDigest enables/disables commit digest collection.
func WithIncludeCommitDigest(include bool) Option {
	return func(o *Options) {
		o.IncludeCommitDigest = include
	}
}
