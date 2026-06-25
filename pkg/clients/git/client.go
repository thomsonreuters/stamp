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

// Package git provides a client for collecting Git repository information.
package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/crypto/hash"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// ClientIface defines the interface for Git workspace client.
type ClientIface interface {
	// GetInfo collects comprehensive information about a Git repository.
	GetInfo(ctx context.Context, path string) (*GitInfo, error)

	// IsGitRepository checks if the path is a Git repository.
	IsGitRepository(ctx context.Context, path string) bool

	// GetCommitHash returns the current commit hash.
	GetCommitHash(ctx context.Context, path string) (string, error)

	// GetBranch returns the current branch name.
	GetBranch(ctx context.Context, path string) (string, error)

	// IsDirty checks if the repository has uncommitted changes.
	IsDirty(ctx context.Context, path string) (bool, error)

	// GetHTMLURL converts a Git remote URL to a web-browsable HTTPS URL.
	// Handles SSH URLs (git@host:path), SSH protocol URLs (ssh://git@host/path),
	// and normalizes HTTPS/HTTP URLs by removing .git suffixes.
	GetHTMLURL(remoteURL string) string
}

// Client is the Git workspace client.
type Client struct {
	executor executor.CommandExecutor
	logger   logger.Logger
	opts     Options
}

// GetInfo collects comprehensive information about a Git repository.
func (c *Client) GetInfo(ctx context.Context, path string) (*GitInfo, error) {
	absPath, err := c.validatePath(path)
	if err != nil {
		return nil, err
	}

	if !c.IsGitRepository(ctx, absPath) {
		return nil, ErrNotGitRepository
	}

	info := &GitInfo{}

	if err := c.collectCommitInfo(ctx, absPath, info); err != nil {
		return nil, err
	}

	if err := c.collectRepositoryState(ctx, absPath, info); err != nil {
		return nil, err
	}

	// Collect supplementary information. These are best-effort and don't fail
	// the operation - missing remotes, tags, or binary info are acceptable.
	c.collectRemoteInfo(ctx, absPath, info)
	c.collectOptionalInfo(ctx, absPath, info)
	c.collectGitBinaryInfo(ctx, info)

	return info, nil
}

// IsGitRepository checks if the path is a Git repository.
func (c *Client) IsGitRepository(ctx context.Context, path string) bool {
	cmd := c.executor.CommandContext(ctx, "git", "rev-parse", "--git-dir")
	cmd.SetDir(path)
	return cmd.Run() == nil
}

// GetCommitHash returns the current commit hash.
func (c *Client) GetCommitHash(ctx context.Context, path string) (string, error) {
	output, err := c.gitCommand(ctx, path, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCommitNotFound, err)
	}
	return strings.TrimSpace(output), nil
}

// GetBranch returns the current branch name.
func (c *Client) GetBranch(ctx context.Context, path string) (string, error) {
	output, err := c.gitCommand(ctx, path, "branch", "--show-current")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrBranchNotFound, err)
	}
	return strings.TrimSpace(output), nil
}

// IsDirty checks if the repository has uncommitted changes.
func (c *Client) IsDirty(ctx context.Context, path string) (bool, error) {
	output, err := c.gitCommand(ctx, path, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(output) != "", nil
}

// GetHTMLURL converts a Git remote URL to a web-browsable HTTPS URL.
// Handles SSH URLs (git@host:path), SSH protocol URLs (ssh://git@host/path),
// and normalizes HTTPS/HTTP URLs by removing .git suffixes.
func (c *Client) GetHTMLURL(remoteURL string) string {
	return ToHTMLURL(remoteURL)
}

// validatePath validates and returns the absolute path.
func (c *Client) validatePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrPathNotFound, path)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("%w: %s", ErrPathNotFound, path)
	}

	return absPath, nil
}

// gitCommand executes a git command and returns the output.
func (c *Client) gitCommand(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := c.executor.CommandContext(ctx, "git", args...)
	cmd.SetDir(dir)

	output, err := cmd.Output()
	if err != nil {
		errMsg := err.Error()
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) {
			errMsg = strings.TrimSpace(string(exitErr.Stderr))
		}
		c.logger.DebugContext(ctx, "git command failed",
			"args", strings.Join(args, " "),
			"dir", dir,
			"error", errMsg)
		return "", fmt.Errorf("%w: git %s: %s", ErrGitCommand, args[0], errMsg)
	}

	return string(output), nil
}

func (c *Client) collectCommitInfo(ctx context.Context, path string, info *GitInfo) error {
	// Git log format placeholders:
	// %H = commit hash, %T = tree hash, %P = parent hashes
	// %an = author name, %ae = author email, %at = author timestamp (unix)
	// %cn = committer name, %ce = committer email, %ct = committer timestamp (unix)
	// %s = subject (commit message first line)
	format := fmt.Sprintf("%%H%s%%T%s%%P%s%%an%s%%ae%s%%at%s%%cn%s%%ce%s%%ct%s%%s",
		commitFieldSeparator, commitFieldSeparator, commitFieldSeparator,
		commitFieldSeparator, commitFieldSeparator, commitFieldSeparator,
		commitFieldSeparator, commitFieldSeparator, commitFieldSeparator)

	output, err := c.gitCommand(ctx, path, "log", "-1", "--format="+format)
	if err != nil {
		return err
	}

	parsed, err := parseCommitLog(output)
	if err != nil {
		return err
	}

	info.CommitHash = parsed.CommitHash
	info.TreeHash = parsed.TreeHash
	info.ParentHashes = parsed.ParentHashes
	info.AuthorName = parsed.AuthorName
	info.AuthorEmail = parsed.AuthorEmail
	info.AuthorTimestamp = parsed.AuthorTimestamp
	info.CommitterName = parsed.CommitterName
	info.CommitterEmail = parsed.CommitterEmail
	info.CommitterTimestamp = parsed.CommitterTimestamp
	info.Message = parsed.Message

	if c.opts.IncludeSignature {
		sigOutput, err := c.gitCommand(ctx, path, "log", "-1", "--format=%GG")
		if err == nil {
			info.Signature = strings.TrimSpace(sigOutput)
		}
	}

	return nil
}

func (c *Client) collectRepositoryState(ctx context.Context, path string, info *GitInfo) error {
	branchOutput, err := c.gitCommand(ctx, path, "branch", "--show-current")
	if err != nil {
		return err
	}

	branch, isDetached := parseBranch(branchOutput)
	info.Branch = branch
	info.IsDetachedHead = isDetached

	shallowOutput, _ := c.gitCommand(ctx, path, "rev-parse", "--is-shallow-repository")
	info.IsShallowClone = isShallowClone(shallowOutput)

	statusOutput, err := c.gitCommand(ctx, path, "status", "--porcelain")
	if err != nil {
		return err
	}

	isDirty, fileStatus := parseRepositoryStatus(statusOutput)
	info.IsDirty = isDirty
	info.FileStatus = fileStatus

	return nil
}

func (c *Client) collectRemoteInfo(ctx context.Context, path string, info *GitInfo) {
	originOutput, err := c.gitCommand(ctx, path, "config", "--get", "remote.origin.url")
	if err == nil {
		info.RemoteOriginURL = utils.SanitizeURL(parseOriginURL(originOutput))
	}

	if c.opts.IncludeAllRemotes {
		remotesOutput, err := c.gitCommand(ctx, path, "remote", "-v")
		if err == nil {
			remotes := parseRemoteInfo(remotesOutput)
			for i := range remotes {
				remotes[i].FetchURL = utils.SanitizeURL(remotes[i].FetchURL)
				remotes[i].PushURL = utils.SanitizeURL(remotes[i].PushURL)
			}
			info.Remotes = remotes
		}
	}
}

func (c *Client) collectOptionalInfo(ctx context.Context, path string, info *GitInfo) {
	if c.opts.IncludeTags {
		c.collectTags(ctx, path, info)
	}
	if c.opts.IncludeSubmodules {
		c.collectSubmodules(ctx, path, info)
	}
	if c.opts.IncludeRefs {
		c.collectRefs(ctx, path, info)
	}
	if c.opts.IncludeCommitDigest {
		c.collectCommitDigest(ctx, path, info)
	}
}

func (c *Client) collectTags(ctx context.Context, path string, info *GitInfo) {
	output, err := c.gitCommand(ctx, path, "tag", "--points-at", "HEAD",
		"--format=%(refname:short)|%(taggername)|%(taggeremail)|%(taggerdate:unix)|%(contents:signature)|%(contents:subject)")
	if err == nil && output != "" {
		info.Tags = parseTagInfo(output)
	}
}

func (c *Client) collectSubmodules(ctx context.Context, path string, info *GitInfo) {
	output, err := c.gitCommand(ctx, path, "submodule", "status")
	if err == nil && output != "" {
		info.Submodules = parseSubmoduleStatus(output)

		for i := range info.Submodules {
			subPath := info.Submodules[i].Path
			if urlOutput, err := c.gitCommand(ctx, path, "config", "--get", "submodule."+subPath+".url"); err == nil {
				info.Submodules[i].URL = strings.TrimSpace(urlOutput)
			}
			if branchOutput, err := c.gitCommand(ctx, path, "config", "--get", "submodule."+subPath+".branch"); err == nil {
				info.Submodules[i].Branch = strings.TrimSpace(branchOutput)
			}
		}
	}
}

func (c *Client) collectRefs(ctx context.Context, path string, info *GitInfo) {
	output, err := c.gitCommand(ctx, path, "for-each-ref", "--points-at=HEAD", "--format=%(refname)")
	if err != nil || output == "" {
		return
	}

	for ref := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		if ref = strings.TrimSpace(ref); ref != "" {
			info.Refs = append(info.Refs, ref)
		}
	}
}

func (c *Client) collectCommitDigest(ctx context.Context, path string, info *GitInfo) {
	if info.CommitHash == "" {
		return
	}

	output, err := c.gitCommand(ctx, path, "cat-file", "-p", info.CommitHash)
	if err != nil || output == "" {
		return
	}

	supportedAlgos := make([]string, 0, len(c.opts.HashAlgorithms))
	for _, algo := range c.opts.HashAlgorithms {
		if hash.ValidateAlgorithm(algo) {
			supportedAlgos = append(supportedAlgos, algo)
		}
	}
	if len(supportedAlgos) == 0 {
		return
	}

	hasher := hash.New(hash.Config{Algorithms: supportedAlgos})
	result, err := hasher.HashBytes(ctx, []byte(output), "commit:"+info.CommitHash)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to hash commit", "error", err)
		return
	}
	info.CommitDigest = result.Digests

	for _, algo := range c.opts.HashAlgorithms {
		if strings.ToLower(algo) == "sha1" {
			if info.CommitDigest == nil {
				info.CommitDigest = make(map[string]string)
			}
			info.CommitDigest["sha1"] = info.CommitHash
		}
	}
}

func (c *Client) collectGitBinaryInfo(ctx context.Context, info *GitInfo) {
	if versionOutput, err := c.gitCommand(ctx, ".", "version"); err == nil {
		info.GitVersion = parseGitVersion(versionOutput)
	}

	if gitPath, err := exec.LookPath("git"); err == nil {
		info.GitPath = gitPath
	}

	if c.opts.IncludeBinaryHash && info.GitPath != "" {
		info.GitBinaryHash = c.calculateFileHashes(ctx, info.GitPath)
	}
}

func (c *Client) calculateFileHashes(ctx context.Context, filePath string) map[string]string {
	supportedAlgos := make([]string, 0, len(c.opts.HashAlgorithms))
	for _, algo := range c.opts.HashAlgorithms {
		if hash.ValidateAlgorithm(algo) {
			supportedAlgos = append(supportedAlgos, algo)
		}
	}
	if len(supportedAlgos) == 0 {
		return make(map[string]string)
	}

	hasher := hash.New(hash.Config{Algorithms: supportedAlgos})
	result, err := hasher.HashFile(ctx, filePath)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to hash file", "path", filePath, "error", err)
		return make(map[string]string)
	}
	return result.Digests
}

func newClient(ctx context.Context, opts ...Option) (ClientIface, error) {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	if options.Executor == nil {
		options.Executor = executor.NewOSCommandExecutor()
	}
	if options.Logger == nil {
		options.Logger = logger.NewNoop()
	}

	cmd := options.Executor.CommandContext(ctx, "git", "--version")
	if err := cmd.Run(); err != nil {
		return nil, ErrGitNotFound
	}

	return &Client{
		executor: options.Executor,
		logger:   options.Logger,
		opts:     options,
	}, nil
}

// New is the constructor function for creating a Git client.
// This variable can be replaced in tests for mocking.
var New = newClient
