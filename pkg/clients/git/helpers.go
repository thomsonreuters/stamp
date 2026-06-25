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
	"strconv"
	"strings"
	"time"

	"github.com/thomsonreuters/stamp/pkg/utils"
)

// Separator used in git log format output.
const commitFieldSeparator = "---FIELD---"

// parseCommitLog parses the output of git log with a specific format.
// Expected format: hash---FIELD---tree---FIELD---parents---FIELD---authorName---FIELD---...
func parseCommitLog(output string) (*GitInfo, error) {
	if output == "" {
		return nil, ErrEmptyRepository
	}

	parts := strings.Split(output, commitFieldSeparator)
	if len(parts) < 10 {
		return nil, ErrInvalidCommitFormat
	}

	info := &GitInfo{
		CommitHash:     strings.TrimSpace(parts[0]),
		TreeHash:       strings.TrimSpace(parts[1]),
		AuthorName:     strings.TrimSpace(parts[3]),
		AuthorEmail:    strings.TrimSpace(parts[4]),
		CommitterName:  strings.TrimSpace(parts[6]),
		CommitterEmail: strings.TrimSpace(parts[7]),
		Message:        strings.TrimSpace(parts[9]),
	}

	// Parse parent hashes
	if parents := strings.TrimSpace(parts[2]); parents != "" {
		info.ParentHashes = strings.Split(parents, " ")
	}

	// Parse timestamps
	if ts := strings.TrimSpace(parts[5]); ts != "" {
		if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
			info.AuthorTimestamp = time.Unix(unix, 0).UTC()
		}
	}
	if ts := strings.TrimSpace(parts[8]); ts != "" {
		if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
			info.CommitterTimestamp = time.Unix(unix, 0).UTC()
		}
	}

	return info, nil
}

// parseRepositoryStatus parses git status --porcelain output.
func parseRepositoryStatus(output string) (bool, map[string]FileStatus) {
	fileStatus := make(map[string]FileStatus)

	if output == "" {
		return false, fileStatus
	}

	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		if len(line) < 3 {
			continue
		}

		staging := string(line[0])
		worktree := string(line[1])
		path := strings.TrimSpace(line[3:])

		// Handle renamed files: "R  old -> new"
		if strings.Contains(path, " -> ") {
			parts := strings.Split(path, " -> ")
			if len(parts) == 2 {
				path = parts[1]
			}
		}

		fileStatus[path] = FileStatus{
			Staging:  staging,
			Worktree: worktree,
		}
	}

	isDirty := len(fileStatus) > 0
	return isDirty, fileStatus
}

// parseBranch parses the output of git branch --show-current.
// Returns the branch name and whether HEAD is detached.
// In detached HEAD state, branch is empty — the commit hash is already
// captured in commit metadata, and the detached state is tracked separately.
func parseBranch(currentBranch string) (string, bool) {
	branch := strings.TrimSpace(currentBranch)
	isDetached := branch == ""

	return branch, isDetached
}

// parseRemoteInfo parses git remote -v output.
func parseRemoteInfo(output string) []RemoteInfo {
	if output == "" {
		return nil
	}

	remoteMap := make(map[string]*RemoteInfo)
	lines := strings.SplitSeq(output, "\n")

	for line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		url := parts[1]
		urlType := ""
		if len(parts) >= 3 {
			urlType = parts[2]
		}

		remote, exists := remoteMap[name]
		if !exists {
			remote = &RemoteInfo{Name: name}
			remoteMap[name] = remote
		}

		switch urlType {
		case "(fetch)":
			remote.FetchURL = url
		case "(push)":
			remote.PushURL = url
		default:
			// If no type specified, use as both
			if remote.FetchURL == "" {
				remote.FetchURL = url
			}
			if remote.PushURL == "" {
				remote.PushURL = url
			}
		}
	}

	remotes := make([]RemoteInfo, 0, len(remoteMap))
	for _, remote := range remoteMap {
		remotes = append(remotes, *remote)
	}

	return remotes
}

// parseOriginURL extracts the origin URL from git remote output.
func parseOriginURL(output string) string {
	return strings.TrimSpace(output)
}

// parseTagInfo parses git tag information.
// Input format: name|taggerName|taggerEmail|timestamp|signature|message.
func parseTagInfo(output string) []TagInfo {
	if output == "" {
		return nil
	}

	var tags []TagInfo
	entries := strings.SplitSeq(output, "\n")

	for entry := range entries {
		if entry == "" {
			continue
		}

		parts := strings.Split(entry, "|")
		if len(parts) < 1 {
			continue
		}

		tag := TagInfo{
			Name: strings.TrimSpace(parts[0]),
		}

		if len(parts) > 1 {
			tag.TaggerName = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			tag.TaggerEmail = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			if ts := strings.TrimSpace(parts[3]); ts != "" {
				if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
					tag.When = time.Unix(unix, 0).UTC()
				}
			}
		}
		if len(parts) > 4 {
			tag.PGPSignature = strings.TrimSpace(parts[4])
		}
		if len(parts) > 5 {
			tag.Message = strings.TrimSpace(parts[5])
		}

		tags = append(tags, tag)
	}

	return tags
}

// parseSubmoduleStatus parses git submodule status output.
func parseSubmoduleStatus(output string) []SubmoduleInfo {
	if output == "" {
		return nil
	}

	var submodules []SubmoduleInfo
	lines := strings.SplitSeq(output, "\n")

	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: [+-U ]<sha1> <path> (optional description)
		// First character indicates status:
		// ' ' = submodule is up to date
		// '-' = submodule is not initialized
		// '+' = submodule has different checked out commit
		// 'U' = submodule has merge conflicts
		status := " "
		if len(line) > 0 {
			firstChar := line[0]
			if firstChar == '-' || firstChar == '+' || firstChar == 'U' {
				status = string(firstChar)
				line = line[1:]
			}
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		submodule := SubmoduleInfo{
			Commit: parts[0],
			Path:   parts[1],
			Status: status,
		}

		submodules = append(submodules, submodule)
	}

	return submodules
}

// parseGitVersion extracts version from "git version X.Y.Z" output.
func parseGitVersion(output string) string {
	output = strings.TrimSpace(output)
	if after, ok := strings.CutPrefix(output, "git version "); ok {
		return after
	}
	return output
}

// isShallowClone checks if the repository is a shallow clone.
func isShallowClone(output string) bool {
	return strings.TrimSpace(output) == "true"
}

// GetSourceURI constructs a source URI in format "git+<url>@<ref>".
func GetSourceURI(info *GitInfo) string {
	if info == nil || info.RemoteOriginURL == "" {
		return ""
	}

	// Normalize the git URL to HTTPS format
	sourceURI := "git+" + ToHTMLURL(info.RemoteOriginURL)

	switch {
	case len(info.Refs) > 0:
		sourceURI += "@" + info.Refs[0]
	case info.Branch != "":
		sourceURI += "@refs/heads/" + info.Branch
	case info.CommitHash != "":
		sourceURI += "@" + info.CommitHash
	}

	return sourceURI
}

// ToHTMLURL converts a Git remote URL to a web-browsable HTTPS URL.
// Handles SSH URLs (git@host:path), SSH protocol URLs (ssh://git@host/path),
// and normalizes HTTPS/HTTP URLs by removing .git suffixes.
func ToHTMLURL(remoteURL string) string {
	// Handle SSH URLs (git@github.com:user/repo.git -> https://github.com/user/repo)
	if strings.HasPrefix(remoteURL, "git@") {
		parts := strings.SplitN(remoteURL, ":", 2)
		if len(parts) == 2 {
			host := strings.TrimPrefix(parts[0], "git@")
			path := strings.TrimSuffix(parts[1], ".git")
			return "https://" + host + "/" + path
		}
	}

	// Handle SSH URLs (ssh://git@github.com/user/repo.git -> https://github.com/user/repo)
	if after, ok := strings.CutPrefix(remoteURL, "ssh://git@"); ok {
		remoteURL = after
		remoteURL = strings.TrimSuffix(remoteURL, ".git")
		return "https://" + remoteURL
	}

	// Handle HTTPS/HTTP URLs (strip credentials and .git suffix)
	if strings.HasPrefix(remoteURL, "https://") || strings.HasPrefix(remoteURL, "http://") {
		return strings.TrimSuffix(utils.SanitizeURL(remoteURL), ".git")
	}

	// Return as-is for other formats (including file://)
	return remoteURL
}
