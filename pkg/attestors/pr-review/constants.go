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

package prreview

import (
	"errors"
	"regexp"
)

const (
	id          = "pr-review"
	name        = "Pull Request Review Attestor"
	description = "Generates a pr-review attestation for a merged GitHub pull request, bound to the landed commit"
)

// Configuration keys.
const (
	configRepository  = "repository"
	configPullRequest = "pull-request"
	configAPIURL      = "api-url"
	configTokenEnv    = "token-env"
)

const (
	// DefaultTokenEnv is the environment variable holding the GitHub App installation token.
	DefaultTokenEnv = "GITHUB_APP_INSTALLATION_TOKEN" //nolint:gosec // environment variable name, not a credential

	// maxConcurrentRequests bounds fan-out for per-ruleset and per-reviewer lookups.
	maxConcurrentRequests = 4
)

// Ruleset and reviewer values from the GitHub REST API.
const (
	rulesetTargetBranch      = "branch"
	rulesetEnforcementActive = "active"
	ruleTypePullRequest      = "pull_request"
	refPatternAll            = "~ALL"
	refPatternDefaultBranch  = "~DEFAULT_BRANCH"
	refsHeadsPrefix          = "refs/heads/"
	reviewerTypeTeam         = "Team"
	reviewerTypeUser         = "User"
	timelineMergeQueueEvent  = "added_to_merge_queue"
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+$`)
	envNamePattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

var (
	// ErrNotMerged is returned when the pull request has not been merged.
	ErrNotMerged = errors.New("pull request is not merged")

	// ErrMissingField is returned when a required field is absent from a GitHub response.
	ErrMissingField = errors.New("missing required field")

	// ErrInvalidField is returned when a GitHub response field has an unexpected type.
	ErrInvalidField = errors.New("invalid field")

	// ErrUnresolvedReviewer is returned when a ruleset reviewer cannot be resolved to a team or user.
	ErrUnresolvedReviewer = errors.New("required reviewer was not resolved")

	// ErrNotCollected is returned when GeneratePredicate runs before Attest.
	ErrNotCollected = errors.New("pull request evidence has not been collected")
)
