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

// Package v1 provides version 1 predicate definitions for GitHub pull-request review attestations.
// The predicate binds to the landed (post-merge) commit and records the review evidence and the
// branch rulesets that applied when the pull request merged.
package v1

const (
	// PredicateURI is the predicate type URI for pull-request review attestations.
	PredicateURI = "https://thomsonreuters.com/pr-review/v1"

	// ReviewPolicySourceGitHubRuleset identifies GitHub branch rulesets as the review policy source.
	ReviewPolicySourceGitHubRuleset = "github-ruleset"

	// CollectionModePostHocGitHubAPI records that evidence was read from the GitHub REST API after merge.
	CollectionModePostHocGitHubAPI = "post-hoc-github-api"

	// LandingMethodMerge is a merge commit with two or more parents.
	LandingMethodMerge = "merge"
	// LandingMethodFastForward is a landed commit identical to the pull request head.
	LandingMethodFastForward = "fast-forward"
	// LandingMethodSquash is a single-parent commit whose title references the pull request number.
	LandingMethodSquash = "squash"
)

// Predicate is the pr-review/v1 predicate.
type Predicate struct {
	Repository   Repository   `json:"repository"   jsonschema:"required"`
	PullRequest  PullRequest  `json:"pullRequest"  jsonschema:"required"`
	Landing      Landing      `json:"landing"      jsonschema:"required"`
	ReviewPolicy ReviewPolicy `json:"reviewPolicy" jsonschema:"required"`
	Reviews      []Review     `json:"reviews"      jsonschema:"required"`
	Collection   Collection   `json:"collection"   jsonschema:"required"`
}

// Repository identifies the GitHub repository.
type Repository struct {
	ID            int64  `json:"id"            jsonschema:"required"`
	NodeID        string `json:"nodeId"        jsonschema:"required"`
	FullName      string `json:"fullName"      jsonschema:"required"`
	DefaultBranch string `json:"defaultBranch" jsonschema:"required"`
}

// Actor identifies a GitHub user, bot, or organization.
type Actor struct {
	ID     int64  `json:"id"     jsonschema:"required"`
	NodeID string `json:"nodeId" jsonschema:"required"`
	Login  string `json:"login"  jsonschema:"required"`
	Type   string `json:"type"   jsonschema:"required"`
}

// Revision identifies a git commit.
type Revision struct {
	GitCommit string `json:"gitCommit" jsonschema:"required"`
}

// PullRequest describes the merged pull request.
type PullRequest struct {
	ID               int64    `json:"id"               jsonschema:"required"`
	NodeID           string   `json:"nodeId"           jsonschema:"required"`
	Number           int64    `json:"number"           jsonschema:"required"`
	URL              string   `json:"url"              jsonschema:"required"`
	Requestor        Actor    `json:"requestor"        jsonschema:"required"`
	BaseRef          string   `json:"baseRef"          jsonschema:"required"`
	ReviewedRevision Revision `json:"reviewedRevision" jsonschema:"required"`
}

// Landing describes the commit the pull request landed as.
type Landing struct {
	Revision        Revision        `json:"revision"         jsonschema:"required"`
	Parents         []string        `json:"parents"          jsonschema:"required"`
	MergedAt        string          `json:"mergedAt"         jsonschema:"required"`
	MergedBy        Actor           `json:"mergedBy"         jsonschema:"required"`
	MergeQueueUsed  bool            `json:"mergeQueueUsed"   jsonschema:"required"`
	CommitSignature CommitSignature `json:"commitSignature"  jsonschema:"required"`
	Method          string          `json:"method,omitempty" jsonschema:"enum=merge,enum=fast-forward,enum=squash"`
}

// CommitSignature is GitHub's verification result for the landed commit.
type CommitSignature struct {
	Verified   bool   `json:"verified"             jsonschema:"required"`
	Reason     string `json:"reason"               jsonschema:"required"`
	VerifiedAt string `json:"verifiedAt,omitempty"`
}

// ReviewPolicy describes the review requirements that applied to the base branch.
type ReviewPolicy struct {
	Source       string        `json:"source"       jsonschema:"required"`
	Requirements []Requirement `json:"requirements" jsonschema:"required"`
	Evaluation   Evaluation    `json:"evaluation"   jsonschema:"required"`
}

// Requirement is one pull_request rule from an applicable ruleset.
type Requirement struct {
	RulesetID                    int64      `json:"rulesetId"                    jsonschema:"required"`
	RulesetName                  string     `json:"rulesetName"                  jsonschema:"required"`
	RequiredApprovingReviewCount int64      `json:"requiredApprovingReviewCount" jsonschema:"required"`
	RequireCodeOwnerReview       bool       `json:"requireCodeOwnerReview"       jsonschema:"required"`
	RequireLastPushApproval      bool       `json:"requireLastPushApproval"      jsonschema:"required"`
	Reviewers                    []Reviewer `json:"reviewers"                    jsonschema:"required"`
}

// Reviewer is a required reviewer resolved by numeric ID. Exactly one of Team or User is set.
type Reviewer struct {
	// MinimumApprovals is emitted as null when the ruleset omits it.
	MinimumApprovals *int64 `json:"minimumApprovals" jsonschema:"oneof_type=integer;null"`
	Team             *Team  `json:"team,omitempty"`
	User             *Actor `json:"user,omitempty"`
}

// Team identifies a GitHub team.
type Team struct {
	ID   int64  `json:"id"   jsonschema:"required"`
	Slug string `json:"slug" jsonschema:"required"`
	Name string `json:"name" jsonschema:"required"`
}

// Evaluation carries GitHub's recorded rule-suite results for the landed commit.
type Evaluation struct {
	Available  bool             `json:"available"            jsonschema:"required"`
	HTTPStatus *int             `json:"httpStatus,omitempty"`
	Suites     []map[string]any `json:"suites"               jsonschema:"required"`
}

// Review is one submitted pull-request review.
type Review struct {
	ID               int64    `json:"id"                    jsonschema:"required"`
	NodeID           string   `json:"nodeId"                jsonschema:"required"`
	URL              string   `json:"url"                   jsonschema:"required"`
	Reviewer         Actor    `json:"reviewer"              jsonschema:"required"`
	State            string   `json:"state"                 jsonschema:"required"`
	SubmittedAt      string   `json:"submittedAt,omitempty"`
	ReviewedRevision Revision `json:"reviewedRevision"      jsonschema:"required"`
}

// Collection records how and when the evidence was collected.
type Collection struct {
	Mode        string `json:"mode"        jsonschema:"required"`
	CollectedAt string `json:"collectedAt" jsonschema:"required"`
}
