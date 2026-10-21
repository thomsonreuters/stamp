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

// Package v1 provides the pr-review/v1 predicate: the human four-eye review
// fact for a merged pull request.
//
// The subject is always the landed (post-merge) commit, never the PR head.
// JSON field names are camelCase as defined by the GitHub Source Attestations
// specification.
package v1

import (
	"encoding/json"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
)

// PredicateURI is the predicate type URI for pr-review v1.
const PredicateURI = "https://attestations.thomsonreuters.com/pr-review/v1"

// Predicate is the pr-review/v1 predicate.
type Predicate struct {
	PullRequest string `json:"pullRequest" jsonschema:"required,format=uri"`
	// Author is the PR author's login, so policies can enforce approvers != author.
	Author string `json:"author" jsonschema:"required"`
	// Approvers are the logins that approved the PR.
	Approvers []string `json:"approvers" jsonschema:"required"`
	// ApprovalCount is the number of approvals; it equals len(Approvers).
	ApprovalCount int `json:"approvalCount" jsonschema:"required,minimum=0"`
	// RequiredApprovals is the live branch-protection setting at merge.
	RequiredApprovals int `json:"requiredApprovals" jsonschema:"required,minimum=0"`
	// RequiredApprovers is the set of reviewers (users or teams) whose
	// approval was required, e.g. resolved CODEOWNERS.
	RequiredApprovers   []string  `json:"requiredApprovers,omitempty"`
	CodeownersSatisfied bool      `json:"codeownersSatisfied"         jsonschema:"required"`
	CreatedAt           time.Time `json:"createdAt"                   jsonschema:"required"`
	MergedAt            time.Time `json:"mergedAt"                    jsonschema:"required"`
}

// Validate checks the predicate for structural correctness.
func (p Predicate) Validate() error {
	if err := sourcecommon.ValidateURL(p.PullRequest, "pullRequest"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateRequired(p.Author, "author"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateLogins(p.Approvers, "approvers", 0); err != nil {
		return err
	}
	if p.ApprovalCount != len(p.Approvers) {
		return sourcecommon.Invalidf("approvalCount (%d) must equal the number of approvers (%d)", p.ApprovalCount, len(p.Approvers))
	}
	if p.RequiredApprovals < 0 {
		return sourcecommon.Invalidf("requiredApprovals must be non-negative, got %d", p.RequiredApprovals)
	}
	if err := sourcecommon.ValidateLogins(p.RequiredApprovers, "requiredApprovers", 0); err != nil {
		return err
	}
	if p.CreatedAt.IsZero() {
		return sourcecommon.Invalidf("createdAt is required")
	}
	if p.MergedAt.IsZero() {
		return sourcecommon.Invalidf("mergedAt is required")
	}
	if p.MergedAt.Before(p.CreatedAt) {
		return sourcecommon.Invalidf("mergedAt must not be before createdAt")
	}
	return nil
}

// MarshalJSON emits approvers as an array even when nil.
func (p Predicate) MarshalJSON() ([]byte, error) {
	type alias Predicate
	a := alias(p)
	if a.Approvers == nil {
		a.Approvers = []string{}
	}
	return json.Marshal(a)
}

// NewStatement builds a pr-review statement bound to the landed commit.
func NewStatement(commit sourcecommon.LandedCommit, p *Predicate) (*intoto.Statement, error) {
	if p == nil {
		return nil, intoto.ErrNilPredicate
	}
	return sourcecommon.NewStatement(PredicateURI, predicateSchema, commit, p)
}

// ParseStatement decodes and validates a pr-review statement whose single
// subject is a gitCommit digest.
func ParseStatement(data []byte) (*intoto.Statement, *Predicate, error) {
	p := &Predicate{}
	stmt, err := sourcecommon.DecodeSourceStatement(data, PredicateURI, predicateSchema, p)
	if err != nil {
		return nil, nil, err
	}
	return stmt, p, nil
}

// Schema returns the JSON schema for the predicate.
func Schema() *jsonschema.Schema {
	return sourcecommon.ReflectSchema(
		&Predicate{},
		"Pull Request Review",
		"Four-eye review evidence for a merged pull request, bound to the landed commit",
		false,
	)
}

// predicateSchema enforces Schema on the wire form when building and parsing.
var predicateSchema = sourcecommon.NewPredicateSchema(Schema)
