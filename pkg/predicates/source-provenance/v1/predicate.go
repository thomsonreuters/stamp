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

// Package v1 provides the source-provenance/v1 predicate: the source-side
// bridge that records, for a landed commit, the reviewed parent revisions it
// was merged from as explicit uri+digest edges.
//
// The subject is always the landed (post-merge) commit and must equal
// mergedRevision.digest.gitCommit. JSON field names are camelCase as defined
// by the GitHub Source Attestations specification; the resolver bridges on
// predicate.reviewedParentRevisions.
//
// Edge roles: each edge is either the reviewed source tip ("reviewed-head",
// the default for an edge without annotations) or the prior tip of the
// landed-on branch ("continuity-parent", which must be declared through the
// in-toto ResourceDescriptor annotation {"role": "continuity-parent"} and
// whose uri must end in "@" + mergedRevision.ref). A valid predicate has
// exactly one reviewed head and at most one continuity parent, so the
// specification's single-edge promotion example needs no annotation and a
// two-edge continuity landing whose roles cannot be determined is rejected.
// Whether a continuity parent is *required* is a profile decision: the
// continuity gate must fail closed when ContinuityParent reports none.
package v1

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
)

const (
	// PredicateURI is the predicate type URI for source-provenance v1.
	PredicateURI = "https://attestations.thomsonreuters.com/source-provenance/v1"

	// BridgeDependenciesPath is the resolver bridge path to the reviewed parent edges.
	BridgeDependenciesPath = "predicate.reviewedParentRevisions"
)

// MergeStrategy is the forge merge method that produced the landed commit.
type MergeStrategy string

const (
	// MergeStrategyMerge is a merge commit.
	MergeStrategyMerge MergeStrategy = "merge"
	// MergeStrategySquash is a squash merge.
	MergeStrategySquash MergeStrategy = "squash"
	// MergeStrategyRebase is a rebase merge.
	MergeStrategyRebase MergeStrategy = "rebase"
)

// MergeStrategies lists every valid MergeStrategy.
func MergeStrategies() []MergeStrategy {
	return []MergeStrategy{MergeStrategyMerge, MergeStrategySquash, MergeStrategyRebase}
}

// IsValid reports whether s is a known merge strategy.
func (s MergeStrategy) IsValid() bool {
	switch s {
	case MergeStrategyMerge, MergeStrategySquash, MergeStrategyRebase:
		return true
	default:
		return false
	}
}

// JSONSchema describes MergeStrategy as a string enum.
func (MergeStrategy) JSONSchema() *jsonschema.Schema {
	return sourcecommon.EnumSchema(MergeStrategies())
}

// MergedRevision identifies the landed commit and the ref it landed on.
type MergedRevision struct {
	Ref    string                 `json:"ref"    jsonschema:"required"`
	Digest sourcecommon.DigestSet `json:"digest" jsonschema:"required"`
}

// ParentRole states what a reviewedParentRevisions edge means to the gates.
type ParentRole string

const (
	// ParentRoleReviewedHead is the reviewed source tip (the PR's head.sha).
	// It is the default role of an edge that carries no annotations.
	ParentRoleReviewedHead ParentRole = "reviewed-head"
	// ParentRoleContinuityParent is the prior tip of the branch the commit
	// landed on. The continuity gate requires this edge's VSA.
	ParentRoleContinuityParent ParentRole = "continuity-parent"
)

// ParentRoles lists every valid ParentRole.
func ParentRoles() []ParentRole {
	return []ParentRole{ParentRoleReviewedHead, ParentRoleContinuityParent}
}

// IsValid reports whether r is a known parent role.
func (r ParentRole) IsValid() bool {
	switch r {
	case ParentRoleReviewedHead, ParentRoleContinuityParent:
		return true
	default:
		return false
	}
}

// JSONSchema describes ParentRole as a string enum.
func (ParentRole) JSONSchema() *jsonschema.Schema {
	return sourcecommon.EnumSchema(ParentRoles())
}

// ParentAnnotations are the in-toto ResourceDescriptor annotations allowed on
// a parent edge.
type ParentAnnotations struct {
	Role ParentRole `json:"role" jsonschema:"required"`
}

// ParentRevision is a uri + gitCommit digest edge, shaped as an in-toto
// ResourceDescriptor. The edge's role is explicit when annotated, and is
// ParentRoleReviewedHead otherwise.
type ParentRevision struct {
	URI         string                 `json:"uri"                   jsonschema:"required"`
	Digest      sourcecommon.DigestSet `json:"digest"                jsonschema:"required"`
	Annotations *ParentAnnotations     `json:"annotations,omitempty"`
}

// Role returns the edge's role, defaulting to ParentRoleReviewedHead.
func (r ParentRevision) Role() ParentRole {
	if r.Annotations == nil {
		return ParentRoleReviewedHead
	}
	return r.Annotations.Role
}

// Predicate is the source-provenance/v1 predicate.
type Predicate struct {
	MergedRevision MergedRevision `json:"mergedRevision" jsonschema:"required"`
	MergeStrategy  MergeStrategy  `json:"mergeStrategy"  jsonschema:"required"`
	// ReviewedParentRevisions are explicit uri+digest edges: exactly one
	// reviewed source tip (PR head.sha) and, for integration-branch landings,
	// at most one continuity parent (prior tip of mergedRevision.ref).
	ReviewedParentRevisions []ParentRevision `json:"reviewedParentRevisions" jsonschema:"required,minItems=1,maxItems=2"`
	PullRequest             string           `json:"pullRequest"             jsonschema:"required,format=uri"`
	MergedBy                string           `json:"mergedBy"                jsonschema:"required"`
	MergedAt                time.Time        `json:"mergedAt"                jsonschema:"required"`
	// ActualApprovals is the number of approvals this PR received.
	ActualApprovals int `json:"actualApprovals" jsonschema:"required,minimum=0"`
	// ClaimedRequiredApprovals is the genesis-anchored review-count bar,
	// copied forward link to link and reset only at re-genesis.
	ClaimedRequiredApprovals int `json:"claimedRequiredApprovals" jsonschema:"required,minimum=0"`
	// ObservedRequiredApprovals is the live branch setting at merge, carried
	// for audit and drift detection only.
	ObservedRequiredApprovals int `json:"observedRequiredApprovals" jsonschema:"required,minimum=0"`
	// ClaimedTier is the genesis-anchored control tier, copied forward link to link.
	ClaimedTier sourcecommon.ControlTier `json:"claimedTier,omitempty"`
	// ObservedControls is the live branch-protection snapshot at merge,
	// captured from the same merge-pinned read as ObservedRequiredApprovals.
	ObservedControls *sourcecommon.BranchControls `json:"observedControls,omitempty"`
}

// Validate checks the predicate for structural correctness.
func (p Predicate) Validate() error {
	if err := sourcecommon.ValidateRef(p.MergedRevision.Ref, "mergedRevision.ref"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateGitCommitDigestSet(p.MergedRevision.Digest, "mergedRevision.digest"); err != nil {
		return err
	}
	if !p.MergeStrategy.IsValid() {
		return sourcecommon.Invalidf("mergeStrategy must be one of %v, got %q", MergeStrategies(), p.MergeStrategy)
	}
	if err := p.validateParents(); err != nil {
		return err
	}
	if err := sourcecommon.ValidateURL(p.PullRequest, "pullRequest"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateRequired(p.MergedBy, "mergedBy"); err != nil {
		return err
	}
	if p.MergedAt.IsZero() {
		return sourcecommon.Invalidf("mergedAt is required")
	}
	if err := p.validateApprovals(); err != nil {
		return err
	}
	return p.validateControls()
}

func (p Predicate) validateParents() error {
	if len(p.ReviewedParentRevisions) == 0 {
		return sourcecommon.Invalidf("reviewedParentRevisions must contain at least one edge")
	}
	landed := p.MergedRevision.Digest.GitCommit()
	seen := make(map[string]struct{}, len(p.ReviewedParentRevisions))
	roles := make(map[ParentRole]int, len(ParentRoles()))
	for i, edge := range p.ReviewedParentRevisions {
		field := "reviewedParentRevisions[" + strconv.Itoa(i) + "]"
		if err := sourcecommon.ValidateRevisionEdge(edge.URI, edge.Digest, field); err != nil {
			return err
		}
		role := edge.Role()
		if !role.IsValid() {
			return sourcecommon.Invalidf("%s.annotations.role must be one of %v, got %q", field, ParentRoles(), role)
		}
		roles[role]++
		if role == ParentRoleContinuityParent && !strings.HasSuffix(edge.URI, "@"+p.MergedRevision.Ref) {
			return sourcecommon.Invalidf("%s is a continuity parent, so its uri must reference mergedRevision.ref %q, got %q",
				field, p.MergedRevision.Ref, edge.URI)
		}
		parent := edge.Digest.GitCommit()
		if parent == landed {
			return sourcecommon.Invalidf("%s must not reference the landed commit itself", field)
		}
		if _, dup := seen[parent]; dup {
			return sourcecommon.Invalidf("%s duplicates parent %s", field, parent)
		}
		seen[parent] = struct{}{}
	}
	if n := roles[ParentRoleReviewedHead]; n != 1 {
		return sourcecommon.Invalidf("reviewedParentRevisions must contain exactly one %s edge, got %d; "+
			"annotate the continuity parent with role %q", ParentRoleReviewedHead, n, ParentRoleContinuityParent)
	}
	if n := roles[ParentRoleContinuityParent]; n > 1 {
		return sourcecommon.Invalidf("reviewedParentRevisions must contain at most one %s edge, got %d", ParentRoleContinuityParent, n)
	}
	return nil
}

// ReviewedHead returns the reviewed source tip edge. It is only meaningful on
// a predicate that passed Validate.
func (p Predicate) ReviewedHead() (ParentRevision, bool) {
	return p.parentWithRole(ParentRoleReviewedHead)
}

// ContinuityParent returns the prior branch tip edge, if the landing carries one.
func (p Predicate) ContinuityParent() (ParentRevision, bool) {
	return p.parentWithRole(ParentRoleContinuityParent)
}

func (p Predicate) parentWithRole(role ParentRole) (ParentRevision, bool) {
	for _, edge := range p.ReviewedParentRevisions {
		if edge.Role() == role {
			return edge, true
		}
	}
	return ParentRevision{}, false
}

func (p Predicate) validateApprovals() error {
	if p.ActualApprovals < 0 {
		return sourcecommon.Invalidf("actualApprovals must be non-negative, got %d", p.ActualApprovals)
	}
	if p.ClaimedRequiredApprovals < 0 {
		return sourcecommon.Invalidf("claimedRequiredApprovals must be non-negative, got %d", p.ClaimedRequiredApprovals)
	}
	if p.ObservedRequiredApprovals < 0 {
		return sourcecommon.Invalidf("observedRequiredApprovals must be non-negative, got %d", p.ObservedRequiredApprovals)
	}
	return nil
}

func (p Predicate) validateControls() error {
	if p.ClaimedTier != "" && !p.ClaimedTier.IsValid() {
		return sourcecommon.Invalidf("claimedTier must be one of %v, got %q", sourcecommon.ControlTiers(), p.ClaimedTier)
	}
	if p.ObservedControls == nil {
		return nil
	}
	if err := p.ObservedControls.Validate("observedControls"); err != nil {
		return err
	}
	// Both values must come from one merge-pinned snapshot; a mismatch indicates a split read.
	if p.ObservedControls.RequiredApprovals != p.ObservedRequiredApprovals {
		return sourcecommon.Invalidf(
			"observedControls.requiredApprovals (%d) must equal observedRequiredApprovals (%d)",
			p.ObservedControls.RequiredApprovals, p.ObservedRequiredApprovals,
		)
	}
	return nil
}

// LandedCommitDigest returns mergedRevision.digest.gitCommit.
func (p Predicate) LandedCommitDigest() string {
	return p.MergedRevision.Digest.GitCommit()
}

// MarshalJSON emits reviewedParentRevisions as an array even when nil.
func (p Predicate) MarshalJSON() ([]byte, error) {
	type alias Predicate
	a := alias(p)
	if a.ReviewedParentRevisions == nil {
		a.ReviewedParentRevisions = []ParentRevision{}
	}
	return json.Marshal(a)
}

// NewStatement builds a source-provenance statement bound to the landed commit.
// It fails with sourcecommon.ErrSubjectNotLandedCommit unless commit.Digest
// equals p.MergedRevision.Digest.gitCommit.
func NewStatement(commit sourcecommon.LandedCommit, p *Predicate) (*intoto.Statement, error) {
	if p == nil {
		return nil, intoto.ErrNilPredicate
	}
	return sourcecommon.NewStatement(PredicateURI, predicateSchema, commit, p)
}

// ParseStatement decodes and validates a source-provenance statement,
// including the subject-is-landed-commit binding.
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
		"Source Provenance",
		"Source-side bridge from a landed commit to its reviewed and continuity parent revisions",
		false,
	)
}

// predicateSchema enforces Schema on the wire form when building and parsing.
var predicateSchema = sourcecommon.NewPredicateSchema(Schema)
