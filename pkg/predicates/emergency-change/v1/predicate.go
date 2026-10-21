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

// Package v1 provides the emergency-change/v1 predicate: the break-glass
// authorization for a commit that bypassed the standard review chain.
//
// The subject is the emergency commit itself. The authorization is
// time-bound (expiresAt) and carries a post-hoc review obligation. JSON field
// names are camelCase as defined by the GitHub Source Attestations
// specification.
package v1

import (
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
)

// PredicateURI is the predicate type URI for emergency-change v1.
const PredicateURI = "https://attestations.thomsonreuters.com/emergency-change/v1"

// ChangeType classifies how the emergency change bypassed review.
type ChangeType string

const (
	// ChangeTypeForcePush is a history-rewriting push to a protected branch.
	ChangeTypeForcePush ChangeType = "force-push"
	// ChangeTypeDirectPush is a non-PR push by a bypass actor.
	ChangeTypeDirectPush ChangeType = "direct-push"
	// ChangeTypeExpeditedHotfix is a PR merged below the standard review bar.
	ChangeTypeExpeditedHotfix ChangeType = "expedited-hotfix"
)

// ChangeTypes lists every valid ChangeType.
func ChangeTypes() []ChangeType {
	return []ChangeType{ChangeTypeForcePush, ChangeTypeDirectPush, ChangeTypeExpeditedHotfix}
}

// IsValid reports whether c is a known change type.
func (c ChangeType) IsValid() bool {
	switch c {
	case ChangeTypeForcePush, ChangeTypeDirectPush, ChangeTypeExpeditedHotfix:
		return true
	default:
		return false
	}
}

// JSONSchema describes ChangeType as a string enum.
func (ChangeType) JSONSchema() *jsonschema.Schema {
	return sourcecommon.EnumSchema(ChangeTypes())
}

// Predicate is the emergency-change/v1 predicate.
type Predicate struct {
	// Incident references the incident record, e.g. a ServiceNow URL.
	Incident      string `json:"incident"      jsonschema:"required"`
	Justification string `json:"justification" jsonschema:"required"`
	// AuthorizedBy are the logins that authorized the break-glass change.
	AuthorizedBy []string   `json:"authorizedBy" jsonschema:"required,minItems=1"`
	ChangeType   ChangeType `json:"changeType"   jsonschema:"required"`
	// Branch is the fully qualified ref the change landed on, e.g. refs/heads/prod.
	Branch string `json:"branch" jsonschema:"required"`
	// ExpiresAt bounds the window in which this authorization is valid.
	ExpiresAt time.Time `json:"expiresAt" jsonschema:"required"`
	// PostHocReviewDue is the deadline for the retroactive review.
	PostHocReviewDue time.Time `json:"postHocReviewDue" jsonschema:"required"`
}

// Validate checks the predicate for structural correctness.
func (p Predicate) Validate() error {
	if err := sourcecommon.ValidateRequired(p.Incident, "incident"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateRequired(p.Justification, "justification"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateLogins(p.AuthorizedBy, "authorizedBy", 1); err != nil {
		return err
	}
	if !p.ChangeType.IsValid() {
		return sourcecommon.Invalidf("changeType must be one of %v, got %q", ChangeTypes(), p.ChangeType)
	}
	if err := sourcecommon.ValidateRef(p.Branch, "branch"); err != nil {
		return err
	}
	if p.ExpiresAt.IsZero() {
		return sourcecommon.Invalidf("expiresAt is required")
	}
	if p.PostHocReviewDue.IsZero() {
		return sourcecommon.Invalidf("postHocReviewDue is required")
	}
	return nil
}

// NewStatement builds an emergency-change statement bound to the emergency commit.
func NewStatement(commit sourcecommon.LandedCommit, p *Predicate) (*intoto.Statement, error) {
	if p == nil {
		return nil, intoto.ErrNilPredicate
	}
	return sourcecommon.NewStatement(PredicateURI, predicateSchema, commit, p)
}

// ParseStatement decodes and validates an emergency-change statement whose
// single subject is a gitCommit digest.
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
		"Emergency Change",
		"Time-bound break-glass authorization for a commit that bypassed standard review",
		false,
	)
}

// predicateSchema enforces Schema on the wire form when building and parsing.
var predicateSchema = sourcecommon.NewPredicateSchema(Schema)
