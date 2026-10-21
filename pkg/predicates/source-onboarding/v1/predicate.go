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

// Package v1 provides the source-onboarding/v1 predicate: the genesis
// attestation for a protected branch, bound to the branch tip at onboarding
// (or re-genesis) time.
//
// It anchors the branch's control tier and claimed review-count bar, from
// which continuity runs forward. JSON field names are camelCase as defined by
// the GitHub Source Attestations specification.
package v1

import (
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
)

// PredicateURI is the predicate type URI for source-onboarding v1.
const PredicateURI = "https://attestations.thomsonreuters.com/source-onboarding/v1"

// Continuity describes the scope of the continuity claim made at genesis.
type Continuity string

// ContinuityFromThisRevisionForward asserts nothing about prior history.
const ContinuityFromThisRevisionForward Continuity = "from-this-revision-forward"

// IsValid reports whether c is a known continuity value.
func (c Continuity) IsValid() bool {
	return c == ContinuityFromThisRevisionForward
}

// JSONSchema describes Continuity as a string enum.
func (Continuity) JSONSchema() *jsonschema.Schema {
	return sourcecommon.EnumSchema([]Continuity{ContinuityFromThisRevisionForward})
}

// Predicate is the source-onboarding/v1 predicate.
type Predicate struct {
	// Repository is the repository URL, e.g. https://github.com/acme/widget-svc.
	Repository string `json:"repository" jsonschema:"required,format=uri"`
	// Branch is the fully qualified protected branch ref, e.g. refs/heads/prod.
	Branch      string    `json:"branch"      jsonschema:"required"`
	OnboardedAt time.Time `json:"onboardedAt" jsonschema:"required"`
	// Controls are the branch-protection settings the tier was derived from.
	Controls    sourcecommon.BranchControls `json:"controls"    jsonschema:"required"`
	ControlTier sourcecommon.ControlTier    `json:"controlTier" jsonschema:"required"`
	// RequiredApprovals is the branch's claimed review-count bar, carried
	// forward by source-provenance as claimedRequiredApprovals.
	RequiredApprovals int        `json:"requiredApprovals" jsonschema:"required,minimum=0"`
	Continuity        Continuity `json:"continuity"        jsonschema:"required"`
	// Reonboarding is true when this record is a re-genesis.
	Reonboarding bool `json:"reonboarding" jsonschema:"required"`
	// Incident references the incident that caused a re-genesis. Required
	// when Reonboarding is true and forbidden otherwise.
	Incident string `json:"incident,omitempty"`
}

// Validate checks the predicate for structural correctness.
func (p Predicate) Validate() error {
	if err := sourcecommon.ValidateURL(p.Repository, "repository"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateRef(p.Branch, "branch"); err != nil {
		return err
	}
	if p.OnboardedAt.IsZero() {
		return sourcecommon.Invalidf("onboardedAt is required")
	}
	if err := p.Controls.Validate("controls"); err != nil {
		return err
	}
	if !p.ControlTier.IsValid() {
		return sourcecommon.Invalidf("controlTier must be one of %v, got %q", sourcecommon.ControlTiers(), p.ControlTier)
	}
	if p.RequiredApprovals < 0 {
		return sourcecommon.Invalidf("requiredApprovals must be non-negative, got %d", p.RequiredApprovals)
	}
	// The bar and the tier input come from the same protection read at genesis.
	if p.RequiredApprovals != p.Controls.RequiredApprovals {
		return sourcecommon.Invalidf(
			"requiredApprovals (%d) must equal controls.requiredApprovals (%d)",
			p.RequiredApprovals, p.Controls.RequiredApprovals,
		)
	}
	if !p.Continuity.IsValid() {
		return sourcecommon.Invalidf("continuity must be %q, got %q", ContinuityFromThisRevisionForward, p.Continuity)
	}
	if p.Reonboarding {
		return sourcecommon.ValidateRequired(p.Incident, "incident (required when reonboarding)")
	}
	if p.Incident != "" {
		return sourcecommon.Invalidf("incident must only be set when reonboarding")
	}
	return nil
}

// NewStatement builds a source-onboarding statement bound to the branch tip.
// commit.Repository must equal p.Repository.
func NewStatement(commit sourcecommon.LandedCommit, p *Predicate) (*intoto.Statement, error) {
	if p == nil {
		return nil, intoto.ErrNilPredicate
	}
	if commit.Repository != p.Repository {
		return nil, sourcecommon.Invalidf("subject repository %q does not match predicate repository %q", commit.Repository, p.Repository)
	}
	return sourcecommon.NewStatement(PredicateURI, predicateSchema, commit, p)
}

// ParseStatement decodes and validates a source-onboarding statement whose
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
		"Source Onboarding",
		"Genesis baseline for a protected branch: control tier, review-count bar and forward-only continuity",
		false,
	)
}

// predicateSchema enforces Schema on the wire form when building and parsing.
var predicateSchema = sourcecommon.NewPredicateSchema(Schema)
