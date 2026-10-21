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

// Package v1 provides the SLSA Verification Summary Attestation (VSA) v1
// predicate.
//
// Source gates consume the VSA of a predecessor commit and discriminate on
// policy.uri (which source profile blessed it) and verificationResult. JSON
// field names follow the SLSA specification (camelCase), and unknown fields
// are tolerated so later SLSA minor revisions remain readable.
// Spec: https://slsa.dev/spec/v1.0/verification_summary
package v1

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
)

// PredicateURI is the SLSA VSA v1 predicate type URI.
const PredicateURI = "https://slsa.dev/verification_summary/v1"

// VerificationResult is the outcome recorded by the verifier.
type VerificationResult string

const (
	// VerificationResultPassed means the resource satisfied the policy.
	VerificationResultPassed VerificationResult = "PASSED"
	// VerificationResultFailed means the resource did not satisfy the policy.
	VerificationResultFailed VerificationResult = "FAILED"
)

// VerificationResults lists every valid VerificationResult.
func VerificationResults() []VerificationResult {
	return []VerificationResult{VerificationResultPassed, VerificationResultFailed}
}

// IsValid reports whether r is a known verification result.
func (r VerificationResult) IsValid() bool {
	switch r {
	case VerificationResultPassed, VerificationResultFailed:
		return true
	default:
		return false
	}
}

// JSONSchema describes VerificationResult as a string enum.
func (VerificationResult) JSONSchema() *jsonschema.Schema {
	return sourcecommon.EnumSchema(VerificationResults())
}

// Verifier identifies the entity that performed the verification.
type Verifier struct {
	ID      string            `json:"id"                jsonschema:"required,format=uri"`
	Version map[string]string `json:"version,omitempty"`
}

// Predicate is the SLSA VSA v1 predicate.
type Predicate struct {
	Verifier     Verifier  `json:"verifier"     jsonschema:"required"`
	TimeVerified time.Time `json:"timeVerified" jsonschema:"required"`
	ResourceURI  string    `json:"resourceUri"  jsonschema:"required"`
	// Policy identifies the policy (for source gates, the source profile)
	// the resource was verified against. Consumers discriminate on Policy.URI.
	Policy             sourcecommon.ResourceDescriptor   `json:"policy"                      jsonschema:"required"`
	InputAttestations  []sourcecommon.ResourceDescriptor `json:"inputAttestations,omitempty"`
	VerificationResult VerificationResult                `json:"verificationResult"          jsonschema:"required"`
	VerifiedLevels     []string                          `json:"verifiedLevels"              jsonschema:"required"`
	DependencyLevels   map[string]int                    `json:"dependencyLevels,omitempty"`
	SlsaVersion        string                            `json:"slsaVersion,omitempty"`
}

// Validate checks the predicate for structural correctness.
func (p Predicate) Validate() error {
	if err := sourcecommon.ValidateURI(p.Verifier.ID, "verifier.id"); err != nil {
		return err
	}
	if p.TimeVerified.IsZero() {
		return sourcecommon.Invalidf("timeVerified is required")
	}
	if err := sourcecommon.ValidateRequired(p.ResourceURI, "resourceUri"); err != nil {
		return err
	}
	if err := sourcecommon.ValidateRequired(p.Policy.URI, "policy.uri"); err != nil {
		return err
	}
	for i, in := range p.InputAttestations {
		field := "inputAttestations[" + strconv.Itoa(i) + "]"
		if err := sourcecommon.ValidateRequired(in.URI, field+".uri"); err != nil {
			return err
		}
		if len(in.Digest) == 0 {
			return sourcecommon.Invalidf("%s.digest is required", field)
		}
	}
	if !p.VerificationResult.IsValid() {
		return sourcecommon.Invalidf("verificationResult must be one of %v, got %q", VerificationResults(), p.VerificationResult)
	}
	for i, level := range p.VerifiedLevels {
		if err := sourcecommon.ValidateRequired(level, "verifiedLevels["+strconv.Itoa(i)+"]"); err != nil {
			return err
		}
	}
	for level, count := range p.DependencyLevels {
		if count < 0 {
			return sourcecommon.Invalidf("dependencyLevels[%q] must be non-negative, got %d", level, count)
		}
	}
	return nil
}

// Passed reports whether the verification result is PASSED.
func (p Predicate) Passed() bool {
	return p.VerificationResult == VerificationResultPassed
}

// MarshalJSON emits verifiedLevels as an array even when nil.
func (p Predicate) MarshalJSON() ([]byte, error) {
	type alias Predicate
	a := alias(p)
	if a.VerifiedLevels == nil {
		a.VerifiedLevels = []string{}
	}
	return json.Marshal(a)
}

// NewSourceStatement builds a VSA statement bound to a source-side commit.
func NewSourceStatement(commit sourcecommon.LandedCommit, p *Predicate) (*intoto.Statement, error) {
	if p == nil {
		return nil, intoto.ErrNilPredicate
	}
	return sourcecommon.NewStatement(PredicateURI, predicateSchema, commit, p)
}

// ParseStatement decodes and validates a VSA statement with any subject
// digests (e.g. an image digest at the deploy gate).
func ParseStatement(data []byte) (*intoto.Statement, *Predicate, error) {
	p := &Predicate{}
	stmt, err := sourcecommon.DecodeStatement(data, PredicateURI, predicateSchema, p)
	if err != nil {
		return nil, nil, err
	}
	return stmt, p, nil
}

// ParseSourceStatement decodes and validates a VSA statement whose single
// subject is a gitCommit digest, as produced by the source gates.
func ParseSourceStatement(data []byte) (*intoto.Statement, *Predicate, error) {
	p := &Predicate{}
	stmt, err := sourcecommon.DecodeSourceStatement(data, PredicateURI, predicateSchema, p)
	if err != nil {
		return nil, nil, err
	}
	return stmt, p, nil
}

// Schema returns the JSON schema for the predicate. Additional properties are
// allowed because the predicate is defined upstream by SLSA.
func Schema() *jsonschema.Schema {
	return sourcecommon.ReflectSchema(
		&Predicate{},
		"SLSA Verification Summary",
		"SLSA Verification Summary Attestation v1",
		true,
	)
}

// predicateSchema enforces Schema on the wire form when building and parsing.
var predicateSchema = sourcecommon.NewPredicateSchema(Schema)
