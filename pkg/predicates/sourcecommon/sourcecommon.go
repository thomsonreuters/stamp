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

// Package sourcecommon provides the primitives shared by the source-side
// predicates (pr-review, source-provenance, source-onboarding,
// emergency-change) and by the source-side use of the SLSA Verification
// Summary Attestation.
//
// Every source-side statement binds exactly one subject: the landed
// (post-merge) commit, identified by its gitCommit digest. The builders and
// parsers in this package enforce that rule so individual predicate packages
// cannot drift from it.
package sourcecommon

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

const (
	// GitCommitDigestAlgorithm is the in-toto digest algorithm name for a git commit ID.
	GitCommitDigestAlgorithm = "gitCommit"

	sha1HexLength   = 40
	sha256HexLength = 64
)

var (
	// ErrInvalidPredicate is wrapped by every predicate validation failure.
	ErrInvalidPredicate = errors.New("invalid predicate")

	// ErrInvalidStatement is wrapped by every statement-level validation failure.
	ErrInvalidStatement = errors.New("invalid statement")

	// ErrSubjectNotLandedCommit is returned when a statement's subject is not the landed commit
	// recorded in the predicate.
	ErrSubjectNotLandedCommit = errors.New("subject digest is not the landed commit")
)

// DigestSet maps a digest algorithm to its hex-encoded value.
type DigestSet map[string]string

// GitCommit returns the gitCommit digest, or an empty string if absent.
func (d DigestSet) GitCommit() string {
	return d[GitCommitDigestAlgorithm]
}

// ResourceDescriptor is the subset of the in-toto v1 ResourceDescriptor used by
// the source-side predicates.
// Spec: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
type ResourceDescriptor struct {
	URI    string    `json:"uri,omitempty"`
	Digest DigestSet `json:"digest,omitempty"`
	Name   string    `json:"name,omitempty"`
}

// ControlTier is the coarse protection tier derived from a branch's controls.
type ControlTier string

const (
	// ControlTierTier1Protected is the strongest tier (e.g. 2 reviewers, CODEOWNERS, linear history).
	ControlTierTier1Protected ControlTier = "tier1-protected"
	// ControlTierTier2 is a reduced-protection tier (e.g. 1 reviewer).
	ControlTierTier2 ControlTier = "tier2"
	// ControlTierUntiered marks an unprotected or degraded branch.
	ControlTierUntiered ControlTier = "untiered"
)

// ControlTiers lists every valid ControlTier.
func ControlTiers() []ControlTier {
	return []ControlTier{ControlTierTier1Protected, ControlTierTier2, ControlTierUntiered}
}

// IsValid reports whether t is a known control tier.
func (t ControlTier) IsValid() bool {
	switch t {
	case ControlTierTier1Protected, ControlTierTier2, ControlTierUntiered:
		return true
	default:
		return false
	}
}

// JSONSchema describes ControlTier as a string enum.
func (ControlTier) JSONSchema() *jsonschema.Schema {
	return EnumSchema(ControlTiers())
}

// BranchControls is a snapshot of the branch-protection settings that feed
// the control-tier derivation.
type BranchControls struct {
	RequiredApprovals       int  `json:"requiredApprovals"       jsonschema:"required,minimum=0"`
	RequiresCodeownerReview bool `json:"requiresCodeownerReview" jsonschema:"required"`
	LinearHistory           bool `json:"linearHistory"           jsonschema:"required"`
	DismissStaleApprovals   bool `json:"dismissStaleApprovals"   jsonschema:"required"`
	RestrictsForcePush      bool `json:"restrictsForcePush"      jsonschema:"required"`
	// BypassActors is the branch's bypass-actor allow-list. A broad set
	// undermines RestrictsForcePush, so it is recorded alongside it.
	BypassActors []string `json:"bypassActors,omitempty"`
}

// Validate checks the controls snapshot for structural correctness. field
// prefixes error messages.
func (c BranchControls) Validate(field string) error {
	if c.RequiredApprovals < 0 {
		return Invalidf("%s.requiredApprovals must be non-negative, got %d", field, c.RequiredApprovals)
	}
	return ValidateLogins(c.BypassActors, field+".bypassActors", 0)
}

// LandedCommit identifies the commit a source-side statement is bound to.
type LandedCommit struct {
	// Repository is the repository URL, e.g. https://github.com/acme/widget-svc.
	Repository string
	// Digest is the lowercase hex git commit ID (SHA-1 or SHA-256).
	Digest string
}

// Validate checks that the landed commit is well formed.
func (c LandedCommit) Validate() error {
	if err := ValidateURL(c.Repository, "landed commit repository"); err != nil {
		return err
	}
	return ValidateGitCommit(c.Digest, "landed commit digest")
}

// Subject returns the in-toto subject for the landed commit. The digest set
// carries only gitCommit so exact-digest matching is unambiguous.
func (c LandedCommit) Subject() intoto.Subject {
	return intoto.Subject{
		Name:   fmt.Sprintf("git+%s@%s", c.Repository, c.Digest),
		Digest: map[string]string{GitCommitDigestAlgorithm: c.Digest},
	}
}

// Validator is implemented by every source-side predicate.
type Validator interface {
	Validate() error
}

// LandedCommitBinder is implemented by predicates that record the landed
// commit in their body. Builders and parsers require it to equal the subject.
type LandedCommitBinder interface {
	LandedCommitDigest() string
}

// NewStatement builds an in-toto statement whose single subject is the landed
// commit. The predicate is checked against schema and validated, and if it
// records the landed commit itself (LandedCommitBinder) that value must equal
// commit.Digest.
func NewStatement(predicateType string, schema *PredicateSchema, commit LandedCommit, predicate Validator) (*intoto.Statement, error) {
	if schema == nil {
		return nil, ErrNilSchema
	}
	if err := commit.Validate(); err != nil {
		return nil, err
	}
	if predicate == nil {
		return nil, intoto.ErrNilPredicate
	}
	if err := schema.ValidateValue(predicate); err != nil {
		return nil, err
	}
	if err := predicate.Validate(); err != nil {
		return nil, err
	}
	if err := checkBinding(predicate, commit.Digest); err != nil {
		return nil, err
	}
	return intoto.NewStatement(predicateType, predicate, []intoto.Subject{commit.Subject()})
}

// DecodeStatement parses a statement of the given predicate type with any
// non-empty subject digests, checks the raw predicate against schema, then
// decodes it into dst and validates it. Schema enforcement runs before
// decoding so an absent required field is rejected instead of decoding to its
// Go zero value.
//
// Subject names are optional, per the in-toto v1 specification. A parsed
// statement without subject names therefore fails intoto.Statement.Validate,
// which stamp applies only to statements it signs. Parsed statements are for
// verification, not for re-signing.
func DecodeStatement(data []byte, predicateType string, schema *PredicateSchema, dst Validator) (*intoto.Statement, error) {
	if schema == nil {
		return nil, ErrNilSchema
	}
	var raw struct {
		Type          string           `json:"_type"`
		Subject       []intoto.Subject `json:"subject"`
		PredicateType string           `json:"predicateType"`
		Predicate     json.RawMessage  `json:"predicate"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if raw.Type != intoto.StatementType {
		return nil, fmt.Errorf("%w: _type must be %s, got %q", ErrInvalidStatement, intoto.StatementType, raw.Type)
	}
	if raw.PredicateType != predicateType {
		return nil, fmt.Errorf("%w: predicateType must be %s, got %q", ErrInvalidStatement, predicateType, raw.PredicateType)
	}
	if len(raw.Subject) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, intoto.ErrNoSubjects)
	}
	for i, s := range raw.Subject {
		if len(s.Digest) == 0 {
			return nil, fmt.Errorf("%w: subject %d: %w", ErrInvalidStatement, i, intoto.ErrNoSubjectDigests)
		}
	}
	if len(raw.Predicate) == 0 || string(raw.Predicate) == "null" {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, intoto.ErrNilPredicate)
	}
	if err := schema.ValidateJSON(raw.Predicate); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw.Predicate, dst); err != nil {
		return nil, fmt.Errorf("%w: predicate: %w", ErrInvalidStatement, err)
	}
	if err := dst.Validate(); err != nil {
		return nil, err
	}
	return &intoto.Statement{
		Type:          raw.Type,
		Subject:       raw.Subject,
		PredicateType: raw.PredicateType,
		Predicate:     dst,
	}, nil
}

// DecodeSourceStatement is DecodeStatement plus the source-side subject rule:
// exactly one subject whose digest set is a single valid gitCommit, matching
// the predicate's landed commit when it records one.
func DecodeSourceStatement(data []byte, predicateType string, schema *PredicateSchema, dst Validator) (*intoto.Statement, error) {
	stmt, err := DecodeStatement(data, predicateType, schema, dst)
	if err != nil {
		return nil, err
	}
	if len(stmt.Subject) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one subject, got %d", ErrInvalidStatement, len(stmt.Subject))
	}
	digest := DigestSet(stmt.Subject[0].Digest)
	if err := ValidateGitCommitDigestSet(digest, "subject digest"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if err := checkBinding(dst, digest.GitCommit()); err != nil {
		return nil, err
	}
	return stmt, nil
}

func checkBinding(predicate Validator, commit string) error {
	binder, ok := predicate.(LandedCommitBinder)
	if !ok {
		return nil
	}
	if bound := binder.LandedCommitDigest(); bound != commit {
		return fmt.Errorf("%w: subject %q, predicate %q", ErrSubjectNotLandedCommit, commit, bound)
	}
	return nil
}

// Invalidf returns a formatted error wrapping ErrInvalidPredicate.
func Invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPredicate, fmt.Sprintf(format, args...))
}

// ValidateGitCommit checks that v is a lowercase hex SHA-1 or SHA-256 commit ID.
func ValidateGitCommit(v, field string) error {
	if len(v) != sha1HexLength && len(v) != sha256HexLength {
		return Invalidf("%s must be a %d or %d character hex git commit, got %q", field, sha1HexLength, sha256HexLength, v)
	}
	if strings.ToLower(v) != v {
		return Invalidf("%s must be lowercase hex, got %q", field, v)
	}
	if _, err := hex.DecodeString(v); err != nil {
		return Invalidf("%s must be hex, got %q", field, v)
	}
	return nil
}

// ValidateGitCommitDigestSet checks that d carries exactly one valid gitCommit digest.
func ValidateGitCommitDigestSet(d DigestSet, field string) error {
	if len(d) != 1 {
		return Invalidf("%s must contain exactly one %s digest, got %d entries", field, GitCommitDigestAlgorithm, len(d))
	}
	v, ok := d[GitCommitDigestAlgorithm]
	if !ok {
		return Invalidf("%s must contain a %s digest", field, GitCommitDigestAlgorithm)
	}
	return ValidateGitCommit(v, field+"."+GitCommitDigestAlgorithm)
}

// ValidateRevisionEdge checks that uri and digest form a uri + gitCommit digest edge.
func ValidateRevisionEdge(uri string, digest DigestSet, field string) error {
	if err := ValidateURI(uri, field+".uri"); err != nil {
		return err
	}
	return ValidateGitCommitDigestSet(digest, field+".digest")
}

// ValidateRequired checks that v is not blank.
func ValidateRequired(v, field string) error {
	if strings.TrimSpace(v) == "" {
		return Invalidf("%s is required", field)
	}
	return nil
}

// ValidateRef checks that ref is a fully qualified git ref (refs/...).
func ValidateRef(ref, field string) error {
	if err := ValidateRequired(ref, field); err != nil {
		return err
	}
	if !strings.HasPrefix(ref, "refs/") || ref == "refs/" {
		return Invalidf("%s must be a fully qualified ref (refs/...), got %q", field, ref)
	}
	return nil
}

// ValidateURI checks that v is an absolute URI with a scheme.
func ValidateURI(v, field string) error {
	if err := ValidateRequired(v, field); err != nil {
		return err
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" {
		return Invalidf("%s must be an absolute URI, got %q", field, v)
	}
	return nil
}

// ValidateURL checks that v is an absolute http(s) URL with a host.
func ValidateURL(v, field string) error {
	if err := ValidateRequired(v, field); err != nil {
		return err
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Invalidf("%s must be an absolute http(s) URL, got %q", field, v)
	}
	return nil
}

// ValidateLogins checks that logins has at least minCount entries, none blank
// and none duplicated.
func ValidateLogins(logins []string, field string, minCount int) error {
	if len(logins) < minCount {
		return Invalidf("%s must contain at least %d entries, got %d", field, minCount, len(logins))
	}
	seen := make(map[string]struct{}, len(logins))
	for i, l := range logins {
		if strings.TrimSpace(l) == "" {
			return Invalidf("%s[%d] must not be blank", field, i)
		}
		if _, dup := seen[l]; dup {
			return Invalidf("%s contains duplicate entry %q", field, l)
		}
		seen[l] = struct{}{}
	}
	return nil
}

// EnumSchema returns a string JSON schema restricted to values.
func EnumSchema[T ~string](values []T) *jsonschema.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = string(v)
	}
	return &jsonschema.Schema{Type: "string", Enum: enum}
}

// ReflectSchema reflects a JSON schema for v using the project's predicate
// conventions (required fields come from jsonschema tags).
func ReflectSchema(v any, title, description string, allowAdditional bool) *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  allowAdditional,
		RequiredFromJSONSchemaTags: true,
	}
	schema := reflector.Reflect(v)
	schema.Title = title
	schema.Description = description
	return schema
}
