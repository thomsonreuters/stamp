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

// Package v1 defines the source-onboarding attestation predicate.
package v1

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
)

const (
	// PredicateURI is the externally defined source-onboarding predicate URI.
	PredicateURI = "https://attestations.thomsonreuters.com/source-onboarding/v1"

	Tier1Protected = "tier1-protected"
	Tier2          = "tier2"
	Untiered       = "untiered"

	ContinuityFromThisRevisionForward = "from-this-revision-forward"
)

var repositoryPattern = regexp.MustCompile(`^[^/]+/[^/]+$`)
var branchPattern = regexp.MustCompile(`^refs/heads/.+$`)

// Predicate records the branch protection baseline and its forward-only scope.
// JSON field names preserve the source-onboarding contract's externally defined
// camelCase spellings.
type Predicate struct {
	Repository              string        `json:"repository"                  jsonschema:"required,minLength=3,pattern=^[^/]+/[^/]+$"`
	Branch                  string        `json:"branch"                      jsonschema:"required,minLength=12,pattern=^refs/heads/.+$"`
	OnboardingTime          time.Time     `json:"onboardingTime"              jsonschema:"required"`
	RequiredApprovals       int           `json:"requiredApprovals"           jsonschema:"required,minimum=0"`
	RequiresCodeownerReview bool          `json:"requiresCodeownerReview"     jsonschema:"required"`
	LinearHistory           bool          `json:"linearHistory"               jsonschema:"required"`
	DismissStaleApprovals   bool          `json:"dismissStaleApprovals"       jsonschema:"required"`
	RestrictsForcePush      bool          `json:"restrictsForcePush"          jsonschema:"required"`
	BypassActors            []BypassActor `json:"bypassActors"                jsonschema:"required"`
	Tier                    string        `json:"tier"                        jsonschema:"required,enum=tier1-protected,enum=tier2,enum=untiered"`
	Continuity              string        `json:"continuity"                  jsonschema:"required"                                               jsonschema_extras:"const=from-this-revision-forward"`
	Reonboarding            *bool         `json:"reonboarding,omitempty"`
	IncidentReference       string        `json:"incidentReference,omitempty" jsonschema:"minLength=1"`
}

// BypassActor identifies an actor allowed to bypass branch controls. Actor IDs
// are platform IDs, and scopes and modes preserve the observed bypass grant.
type BypassActor struct {
	ActorType    string   `json:"actorType"    jsonschema:"required,minLength=1"`
	ActorID      string   `json:"actorID"      jsonschema:"required,minLength=1"`
	BypassModes  []string `json:"bypassModes"  jsonschema:"required,minItems=1,minLength=1"`
	BypassScopes []string `json:"bypassScopes" jsonschema:"required,minItems=1,minLength=1"`
}

// Validate checks required fields and invariants not expressible in JSON
// Schema, including UTC timestamps and re-genesis field relationships.
func (p Predicate) Validate() error {
	if !repositoryPattern.MatchString(p.Repository) || strings.TrimSpace(p.Repository) != p.Repository {
		return errors.New("repository must be in owner/name form")
	}
	if !branchPattern.MatchString(p.Branch) || strings.TrimSpace(p.Branch) != p.Branch {
		return errors.New("branch must be a full refs/heads/... ref")
	}
	if p.OnboardingTime.IsZero() {
		return errors.New("onboardingTime is required")
	}
	_, offset := p.OnboardingTime.Zone()
	if offset != 0 {
		return errors.New("onboardingTime must be UTC")
	}
	if p.RequiredApprovals < 0 {
		return errors.New("requiredApprovals must be non-negative")
	}
	if p.BypassActors == nil {
		return errors.New("bypassActors must be present; use an empty array when there are no bypass actors")
	}
	for i, actor := range p.BypassActors {
		if strings.TrimSpace(actor.ActorType) == "" {
			return fmt.Errorf("bypassActors[%d].actorType is required", i)
		}
		if strings.TrimSpace(actor.ActorID) == "" {
			return fmt.Errorf("bypassActors[%d].actorID is required", i)
		}
		if err := validateStringList(actor.BypassModes); err != nil {
			return fmt.Errorf("bypassActors[%d].bypassModes: %w", i, err)
		}
		if err := validateStringList(actor.BypassScopes); err != nil {
			return fmt.Errorf("bypassActors[%d].bypassScopes: %w", i, err)
		}
	}
	switch p.Tier {
	case Tier1Protected, Tier2, Untiered:
	default:
		return fmt.Errorf("tier must be one of %q, %q, or %q", Tier1Protected, Tier2, Untiered)
	}
	if p.Continuity != ContinuityFromThisRevisionForward {
		return fmt.Errorf("continuity must be %q", ContinuityFromThisRevisionForward)
	}
	if p.Reonboarding == nil {
		if p.IncidentReference != "" {
			return errors.New("incidentReference requires reonboarding to be true")
		}
		return nil
	}
	if !*p.Reonboarding {
		return errors.New("reonboarding must be omitted or true")
	}
	if strings.TrimSpace(p.IncidentReference) == "" {
		return errors.New("incidentReference is required for reonboarding")
	}
	return nil
}

// Schema returns the JSON Schema for the predicate.
func Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		DoNotReference:             true,
		ExpandedStruct:             true,
		RequiredFromJSONSchemaTags: true,
	}
	schema := reflector.Reflect(&Predicate{})
	schema.Title = "Source Onboarding v1"
	schema.Description = "Observed branch protection baseline and forward-only continuity marker"
	schema.DependentRequired = map[string][]string{
		"reonboarding":      {"incidentReference"},
		"incidentReference": {"reonboarding"},
	}
	onboardingTimeSchema, ok := schema.Properties.Get("onboardingTime")
	if !ok {
		panic("source-onboarding schema is missing onboardingTime")
	}
	onboardingTimeSchema.Pattern = "Z$"
	reonboardingSchema, ok := schema.Properties.Get("reonboarding")
	if !ok {
		panic("source-onboarding schema is missing reonboarding")
	}
	reonboardingSchema.Enum = []any{true}
	return schema
}

func validateStringList(values []string) error {
	if len(values) == 0 {
		return errors.New("at least one value is required")
	}
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("value at index %d must not be empty", i)
		}
	}
	return nil
}
