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

package v1

import (
	"encoding/json"
	"testing"
	"time"

	jsonschemavalidator "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://attestations.thomsonreuters.com/source-onboarding/v1", PredicateURI)
}

func TestPredicate_RoundTrip(t *testing.T) {
	reonboarding := true
	tests := []struct {
		name string
		in   Predicate
	}{
		{
			name: "minimal",
			in: Predicate{
				Repository:        "owner/repository",
				Branch:            "refs/heads/main",
				OnboardingTime:    time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC),
				BypassActors:      []BypassActor{},
				Tier:              Tier2,
				Continuity:        ContinuityFromThisRevisionForward,
				RequiredApprovals: 0,
			},
		},
		{
			name: "complete with re-onboarding fields",
			in: Predicate{
				Repository:              "owner/repository",
				Branch:                  "refs/heads/release",
				OnboardingTime:          time.Date(2026, 11, 11, 20, 1, 2, 0, time.UTC),
				RequiredApprovals:       3,
				RequiresCodeownerReview: true,
				LinearHistory:           true,
				DismissStaleApprovals:   true,
				RestrictsForcePush:      true,
				BypassActors: []BypassActor{{
					ActorType:    "team",
					ActorID:      "42",
					BypassModes:  []string{"always"},
					BypassScopes: []string{"force_push"},
				}},
				Tier:              Tier1Protected,
				Continuity:        ContinuityFromThisRevisionForward,
				Reonboarding:      &reonboarding,
				IncidentReference: "INC-12345",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.in)
			require.NoError(t, err)

			var got Predicate
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Equal(t, tt.in, got)
			require.NoError(t, got.Validate())
		})
	}
}

func TestPredicate_OptionalReonboardingFields(t *testing.T) {
	predicate := validPredicate()
	data, err := json.Marshal(predicate)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "reonboarding")
	assert.NotContains(t, string(data), "incidentReference")

	reonboarding := true
	predicate.Reonboarding = &reonboarding
	predicate.IncidentReference = "INC-1"
	data, err = json.Marshal(predicate)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"reonboarding":true`)
	assert.Contains(t, string(data), `"incidentReference":"INC-1"`)
	require.NoError(t, predicate.Validate())
}

func TestPredicate_ValidateRejectsInvalidValues(t *testing.T) {
	falseValue := false
	tests := []struct {
		name   string
		mutate func(*Predicate)
	}{
		{name: "repository format", mutate: func(p *Predicate) { p.Repository = "not-a-repository" }},
		{name: "branch must be a full ref", mutate: func(p *Predicate) { p.Branch = "main" }},
		{name: "branch ref must name a branch", mutate: func(p *Predicate) { p.Branch = "refs/heads/" }},
		{name: "missing timestamp", mutate: func(p *Predicate) { p.OnboardingTime = time.Time{} }},
		{name: "non-UTC timestamp", mutate: func(p *Predicate) {
			p.OnboardingTime = time.Date(2026, 11, 11, 20, 0, 0, 0, time.FixedZone("offset", 3600))
		}},
		{name: "negative approvals", mutate: func(p *Predicate) { p.RequiredApprovals = -1 }},
		{name: "missing bypass list", mutate: func(p *Predicate) { p.BypassActors = nil }},
		{name: "incomplete bypass actor", mutate: func(p *Predicate) {
			p.BypassActors = []BypassActor{{ActorType: "team"}}
		}},
		{name: "unknown tier", mutate: func(p *Predicate) { p.Tier = "tier0" }},
		{name: "incorrect continuity", mutate: func(p *Predicate) { p.Continuity = "full-history" }},
		{name: "false reonboarding marker", mutate: func(p *Predicate) { p.Reonboarding = &falseValue }},
		{name: "incident without reonboarding marker", mutate: func(p *Predicate) { p.IncidentReference = "INC-1" }},
		{name: "reonboarding without incident", mutate: func(p *Predicate) {
			value := true
			p.Reonboarding = &value
		}},
		{name: "empty incident", mutate: func(p *Predicate) {
			value := true
			p.Reonboarding = &value
			p.IncidentReference = " "
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := validPredicate()
			tt.mutate(&predicate)
			assert.Error(t, predicate.Validate())
		})
	}
}

func TestSchema_Contract(t *testing.T) {
	data, err := json.Marshal(Schema())
	require.NoError(t, err)

	type schemaNode struct {
		Type       string                `json:"type"`
		Format     string                `json:"format"`
		Pattern    string                `json:"pattern"`
		Enum       []any                 `json:"enum"`
		Const      string                `json:"const"`
		Min        *int                  `json:"minimum"`
		MinLength  *int                  `json:"minLength"`
		Items      *schemaNode           `json:"items"`
		Properties map[string]schemaNode `json:"properties"`
		Required   []string              `json:"required"`
	}
	var schema struct {
		Properties        map[string]schemaNode `json:"properties"`
		Required          []string              `json:"required"`
		DependentRequired map[string][]string   `json:"dependentRequired"`
	}
	require.NoError(t, json.Unmarshal(data, &schema))

	for _, field := range []string{
		"repository", "branch", "onboardingTime", "requiredApprovals",
		"requiresCodeownerReview", "linearHistory", "dismissStaleApprovals",
		"restrictsForcePush", "bypassActors", "tier", "continuity",
	} {
		assert.Contains(t, schema.Required, field)
	}
	assert.NotContains(t, schema.Required, "reonboarding")
	assert.NotContains(t, schema.Required, "incidentReference")
	assert.Equal(t, "string", schema.Properties["repository"].Type)
	assert.Equal(t, "string", schema.Properties["branch"].Type)
	assert.Equal(t, "date-time", schema.Properties["onboardingTime"].Format)
	assert.Equal(t, "Z$", schema.Properties["onboardingTime"].Pattern)
	assert.Equal(t, "integer", schema.Properties["requiredApprovals"].Type)
	for _, field := range []string{
		"requiresCodeownerReview", "linearHistory", "dismissStaleApprovals", "restrictsForcePush",
	} {
		assert.Equal(t, "boolean", schema.Properties[field].Type)
	}
	assert.Equal(t, "array", schema.Properties["bypassActors"].Type)
	assert.Equal(t, "string", schema.Properties["tier"].Type)
	assert.Equal(t, "string", schema.Properties["continuity"].Type)
	require.NotNil(t, schema.Properties["requiredApprovals"].Min)
	assert.Zero(t, *schema.Properties["requiredApprovals"].Min)
	assert.Equal(t, []any{Tier1Protected, Tier2, Untiered}, schema.Properties["tier"].Enum)
	assert.Equal(t, ContinuityFromThisRevisionForward, schema.Properties["continuity"].Const)
	require.NotNil(t, schema.Properties["bypassActors"].Items)
	assert.Contains(t, schema.Properties["bypassActors"].Items.Required, "actorType")
	require.NotNil(t, schema.Properties["bypassActors"].Items.Properties["bypassModes"].Items)
	require.NotNil(t, schema.Properties["bypassActors"].Items.Properties["bypassModes"].Items.MinLength)
	assert.Equal(t, 1, *schema.Properties["bypassActors"].Items.Properties["bypassModes"].Items.MinLength)
	assert.Equal(t, []any{true}, schema.Properties["reonboarding"].Enum)
	assert.Equal(t, []string{"incidentReference"}, schema.DependentRequired["reonboarding"])
	assert.Equal(t, []string{"reonboarding"}, schema.DependentRequired["incidentReference"])
}

func TestSchema_ValidatesPredicates(t *testing.T) {
	schemaData, err := json.Marshal(Schema())
	require.NoError(t, err)
	var schemaDocument any
	require.NoError(t, json.Unmarshal(schemaData, &schemaDocument))

	const schemaURI = "https://attestations.thomsonreuters.com/source-onboarding/v1/schema.json"
	compiler := jsonschemavalidator.NewCompiler()
	compiler.AssertFormat()
	require.NoError(t, compiler.AddResource(schemaURI, schemaDocument))
	schema, err := compiler.Compile(schemaURI)
	require.NoError(t, err)

	validData, err := json.Marshal(validPredicate())
	require.NoError(t, err)
	var validInstance any
	require.NoError(t, json.Unmarshal(validData, &validInstance))
	require.NoError(t, schema.Validate(validInstance))

	reonboarding := true
	completeData, err := json.Marshal(Predicate{
		Repository:        "owner/repository",
		Branch:            "refs/heads/main",
		OnboardingTime:    time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC),
		RequiredApprovals: 2,
		BypassActors:      []BypassActor{},
		Tier:              Tier2,
		Continuity:        ContinuityFromThisRevisionForward,
		Reonboarding:      &reonboarding,
		IncidentReference: "INC-1",
	})
	require.NoError(t, err)
	var completeInstance any
	require.NoError(t, json.Unmarshal(completeData, &completeInstance))
	require.NoError(t, schema.Validate(completeInstance))

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "negative approvals", mutate: func(value map[string]any) { value["requiredApprovals"] = -1 }},
		{name: "unsupported tier", mutate: func(value map[string]any) { value["tier"] = "tier0" }},
		{name: "incorrect continuity", mutate: func(value map[string]any) { value["continuity"] = "full-history" }},
		{name: "missing required field", mutate: func(value map[string]any) { delete(value, "repository") }},
		{name: "wrong control type", mutate: func(value map[string]any) { value["linearHistory"] = "true" }},
		{name: "malformed timestamp", mutate: func(value map[string]any) { value["onboardingTime"] = "not-a-timestamp" }},
		{name: "non-UTC timestamp", mutate: func(value map[string]any) {
			value["onboardingTime"] = "2026-11-11T20:00:00+01:00"
		}},
		{name: "unknown field", mutate: func(value map[string]any) { value["unexpected"] = true }},
		{name: "reonboarding without incident", mutate: func(value map[string]any) { value["reonboarding"] = true }},
		{name: "incident without reonboarding", mutate: func(value map[string]any) { value["incidentReference"] = "INC-1" }},
		{name: "false reonboarding", mutate: func(value map[string]any) {
			value["reonboarding"] = false
			value["incidentReference"] = "INC-1"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, marshalErr := json.Marshal(validPredicate())
			require.NoError(t, marshalErr)
			var instance map[string]any
			require.NoError(t, json.Unmarshal(data, &instance))
			tt.mutate(instance)
			assert.Error(t, schema.Validate(instance))
		})
	}
}

func validPredicate() Predicate {
	return Predicate{
		Repository:        "owner/repository",
		Branch:            "refs/heads/main",
		OnboardingTime:    time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC),
		BypassActors:      []BypassActor{},
		Tier:              Tier2,
		Continuity:        ContinuityFromThisRevisionForward,
		RequiredApprovals: 2,
	}
}
