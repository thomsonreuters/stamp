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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://thomsonreuters.com/pr-review/v1", PredicateURI)
}

func definition(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := json.Marshal(Schema())
	require.NoError(t, err)
	var schema struct {
		Defs map[string]map[string]any `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(data, &schema))
	def, ok := schema.Defs[name]
	require.True(t, ok, "missing definition %s", name)
	return def
}

func requiredOf(def map[string]any) []string {
	var out []string
	required, _ := def["required"].([]any)
	for _, v := range required {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func TestSchemaRequiredFields(t *testing.T) {
	schema := Schema()
	assert.Equal(t, "Pull Request Review Attestation", schema.Title)

	tests := map[string][]string{
		"Predicate":       {"repository", "pullRequest", "landing", "reviewPolicy", "reviews", "collection"},
		"Landing":         {"revision", "parents", "mergedAt", "mergedBy", "mergeQueueUsed", "commitSignature"},
		"CommitSignature": {"verified", "reason"},
		"Review":          {"id", "nodeId", "url", "reviewer", "state", "reviewedRevision"},
		"Requirement": {
			"rulesetId", "rulesetName", "requiredApprovingReviewCount",
			"requireCodeOwnerReview", "requireLastPushApproval", "reviewers",
		},
		"Evaluation": {"available", "suites"},
	}
	for name, want := range tests {
		assert.ElementsMatch(t, want, requiredOf(definition(t, name)), name)
	}

	reviewer := definition(t, "Reviewer")
	assert.NotContains(t, reviewer, "required")
	assert.Equal(t, false, reviewer["additionalProperties"])
}

func TestOptionalFieldSerialization(t *testing.T) {
	data, err := json.Marshal(Predicate{
		Landing:      Landing{Parents: []string{}},
		ReviewPolicy: ReviewPolicy{Requirements: []Requirement{{Reviewers: []Reviewer{{Team: &Team{ID: 1}}}}}},
		Reviews:      []Review{{}},
	})
	require.NoError(t, err)
	s := string(data)
	assert.NotContains(t, s, `"method"`)
	assert.NotContains(t, s, `"verifiedAt"`)
	assert.NotContains(t, s, `"submittedAt"`)
	assert.NotContains(t, s, `"httpStatus"`)
	assert.NotContains(t, s, `"user"`)
	assert.Contains(t, s, `"minimumApprovals":null`)
}
