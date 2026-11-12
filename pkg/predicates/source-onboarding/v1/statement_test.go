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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

func TestDeriveTier_AllControlCombinations(t *testing.T) {
	bypassCases := []struct {
		name   string
		actors []BypassActor
		broad  bool
	}{
		{name: "no bypass actors", actors: []BypassActor{}},
		{
			name: "explicit individual user",
			actors: []BypassActor{{
				ActorType:    BypassActorUser,
				ActorID:      "1234",
				BypassModes:  []string{"always"},
				BypassScopes: []string{"force_push"},
			}},
		},
		{
			name: "team bypass",
			actors: []BypassActor{{
				ActorType:    "team",
				ActorID:      "42",
				BypassModes:  []string{"always"},
				BypassScopes: []string{"force_push"},
			}},
			broad: true,
		},
		{
			name: "unknown actor kind",
			actors: []BypassActor{{
				ActorType:    "future-platform-actor",
				ActorID:      "42",
				BypassModes:  []string{"always"},
				BypassScopes: []string{"force_push"},
			}},
			broad: true,
		},
	}

	for _, approvals := range []int{0, 1, 2, 3} {
		for flags := range 16 {
			for _, bypass := range bypassCases {
				t.Run(fmt.Sprintf("approvals-%d/flags-%04b/%s", approvals, flags, bypass.name), func(t *testing.T) {
					controls := ObservedControls{
						RequiredApprovals:       approvals,
						RequiresCodeownerReview: flags&1 != 0,
						LinearHistory:           flags&2 != 0,
						DismissStaleApprovals:   flags&4 != 0,
						RestrictsForcePush:      flags&8 != 0,
						BypassActors:            bypass.actors,
						EvidenceComplete:        true,
					}

					want := Tier2
					if approvals == 0 {
						want = Untiered
					} else if approvals >= 2 && flags == 15 && !bypass.broad {
						want = Tier1Protected
					}

					got, err := DeriveTier(controls)
					require.NoError(t, err)
					assert.Equal(t, want, got)
				})
			}
		}
	}
}

func TestDeriveTier_RejectsIncompleteEvidence(t *testing.T) {
	_, err := DeriveTier(ObservedControls{
		RequiredApprovals:       3,
		RequiresCodeownerReview: true,
		LinearHistory:           true,
		DismissStaleApprovals:   true,
		RestrictsForcePush:      true,
		BypassActors:            []BypassActor{},
	})
	require.ErrorIs(t, err, ErrIncompleteControls)

	_, err = DeriveTier(ObservedControls{
		RequiredApprovals:       3,
		RequiresCodeownerReview: true,
		LinearHistory:           true,
		DismissStaleApprovals:   true,
		RestrictsForcePush:      true,
		EvidenceComplete:        true,
	})
	require.ErrorIs(t, err, ErrIncompleteControls)
}

func TestDeriveTier_RejectsInvalidObservation(t *testing.T) {
	tests := []struct {
		name      string
		approvals int
		actors    []BypassActor
	}{
		{name: "negative approvals", approvals: -1, actors: []BypassActor{}},
		{
			name:      "missing actor type",
			approvals: 2,
			actors:    []BypassActor{{ActorID: "123", BypassModes: []string{"always"}, BypassScopes: []string{"force_push"}}},
		},
		{name: "missing bypass mode", approvals: 2, actors: []BypassActor{{ActorType: "team", ActorID: "42", BypassScopes: []string{"force_push"}}}},
		{name: "missing bypass scope", approvals: 2, actors: []BypassActor{{ActorType: "team", ActorID: "42", BypassModes: []string{"always"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveTier(ObservedControls{
				RequiredApprovals: tt.approvals,
				BypassActors:      tt.actors,
				EvidenceComplete:  true,
			})
			require.Error(t, err)
		})
	}
}

func TestBuildStatement_UsesCurrentBranchTip(t *testing.T) {
	predicate := tier1Predicate()
	tip := strings.Repeat("a", 39) + "b"

	statement, err := BuildStatement(predicate, tip)
	require.NoError(t, err)
	require.NoError(t, statement.Validate())
	assert.Equal(t, intoto.StatementType, statement.Type)
	assert.Equal(t, PredicateURI, statement.PredicateType)
	require.Len(t, statement.Subject, 1)
	assert.Equal(t, "owner/repository@refs/heads/release", statement.Subject[0].Name)
	assert.Equal(t, map[string]string{"gitCommit": tip}, statement.Subject[0].Digest)
	assert.Equal(t, predicate, statement.Predicate)

	encoded, err := statement.ToJSON()
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(encoded, &document))
	predicateFields, ok := document["predicate"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, ContinuityFromThisRevisionForward, predicateFields["continuity"])
	for _, forbidden := range []string{
		"reviewedParentRevisions",
		"preOnboardingReview",
		"historyReviewed",
		"continuousHistoricalCoverage",
	} {
		assert.NotContains(t, predicateFields, forbidden)
	}

	secondTip := strings.Repeat("c", 39) + "d"
	second, err := BuildStatement(predicate, secondTip)
	require.NoError(t, err)
	assert.Equal(t, secondTip, second.Subject[0].Digest["gitCommit"])
}

func TestBuildStatement_UsesObservedControlsAndTier(t *testing.T) {
	predicate := validPredicate()
	predicate.RequiredApprovals = 2
	predicate.RequiresCodeownerReview = true
	predicate.LinearHistory = true
	predicate.DismissStaleApprovals = true
	predicate.RestrictsForcePush = true
	predicate.Tier = Tier1Protected

	statement, err := BuildStatement(predicate, strings.Repeat("1", 40))
	require.NoError(t, err)
	got, ok := statement.Predicate.(Predicate)
	require.True(t, ok)
	assert.Equal(t, predicate.RequiredApprovals, got.RequiredApprovals)
	assert.Equal(t, predicate.RequiresCodeownerReview, got.RequiresCodeownerReview)
	assert.Equal(t, predicate.LinearHistory, got.LinearHistory)
	assert.Equal(t, predicate.DismissStaleApprovals, got.DismissStaleApprovals)
	assert.Equal(t, predicate.RestrictsForcePush, got.RestrictsForcePush)
	assert.Equal(t, Tier1Protected, got.Tier)
}

func TestBuildStatement_RejectsTierMismatchAndInvalidTip(t *testing.T) {
	tests := []struct {
		name string
		pred Predicate
		tip  string
		err  error
	}{
		{
			name: "tier mismatch",
			pred: mismatchedTierPredicate(),
			tip:  strings.Repeat("a", 40),
			err:  ErrTierMismatch,
		},
		{
			name: "short digest",
			pred: tier1Predicate(),
			tip:  "abcd",
			err:  ErrInvalidCommit,
		},
		{
			name: "non-hex digest",
			pred: tier1Predicate(),
			tip:  strings.Repeat("z", 40),
			err:  ErrInvalidCommit,
		},
		{
			name: "unsupported digest length",
			pred: tier1Predicate(),
			tip:  strings.Repeat("a", 41),
			err:  ErrInvalidCommit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildStatement(tt.pred, tt.tip)
			require.Error(t, err)
			require.ErrorIs(t, err, tt.err)
		})
	}
}

func TestBuildStatement_RejectsTier1WithBroadBypass(t *testing.T) {
	predicate := tier1Predicate()
	predicate.BypassActors = []BypassActor{{
		ActorType:    "team",
		ActorID:      "42",
		BypassModes:  []string{"always"},
		BypassScopes: []string{"force_push"},
	}}

	_, err := BuildStatement(predicate, strings.Repeat("a", 40))
	require.ErrorIs(t, err, ErrTierMismatch)
}

func tier1Predicate() Predicate {
	return Predicate{
		Repository:              "owner/repository",
		Branch:                  "refs/heads/release",
		OnboardingTime:          time.Date(2026, 11, 11, 20, 0, 0, 0, time.UTC),
		RequiredApprovals:       2,
		RequiresCodeownerReview: true,
		LinearHistory:           true,
		DismissStaleApprovals:   true,
		RestrictsForcePush:      true,
		BypassActors:            []BypassActor{},
		Tier:                    Tier1Protected,
		Continuity:              ContinuityFromThisRevisionForward,
	}
}

func mismatchedTierPredicate() Predicate {
	predicate := validPredicate()
	predicate.Tier = Tier1Protected
	return predicate
}
