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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon/sourcetest"
)

const repo = "https://github.com/acme/widget-svc"

var tipG = strings.Repeat("0a", 32) // SHA-256 object format

func tip() sourcecommon.LandedCommit {
	return sourcecommon.LandedCommit{Repository: repo, Digest: tipG}
}

func genesis() Predicate {
	return Predicate{
		Repository:  repo,
		Branch:      "refs/heads/prod",
		OnboardedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Controls: sourcecommon.BranchControls{
			RequiredApprovals:       3,
			RequiresCodeownerReview: true,
			LinearHistory:           true,
			DismissStaleApprovals:   true,
			RestrictsForcePush:      true,
		},
		ControlTier:       sourcecommon.ControlTierTier1Protected,
		RequiredApprovals: 3,
		Continuity:        ContinuityFromThisRevisionForward,
	}
}

func reGenesis() Predicate {
	p := genesis()
	p.OnboardedAt = time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	p.Controls = sourcecommon.BranchControls{BypassActors: []string{"release-bot"}}
	p.ControlTier = sourcecommon.ControlTierUntiered
	p.RequiredApprovals = 0
	p.Reonboarding = true
	p.Incident = "https://trentreprise.service-now.com/INC0451234"
	return p
}

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://attestations.thomsonreuters.com/source-onboarding/v1", PredicateURI)
}

func TestBuilder_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Predicate
	}{
		{name: "genesis", in: genesis()},
		{name: "re-genesis", in: reGenesis()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			stmt, err := NewStatement(tip(), &in)
			require.NoError(t, err)
			require.NoError(t, stmt.Validate())
			assert.Equal(t, map[string]string{"gitCommit": tipG}, stmt.Subject[0].Digest)

			data, err := stmt.ToJSON()
			require.NoError(t, err)

			parsed, out, err := ParseStatement(data)
			require.NoError(t, err)
			assert.Equal(t, tc.in, *out)
			assert.Equal(t, stmt.Subject, parsed.Subject)
		})
	}
}

func TestPredicate_JSONShape(t *testing.T) {
	data, err := json.Marshal(genesis())
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "from-this-revision-forward", raw["continuity"])
	assert.Equal(t, "tier1-protected", raw["controlTier"])
	assert.Equal(t, false, raw["reonboarding"])
	assert.NotContains(t, raw, "incident")
	controls, ok := raw["controls"].(map[string]any)
	require.True(t, ok)
	for _, k := range []string{"requiredApprovals", "requiresCodeownerReview", "linearHistory", "dismissStaleApprovals", "restrictsForcePush"} {
		assert.Contains(t, controls, k)
	}
}

func TestNewStatement_RejectsInvalidInput(t *testing.T) {
	_, err := NewStatement(tip(), nil)
	require.ErrorIs(t, err, intoto.ErrNilPredicate)

	p := genesis()
	_, err = NewStatement(sourcecommon.LandedCommit{Repository: "https://github.com/acme/other", Digest: tipG}, &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)

	p.Continuity = "full-history"
	_, err = NewStatement(tip(), &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestPredicate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Predicate)
		wantErr string
	}{
		{name: "valid genesis", mutate: func(*Predicate) {}},
		{name: "valid re-genesis", mutate: func(p *Predicate) { *p = reGenesis() }},
		{name: "missing repository", mutate: func(p *Predicate) { p.Repository = "" }, wantErr: "repository"},
		{name: "unqualified branch", mutate: func(p *Predicate) { p.Branch = "prod" }, wantErr: "branch"},
		{name: "missing onboardedAt", mutate: func(p *Predicate) { p.OnboardedAt = time.Time{} }, wantErr: "onboardedAt"},
		{name: "negative control approvals", mutate: func(p *Predicate) { p.Controls.RequiredApprovals = -1 }, wantErr: "controls.requiredApprovals"},
		{name: "invalid tier", mutate: func(p *Predicate) { p.ControlTier = "" }, wantErr: "controlTier"},
		{
			name:    "negative bar",
			mutate:  func(p *Predicate) { p.RequiredApprovals, p.Controls.RequiredApprovals = -1, -1 },
			wantErr: "requiredApprovals",
		},
		{name: "bar differs from controls", mutate: func(p *Predicate) { p.RequiredApprovals = 2 }, wantErr: "must equal controls.requiredApprovals"},
		{name: "invalid continuity", mutate: func(p *Predicate) { p.Continuity = "" }, wantErr: "continuity"},
		{name: "reonboarding without incident", mutate: func(p *Predicate) { p.Reonboarding = true }, wantErr: "incident"},
		{name: "incident without reonboarding", mutate: func(p *Predicate) { p.Incident = "INC1" }, wantErr: "incident"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := genesis()
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestSchema(t *testing.T) {
	s := Schema()
	require.NotNil(t, s)
	assert.Equal(t, "Source Onboarding", s.Title)

	def := s.Definitions["Predicate"]
	require.NotNil(t, def)
	assert.ElementsMatch(t, []string{
		"repository", "branch", "onboardedAt", "controls", "controlTier",
		"requiredApprovals", "continuity", "reonboarding",
	}, def.Required)
	assert.Equal(t, []any{"from-this-revision-forward"}, s.Definitions["Continuity"].Enum)
	assert.ElementsMatch(t, []string{
		"requiredApprovals", "requiresCodeownerReview", "linearHistory", "dismissStaleApprovals", "restrictsForcePush",
	}, s.Definitions["BranchControls"].Required)
}

func statementJSON(t *testing.T, p Predicate) []byte {
	t.Helper()
	stmt, err := NewStatement(tip(), &p)
	require.NoError(t, err)
	data, err := stmt.ToJSON()
	require.NoError(t, err)
	return data
}

func TestParseStatement_RejectsAbsentRequiredFields(t *testing.T) {
	data := statementJSON(t, reGenesis())
	paths := sourcetest.RequiredPaths(Schema())
	assert.Subset(
		t,
		paths,
		[]string{
			"requiredApprovals",
			"reonboarding",
			"continuity",
			"controlTier",
			"controls.requiredApprovals",
			"controls.restrictsForcePush",
			"controls.requiresCodeownerReview",
			"controls.linearHistory",
			"controls.dismissStaleApprovals",
		},
	)

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			mutated, found := sourcetest.DeletePath(t, data, "predicate."+path)
			require.True(t, found, "fixture must populate %s", path)
			_, _, err := ParseStatement(mutated)
			require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
		})
	}
}

func TestParseStatement_UnknownFields(t *testing.T) {
	data := sourcetest.SetPath(t, statementJSON(t, reGenesis()), "predicate.requiredApproval", 1)
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate, "unknown fields are rejected")
}

func TestParseStatement_RejectsEmptyPredicate(t *testing.T) {
	data := sourcetest.SetPath(t, statementJSON(t, reGenesis()), "predicate", map[string]any{})
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}
