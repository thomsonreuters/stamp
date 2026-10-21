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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon/sourcetest"
)

var tipX = strings.Repeat("9f", 20)

// specExampleJSON is the emergency-change example from the GitHub Source
// Attestations specification section 7.3, with the elided digest expanded.
var specExampleJSON = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "digest": { "gitCommit": "` + tipX + `" } }],
  "predicateType": "https://attestations.thomsonreuters.com/emergency-change/v1",
  "predicate": {
    "incident": "https://trentreprise.service-now.com/INC0451234",
    "justification": "prod outage — hotfix bypassed review under incident commander authority",
    "authorizedBy": ["alice", "bob"],
    "changeType": "force-push",
    "branch": "refs/heads/prod",
    "expiresAt": "2026-07-09T12:00:00Z",
    "postHocReviewDue": "2026-07-11T12:00:00Z"
  }
}`

func emergencyTip() sourcecommon.LandedCommit {
	return sourcecommon.LandedCommit{Repository: "https://github.com/acme/widget-svc", Digest: tipX}
}

func examplePredicate() Predicate {
	return Predicate{
		Incident:         "https://trentreprise.service-now.com/INC0451234",
		Justification:    "prod outage — hotfix bypassed review under incident commander authority",
		AuthorizedBy:     []string{"alice", "bob"},
		ChangeType:       ChangeTypeForcePush,
		Branch:           "refs/heads/prod",
		ExpiresAt:        time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		PostHocReviewDue: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
	}
}

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://attestations.thomsonreuters.com/emergency-change/v1", PredicateURI)
}

func TestChangeType_IsValid(t *testing.T) {
	for _, c := range ChangeTypes() {
		assert.True(t, c.IsValid(), c)
	}
	assert.False(t, ChangeType("revert").IsValid())
}

func TestSpecExample_Parse(t *testing.T) {
	stmt, p, err := ParseStatement([]byte(specExampleJSON))
	require.NoError(t, err)
	assert.Equal(t, tipX, stmt.Subject[0].Digest["gitCommit"])
	assert.Equal(t, examplePredicate(), *p)
}

func TestBuilder_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Predicate
	}{
		{name: "force push", in: examplePredicate()},
		{
			name: "expedited hotfix",
			in: func() Predicate {
				p := examplePredicate()
				p.ChangeType = ChangeTypeExpeditedHotfix
				p.AuthorizedBy = []string{"alice"}
				p.Incident = "INC0451299"
				return p
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			stmt, err := NewStatement(emergencyTip(), &in)
			require.NoError(t, err)
			require.NoError(t, stmt.Validate())

			data, err := stmt.ToJSON()
			require.NoError(t, err)

			parsed, out, err := ParseStatement(data)
			require.NoError(t, err)
			assert.Equal(t, tc.in, *out)
			assert.Equal(t, stmt.Subject, parsed.Subject)
		})
	}
}

func TestNewStatement_RejectsInvalidInput(t *testing.T) {
	_, err := NewStatement(emergencyTip(), nil)
	require.ErrorIs(t, err, intoto.ErrNilPredicate)

	p := examplePredicate()
	_, err = NewStatement(sourcecommon.LandedCommit{Repository: "https://github.com/acme/widget-svc", Digest: "x9x9"}, &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestPredicate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Predicate)
		wantErr string
	}{
		{name: "valid", mutate: func(*Predicate) {}},
		{name: "missing incident", mutate: func(p *Predicate) { p.Incident = "" }, wantErr: "incident"},
		{name: "missing justification", mutate: func(p *Predicate) { p.Justification = "  " }, wantErr: "justification"},
		{name: "no authorizers", mutate: func(p *Predicate) { p.AuthorizedBy = nil }, wantErr: "authorizedBy"},
		{name: "duplicate authorizer", mutate: func(p *Predicate) { p.AuthorizedBy = []string{"bob", "bob"} }, wantErr: "authorizedBy"},
		{name: "invalid change type", mutate: func(p *Predicate) { p.ChangeType = "" }, wantErr: "changeType"},
		{name: "unqualified branch", mutate: func(p *Predicate) { p.Branch = "prod" }, wantErr: "branch"},
		{name: "missing expiresAt", mutate: func(p *Predicate) { p.ExpiresAt = time.Time{} }, wantErr: "expiresAt"},
		{name: "missing postHocReviewDue", mutate: func(p *Predicate) { p.PostHocReviewDue = time.Time{} }, wantErr: "postHocReviewDue"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := examplePredicate()
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
	assert.Equal(t, "Emergency Change", s.Title)

	def := s.Definitions["Predicate"]
	require.NotNil(t, def)
	assert.ElementsMatch(t, []string{
		"incident", "justification", "authorizedBy", "changeType", "branch", "expiresAt", "postHocReviewDue",
	}, def.Required)
	assert.Equal(t, []any{"force-push", "direct-push", "expedited-hotfix"}, s.Definitions["ChangeType"].Enum)
}

func statementJSON(t *testing.T, p Predicate) []byte {
	t.Helper()
	stmt, err := NewStatement(emergencyTip(), &p)
	require.NoError(t, err)
	data, err := stmt.ToJSON()
	require.NoError(t, err)
	return data
}

func TestParseStatement_RejectsAbsentRequiredFields(t *testing.T) {
	data := statementJSON(t, examplePredicate())
	paths := sourcetest.RequiredPaths(Schema())
	assert.Subset(t, paths, []string{"incident", "justification", "authorizedBy", "changeType", "branch", "expiresAt", "postHocReviewDue"})

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
	data := sourcetest.SetPath(t, statementJSON(t, examplePredicate()), "predicate.expiresAtt", 1)
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate, "unknown fields are rejected")
}

func TestParseStatement_RejectsEmptyPredicate(t *testing.T) {
	data := sourcetest.SetPath(t, statementJSON(t, examplePredicate()), "predicate", map[string]any{})
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}
