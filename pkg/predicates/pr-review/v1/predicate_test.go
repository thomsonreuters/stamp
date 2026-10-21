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

var landedC1 = strings.Repeat("c1", 20)

func landed() sourcecommon.LandedCommit {
	return sourcecommon.LandedCommit{Repository: "https://github.com/acme/widget-svc", Digest: landedC1}
}

func minimalPredicate() Predicate {
	return Predicate{
		PullRequest:       "https://github.com/acme/widget-svc/pull/512",
		Author:            "dave",
		Approvers:         []string{},
		ApprovalCount:     0,
		RequiredApprovals: 0,
		CreatedAt:         time.Date(2026, 4, 30, 8, 0, 0, 0, time.UTC),
		MergedAt:          time.Date(2026, 5, 1, 9, 14, 0, 0, time.UTC),
	}
}

func fullPredicate() Predicate {
	p := minimalPredicate()
	p.Approvers = []string{"alice", "bob"}
	p.ApprovalCount = 2
	p.RequiredApprovals = 2
	p.RequiredApprovers = []string{"acme/widget-owners"}
	p.CodeownersSatisfied = true
	return p
}

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://attestations.thomsonreuters.com/pr-review/v1", PredicateURI)
}

func TestBuilder_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Predicate
	}{
		{name: "minimal (no approvals)", in: minimalPredicate()},
		{name: "full", in: fullPredicate()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			stmt, err := NewStatement(landed(), &in)
			require.NoError(t, err)
			require.NoError(t, stmt.Validate())
			assert.Equal(t, PredicateURI, stmt.PredicateType)
			require.Len(t, stmt.Subject, 1)
			assert.Equal(t, map[string]string{"gitCommit": landedC1}, stmt.Subject[0].Digest)

			data, err := stmt.ToJSON()
			require.NoError(t, err)

			parsed, out, err := ParseStatement(data)
			require.NoError(t, err)
			assert.Equal(t, tc.in, *out)
			assert.Equal(t, stmt.Subject, parsed.Subject)
		})
	}
}

func TestPredicate_JSONFieldNames(t *testing.T) {
	data, err := json.Marshal(fullPredicate())
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	for _, k := range []string{
		"pullRequest", "author", "approvers", "approvalCount", "requiredApprovals",
		"requiredApprovers", "codeownersSatisfied", "createdAt", "mergedAt",
	} {
		assert.Contains(t, raw, k)
	}
	assert.Equal(t, "2026-05-01T09:14:00Z", raw["mergedAt"])
}

func TestMarshalJSON_NilApproversSerializeAsArray(t *testing.T) {
	p := minimalPredicate()
	p.Approvers = nil
	data, err := json.Marshal(p)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"approvers":[]`)
	assert.NotContains(t, string(data), "requiredApprovers")
}

func TestNewStatement_RejectsInvalidInput(t *testing.T) {
	_, err := NewStatement(landed(), nil)
	require.ErrorIs(t, err, intoto.ErrNilPredicate)

	p := fullPredicate()
	_, err = NewStatement(sourcecommon.LandedCommit{Repository: landed().Repository, Digest: "C1" + landedC1[2:]}, &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)

	p.ApprovalCount = 5
	_, err = NewStatement(landed(), &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestParseStatement_RejectsWrongPredicateType(t *testing.T) {
	p := fullPredicate()
	stmt, err := NewStatement(landed(), &p)
	require.NoError(t, err)
	stmt.PredicateType = "https://attestations.thomsonreuters.com/source-provenance/v1"
	data, err := stmt.ToJSON()
	require.NoError(t, err)

	_, _, err = ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidStatement)
}

func TestPredicate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Predicate)
		wantErr string
	}{
		{name: "valid full", mutate: func(*Predicate) {}},
		{name: "valid merged at creation", mutate: func(p *Predicate) { p.MergedAt = p.CreatedAt }},
		{name: "missing pull request", mutate: func(p *Predicate) { p.PullRequest = "" }, wantErr: "pullRequest"},
		{name: "relative pull request", mutate: func(p *Predicate) { p.PullRequest = "/pull/1" }, wantErr: "pullRequest"},
		{name: "missing author", mutate: func(p *Predicate) { p.Author = "" }, wantErr: "author"},
		{name: "blank approver", mutate: func(p *Predicate) { p.Approvers[1] = "" }, wantErr: "approvers[1]"},
		{
			name:    "duplicate approver",
			mutate:  func(p *Predicate) { p.Approvers = []string{"alice", "alice"} },
			wantErr: "duplicate",
		},
		{name: "count mismatch", mutate: func(p *Predicate) { p.ApprovalCount = 3 }, wantErr: "approvalCount"},
		{name: "negative required", mutate: func(p *Predicate) { p.RequiredApprovals = -1 }, wantErr: "requiredApprovals"},
		{name: "blank required approver", mutate: func(p *Predicate) { p.RequiredApprovers = []string{" "} }, wantErr: "requiredApprovers[0]"},
		{name: "missing createdAt", mutate: func(p *Predicate) { p.CreatedAt = time.Time{} }, wantErr: "createdAt"},
		{name: "missing mergedAt", mutate: func(p *Predicate) { p.MergedAt = time.Time{} }, wantErr: "mergedAt"},
		{
			name:    "merged before created",
			mutate:  func(p *Predicate) { p.MergedAt = p.CreatedAt.Add(-time.Minute) },
			wantErr: "mergedAt must not be before createdAt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := fullPredicate()
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
	assert.Equal(t, "Pull Request Review", s.Title)

	def := s.Definitions["Predicate"]
	require.NotNil(t, def)
	assert.ElementsMatch(t, []string{
		"pullRequest", "author", "approvers", "approvalCount", "requiredApprovals",
		"codeownersSatisfied", "createdAt", "mergedAt",
	}, def.Required)
	_, ok := def.Properties.Get("requiredApprovers")
	assert.True(t, ok)
}

func statementJSON(t *testing.T, p Predicate) []byte {
	t.Helper()
	stmt, err := NewStatement(landed(), &p)
	require.NoError(t, err)
	data, err := stmt.ToJSON()
	require.NoError(t, err)
	return data
}

func TestParseStatement_RejectsAbsentRequiredFields(t *testing.T) {
	data := statementJSON(t, fullPredicate())
	paths := sourcetest.RequiredPaths(Schema())
	assert.Subset(t, paths, []string{"approvers", "approvalCount", "requiredApprovals", "codeownersSatisfied", "createdAt", "mergedAt"})

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
	data := sourcetest.SetPath(t, statementJSON(t, fullPredicate()), "predicate.approvalCuont", 1)
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate, "unknown fields are rejected")
}

func TestParseStatement_RejectsEmptyPredicate(t *testing.T) {
	data := sourcetest.SetPath(t, statementJSON(t, fullPredicate()), "predicate", map[string]any{})
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}
