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

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon"
	"github.com/thomsonreuters/stamp/pkg/predicates/sourcecommon/sourcetest"
)

var (
	landedC1 = strings.Repeat("c1", 20)
	tipD2    = strings.Repeat("d2", 20)
	tipD1    = strings.Repeat("d1", 20)
)

// specExampleJSON is the source-provenance example from the GitHub Source
// Attestations specification section 3.2, with the elided digests expanded to
// full-length commit IDs.
var specExampleJSON = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "digest": { "gitCommit": "` + landedC1 + `" } }],
  "predicateType": "https://attestations.thomsonreuters.com/source-provenance/v1",
  "predicate": {
    "mergedRevision": { "ref": "refs/heads/prod", "digest": { "gitCommit": "` + landedC1 + `" } },
    "mergeStrategy": "squash",
    "reviewedParentRevisions": [
      { "uri": "git+https://github.com/acme/widget-svc@refs/heads/dev",
        "digest": { "gitCommit": "` + tipD2 + `" } }
    ],
    "pullRequest": "https://github.com/acme/widget-svc/pull/512",
    "mergedBy": "carol",
    "mergedAt": "2026-05-01T09:14:00Z",
    "actualApprovals": 2,
    "claimedRequiredApprovals": 2,
    "observedRequiredApprovals": 2
  }
}`

func landed() sourcecommon.LandedCommit {
	return sourcecommon.LandedCommit{Repository: "https://github.com/acme/widget-svc", Digest: landedC1}
}

func edge(ref, digest string) ParentRevision {
	return ParentRevision{
		URI:    "git+https://github.com/acme/widget-svc@" + ref,
		Digest: sourcecommon.DigestSet{sourcecommon.GitCommitDigestAlgorithm: digest},
	}
}

func continuityEdge(ref, digest string) ParentRevision {
	e := edge(ref, digest)
	e.Annotations = &ParentAnnotations{Role: ParentRoleContinuityParent}
	return e
}

func minimalPredicate() Predicate {
	return Predicate{
		MergedRevision: MergedRevision{
			Ref:    "refs/heads/prod",
			Digest: sourcecommon.DigestSet{sourcecommon.GitCommitDigestAlgorithm: landedC1},
		},
		MergeStrategy:             MergeStrategySquash,
		ReviewedParentRevisions:   []ParentRevision{edge("refs/heads/dev", tipD2)},
		PullRequest:               "https://github.com/acme/widget-svc/pull/512",
		MergedBy:                  "carol",
		MergedAt:                  time.Date(2026, 5, 1, 9, 14, 0, 0, time.UTC),
		ActualApprovals:           2,
		ClaimedRequiredApprovals:  2,
		ObservedRequiredApprovals: 2,
	}
}

func fullPredicate() Predicate {
	p := minimalPredicate()
	p.MergedRevision.Ref = "refs/heads/dev"
	p.MergeStrategy = MergeStrategyMerge
	p.ReviewedParentRevisions = []ParentRevision{
		edge("refs/heads/feat/feature2", tipD2),
		continuityEdge("refs/heads/dev", tipD1),
	}
	p.ActualApprovals = 3
	p.ClaimedRequiredApprovals = 3
	p.ObservedRequiredApprovals = 2
	p.ClaimedTier = sourcecommon.ControlTierTier1Protected
	p.ObservedControls = &sourcecommon.BranchControls{
		RequiredApprovals:       2,
		RequiresCodeownerReview: true,
		LinearHistory:           true,
		DismissStaleApprovals:   true,
		RestrictsForcePush:      true,
		BypassActors:            []string{"org-admins"},
	}
	return p
}

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://attestations.thomsonreuters.com/source-provenance/v1", PredicateURI)
	assert.Equal(t, "predicate.reviewedParentRevisions", BridgeDependenciesPath)
}

func TestMergeStrategy_IsValid(t *testing.T) {
	for _, s := range MergeStrategies() {
		assert.True(t, s.IsValid(), s)
	}
	assert.False(t, MergeStrategy("fast-forward").IsValid())
	assert.False(t, MergeStrategy("").IsValid())
}

func TestSpecExample_RoundTrip(t *testing.T) {
	stmt, p, err := ParseStatement([]byte(specExampleJSON))
	require.NoError(t, err)

	assert.Equal(t, PredicateURI, stmt.PredicateType)
	assert.Equal(t, landedC1, stmt.Subject[0].Digest[sourcecommon.GitCommitDigestAlgorithm])
	assert.Equal(t, minimalPredicate(), *p)

	// Marshal the parsed statement and compare it to the spec's JSON.
	out, err := stmt.ToJSON()
	require.NoError(t, err)
	assert.JSONEq(t, specExampleJSON, string(out))

	_, p2, err := ParseStatement(out)
	require.NoError(t, err)
	assert.Equal(t, p, p2)
}

func TestBuilder_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Predicate
	}{
		{name: "minimal", in: minimalPredicate()},
		{name: "full with control-tier fields", in: fullPredicate()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			stmt, err := NewStatement(landed(), &in)
			require.NoError(t, err)
			require.NoError(t, stmt.Validate())

			require.Len(t, stmt.Subject, 1)
			assert.Equal(t, map[string]string{"gitCommit": landedC1}, stmt.Subject[0].Digest)
			assert.Equal(t, "git+https://github.com/acme/widget-svc@"+landedC1, stmt.Subject[0].Name)

			data, err := stmt.ToJSON()
			require.NoError(t, err)

			parsed, out, err := ParseStatement(data)
			require.NoError(t, err)
			assert.Equal(t, tc.in, *out)
			assert.Equal(t, stmt.Subject, parsed.Subject)
		})
	}
}

func TestApprovalFields_AreDistinctAndAlwaysSerialized(t *testing.T) {
	p := minimalPredicate()
	p.ActualApprovals = 0
	p.ClaimedRequiredApprovals = 3
	p.ObservedRequiredApprovals = 0

	data, err := json.Marshal(p)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.InDelta(t, 0, raw["actualApprovals"], 0)
	assert.InDelta(t, 3, raw["claimedRequiredApprovals"], 0)
	assert.InDelta(t, 0, raw["observedRequiredApprovals"], 0)
	assert.NotContains(t, raw, "claimedTier")
	assert.NotContains(t, raw, "observedControls")
}

func TestNewStatement_RejectsSubjectThatIsNotLandedCommit(t *testing.T) {
	p := minimalPredicate()

	tests := []struct {
		name   string
		commit sourcecommon.LandedCommit
	}{
		{name: "reviewed parent (PR head)", commit: sourcecommon.LandedCommit{Repository: landed().Repository, Digest: tipD2}},
		{name: "unrelated commit", commit: sourcecommon.LandedCommit{Repository: landed().Repository, Digest: strings.Repeat("ab", 20)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, err := NewStatement(tc.commit, &p)
			require.ErrorIs(t, err, sourcecommon.ErrSubjectNotLandedCommit)
			assert.Nil(t, stmt)
		})
	}
}

func TestNewStatement_RejectsInvalidInput(t *testing.T) {
	_, err := NewStatement(landed(), nil)
	require.ErrorIs(t, err, intoto.ErrNilPredicate)

	p := minimalPredicate()
	_, err = NewStatement(sourcecommon.LandedCommit{Repository: "https://github.com/acme/widget-svc", Digest: "c1c1"}, &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)

	_, err = NewStatement(sourcecommon.LandedCommit{Repository: "", Digest: landedC1}, &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)

	p.MergeStrategy = "octopus"
	_, err = NewStatement(landed(), &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestParseStatement_RejectsSubjectMismatch(t *testing.T) {
	data := strings.Replace(specExampleJSON,
		`"subject": [{ "digest": { "gitCommit": "`+landedC1+`" } }]`,
		`"subject": [{ "digest": { "gitCommit": "`+tipD2+`" } }]`, 1)

	_, _, err := ParseStatement([]byte(data))
	require.ErrorIs(t, err, sourcecommon.ErrSubjectNotLandedCommit)
}

func TestParseStatement_RejectsInvalidEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr error
	}{
		{
			name:    "wrong predicate type",
			mutate:  func(s string) string { return strings.Replace(s, "source-provenance/v1", "pr-review/v1", 1) },
			wantErr: sourcecommon.ErrInvalidStatement,
		},
		{
			name: "extra subject digest algorithm",
			mutate: func(s string) string {
				return strings.Replace(s, `"subject": [{ "digest": { "gitCommit"`, `"subject": [{ "digest": { "sha256": "aa", "gitCommit"`, 1)
			},
			wantErr: sourcecommon.ErrInvalidStatement,
		},
		{
			name: "two subjects",
			mutate: func(s string) string {
				return strings.Replace(s, `"subject": [`, `"subject": [{ "digest": { "gitCommit": "`+tipD1+`" } },`, 1)
			},
			wantErr: sourcecommon.ErrInvalidStatement,
		},
		{
			name:    "empty reviewedParentRevisions",
			mutate:  func(s string) string { return replaceBetween(s, `"reviewedParentRevisions": [`, `],`, "") },
			wantErr: sourcecommon.ErrInvalidPredicate,
		},
		{
			name:    "malformed JSON",
			mutate:  func(s string) string { return s[:len(s)-2] },
			wantErr: sourcecommon.ErrInvalidStatement,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseStatement([]byte(tc.mutate(specExampleJSON)))
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestPredicate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Predicate)
		wantErr string
	}{
		{name: "valid minimal", mutate: func(*Predicate) {}},
		{name: "valid full", mutate: func(p *Predicate) { *p = fullPredicate() }},
		{name: "unqualified ref", mutate: func(p *Predicate) { p.MergedRevision.Ref = "prod" }, wantErr: "mergedRevision.ref"},
		{name: "missing merged digest", mutate: func(p *Predicate) { p.MergedRevision.Digest = nil }, wantErr: "mergedRevision.digest"},
		{
			name:    "non-gitCommit merged digest",
			mutate:  func(p *Predicate) { p.MergedRevision.Digest = sourcecommon.DigestSet{"sha1": landedC1} },
			wantErr: "mergedRevision.digest",
		},
		{name: "invalid merge strategy", mutate: func(p *Predicate) { p.MergeStrategy = "" }, wantErr: "mergeStrategy"},
		{name: "no parents", mutate: func(p *Predicate) { p.ReviewedParentRevisions = nil }, wantErr: "reviewedParentRevisions"},
		{
			name:    "parent without uri",
			mutate:  func(p *Predicate) { p.ReviewedParentRevisions[0].URI = "" },
			wantErr: "reviewedParentRevisions[0].uri",
		},
		{
			name:    "parent without digest",
			mutate:  func(p *Predicate) { p.ReviewedParentRevisions[0].Digest = nil },
			wantErr: "reviewedParentRevisions[0].digest",
		},
		{
			name:    "parent with short digest",
			mutate:  func(p *Predicate) { p.ReviewedParentRevisions[0].Digest = sourcecommon.DigestSet{"gitCommit": "d2d2"} },
			wantErr: "reviewedParentRevisions[0].digest.gitCommit",
		},
		{
			name: "two unannotated edges (roles undeterminable)",
			mutate: func(p *Predicate) {
				p.MergedRevision.Ref = "refs/heads/dev"
				p.ReviewedParentRevisions = []ParentRevision{edge("refs/heads/feat/f", tipD2), edge("refs/heads/dev", tipD1)}
			},
			wantErr: "exactly one reviewed-head edge",
		},
		{
			name: "only a continuity parent",
			mutate: func(p *Predicate) {
				p.MergedRevision.Ref = "refs/heads/dev"
				p.ReviewedParentRevisions = []ParentRevision{continuityEdge("refs/heads/dev", tipD1)}
			},
			wantErr: "exactly one reviewed-head edge",
		},
		{
			name: "two continuity parents",
			mutate: func(p *Predicate) {
				*p = fullPredicate()
				p.ReviewedParentRevisions = append(p.ReviewedParentRevisions, continuityEdge("refs/heads/dev", strings.Repeat("e3", 20)))
			},
			wantErr: "at most one continuity-parent edge",
		},
		{
			name: "continuity parent on another branch",
			mutate: func(p *Predicate) {
				*p = fullPredicate()
				p.ReviewedParentRevisions[1] = continuityEdge("refs/heads/main", tipD1)
			},
			wantErr: "must reference mergedRevision.ref",
		},
		{
			name: "unknown role",
			mutate: func(p *Predicate) {
				p.ReviewedParentRevisions[0].Annotations = &ParentAnnotations{Role: "sibling"}
			},
			wantErr: "annotations.role",
		},
		{
			name: "parent is landed commit",
			mutate: func(p *Predicate) {
				p.ReviewedParentRevisions = append(p.ReviewedParentRevisions, continuityEdge("refs/heads/prod", landedC1))
			},
			wantErr: "must not reference the landed commit",
		},
		{
			name: "duplicate parent",
			mutate: func(p *Predicate) {
				p.ReviewedParentRevisions = append(p.ReviewedParentRevisions, continuityEdge("refs/heads/prod", tipD2))
			},
			wantErr: "duplicates parent",
		},
		{name: "invalid pull request", mutate: func(p *Predicate) { p.PullRequest = "pull/512" }, wantErr: "pullRequest"},
		{name: "missing mergedBy", mutate: func(p *Predicate) { p.MergedBy = " " }, wantErr: "mergedBy"},
		{name: "missing mergedAt", mutate: func(p *Predicate) { p.MergedAt = time.Time{} }, wantErr: "mergedAt"},
		{name: "negative actual", mutate: func(p *Predicate) { p.ActualApprovals = -1 }, wantErr: "actualApprovals"},
		{name: "negative claimed", mutate: func(p *Predicate) { p.ClaimedRequiredApprovals = -1 }, wantErr: "claimedRequiredApprovals"},
		{name: "negative observed", mutate: func(p *Predicate) { p.ObservedRequiredApprovals = -1 }, wantErr: "observedRequiredApprovals"},
		{name: "invalid claimed tier", mutate: func(p *Predicate) { p.ClaimedTier = "gold" }, wantErr: "claimedTier"},
		{
			name: "observed controls split read",
			mutate: func(p *Predicate) {
				*p = fullPredicate()
				p.ObservedControls.RequiredApprovals = 3
			},
			wantErr: "must equal observedRequiredApprovals",
		},
		{
			name: "observed controls invalid bypass actors",
			mutate: func(p *Predicate) {
				*p = fullPredicate()
				p.ObservedControls.BypassActors = []string{"a", "a"}
			},
			wantErr: "observedControls.bypassActors",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := minimalPredicate()
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

func TestMarshalJSON_NilParentsSerializeAsArray(t *testing.T) {
	data, err := json.Marshal(Predicate{})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"reviewedParentRevisions":[]`)
}

func TestSchema(t *testing.T) {
	s := Schema()
	require.NotNil(t, s)
	assert.Equal(t, "Source Provenance", s.Title)

	def := s.Definitions["Predicate"]
	require.NotNil(t, def)
	assert.ElementsMatch(t, []string{
		"mergedRevision", "mergeStrategy", "reviewedParentRevisions", "pullRequest", "mergedBy", "mergedAt",
		"actualApprovals", "claimedRequiredApprovals", "observedRequiredApprovals",
	}, def.Required)
	assert.Equal(t, jsonschema.FalseSchema, def.AdditionalProperties)

	for _, k := range []string{"claimedTier", "observedControls"} {
		_, ok := def.Properties.Get(k)
		assert.True(t, ok, k)
	}
	parents, ok := def.Properties.Get("reviewedParentRevisions")
	require.True(t, ok)
	require.NotNil(t, parents.MinItems)
	assert.Equal(t, uint64(1), *parents.MinItems)

	assert.Equal(t, []any{"merge", "squash", "rebase"}, s.Definitions["MergeStrategy"].Enum)
	assert.Equal(t, []any{"tier1-protected", "tier2", "untiered"}, s.Definitions["ControlTier"].Enum)
}

func replaceBetween(s, start, end, with string) string {
	i := strings.Index(s, start)
	j := strings.Index(s[i+len(start):], end)
	return s[:i+len(start)] + with + s[i+len(start)+j:]
}

func fullStatementJSON(t *testing.T) []byte {
	t.Helper()
	p := fullPredicate()
	stmt, err := NewStatement(landed(), &p)
	require.NoError(t, err)
	data, err := stmt.ToJSON()
	require.NoError(t, err)
	return data
}

func TestParseStatement_RejectsAbsentRequiredFields(t *testing.T) {
	data := fullStatementJSON(t)
	paths := sourcetest.RequiredPaths(Schema())
	assert.Subset(t, paths, []string{
		"actualApprovals", "claimedRequiredApprovals", "observedRequiredApprovals",
		"observedControls.requiredApprovals", "observedControls.restrictsForcePush",
		"observedControls.requiresCodeownerReview", "observedControls.linearHistory",
		"observedControls.dismissStaleApprovals", "reviewedParentRevisions.0.uri",
		"reviewedParentRevisions.0.digest", "reviewedParentRevisions.0.annotations.role",
	})

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			mutated, found := sourcetest.DeletePath(t, data, "predicate."+path)
			if !found {
				mutated, found = sourcetest.DeletePath(t, data, "predicate."+strings.Replace(path, ".0.", ".1.", 1))
			}
			require.True(t, found, "full fixture must populate %s", path)
			_, _, err := ParseStatement(mutated)
			require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
		})
	}
}

func TestParseStatement_RejectsAbsentApprovalCounts(t *testing.T) {
	data := []byte(specExampleJSON)
	for _, path := range []string{"predicate.actualApprovals", "predicate.claimedRequiredApprovals"} {
		data, _ = sourcetest.DeletePath(t, data, path)
	}
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestParseStatement_RejectsUnknownFields(t *testing.T) {
	for _, path := range []string{
		"predicate.claimedRequiredApproval",
		"predicate.mergedRevision.uri",
		"predicate.observedControls.bypass",
		"predicate.reviewedParentRevisions.1.annotations.comment",
	} {
		t.Run(path, func(t *testing.T) {
			_, _, err := ParseStatement(sourcetest.SetPath(t, fullStatementJSON(t), path, 2))
			require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
		})
	}
}

func TestParseStatement_RejectsEmptyPredicate(t *testing.T) {
	data := sourcetest.SetPath(t, []byte(specExampleJSON), "predicate", map[string]any{})
	_, _, err := ParseStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestSpecExample_SubjectNameDecision(t *testing.T) {
	// The spec example has no subject name. Parsing accepts it (in-toto v1),
	// but stamp signs only named statements, so Validate rejects it.
	stmt, _, err := ParseStatement([]byte(specExampleJSON))
	require.NoError(t, err)
	require.ErrorIs(t, stmt.Validate(), intoto.ErrEmptySubjectName)

	p := minimalPredicate()
	built, err := NewStatement(landed(), &p)
	require.NoError(t, err)
	require.NoError(t, built.Validate())
}

func TestEdgeRoles(t *testing.T) {
	promotion := minimalPredicate()
	head, ok := promotion.ReviewedHead()
	require.True(t, ok)
	assert.Equal(t, tipD2, head.Digest.GitCommit())
	_, ok = promotion.ContinuityParent()
	assert.False(t, ok)

	landing := fullPredicate()
	head, ok = landing.ReviewedHead()
	require.True(t, ok)
	assert.Equal(t, tipD2, head.Digest.GitCommit())
	cont, ok := landing.ContinuityParent()
	require.True(t, ok)
	assert.Equal(t, tipD1, cont.Digest.GitCommit())

	data, err := json.Marshal(landing)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"annotations":{"role":"continuity-parent"}`)
	assert.Equal(t, 1, strings.Count(string(data), `"annotations"`), "reviewed head stays unannotated")
}
