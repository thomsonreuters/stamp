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

package sourcecommon

import (
	"strings"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

const testType = "https://example.com/test/v1"

var commitA = strings.Repeat("a", 40)

type bound struct {
	Commit string `json:"commit"`
}

func (b bound) Validate() error            { return ValidateGitCommit(b.Commit, "commit") }
func (b bound) LandedCommitDigest() string { return b.Commit }

type unbound struct {
	Value string `json:"value"`
}

func (u unbound) Validate() error { return ValidateRequired(u.Value, "value") }

var (
	boundSchema   = NewPredicateSchema(func() *jsonschema.Schema { return ReflectSchema(&bound{}, "b", "b", false) })
	unboundSchema = NewPredicateSchema(func() *jsonschema.Schema { return ReflectSchema(&unbound{}, "u", "u", false) })
)

func TestValidateGitCommit(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		valid bool
	}{
		{name: "sha1", in: commitA, valid: true},
		{name: "sha256", in: strings.Repeat("0f", 32), valid: true},
		{name: "empty", in: ""},
		{name: "short", in: "c1c1"},
		{name: "uppercase", in: strings.Repeat("A", 40)},
		{name: "non-hex", in: strings.Repeat("g", 40)},
		{name: "elided", in: "c1c1…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGitCommit(tc.in, "f")
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrInvalidPredicate)
			}
		})
	}
}

func TestValidateGitCommitDigestSet(t *testing.T) {
	require.NoError(t, ValidateGitCommitDigestSet(DigestSet{"gitCommit": commitA}, "d"))
	require.ErrorIs(t, ValidateGitCommitDigestSet(nil, "d"), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateGitCommitDigestSet(DigestSet{"sha1": commitA}, "d"), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateGitCommitDigestSet(DigestSet{"gitCommit": commitA, "sha256": "aa"}, "d"), ErrInvalidPredicate)
}

func TestValidateRefURIURL(t *testing.T) {
	require.NoError(t, ValidateRef("refs/heads/dev", "r"))
	require.ErrorIs(t, ValidateRef("dev", "r"), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateRef("refs/", "r"), ErrInvalidPredicate)

	require.NoError(t, ValidateURI("git+https://github.com/a/b@refs/heads/dev", "u"))
	require.ErrorIs(t, ValidateURI("github.com/a/b", "u"), ErrInvalidPredicate)

	require.NoError(t, ValidateURL("https://github.com/a/b/pull/1", "u"))
	require.ErrorIs(t, ValidateURL("git+https://github.com/a/b", "u"), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateURL("https://", "u"), ErrInvalidPredicate)
}

func TestValidateLogins(t *testing.T) {
	require.NoError(t, ValidateLogins(nil, "l", 0))
	require.NoError(t, ValidateLogins([]string{"a", "b"}, "l", 2))
	require.ErrorIs(t, ValidateLogins([]string{"a"}, "l", 2), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateLogins([]string{"a", "a"}, "l", 0), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateLogins([]string{""}, "l", 0), ErrInvalidPredicate)
}

func TestValidateRevisionEdge(t *testing.T) {
	uri, digest := "git+https://github.com/a/b@refs/heads/dev", DigestSet{"gitCommit": commitA}
	require.NoError(t, ValidateRevisionEdge(uri, digest, "e"))
	require.ErrorIs(t, ValidateRevisionEdge("", digest, "e"), ErrInvalidPredicate)
	require.ErrorIs(t, ValidateRevisionEdge(uri, nil, "e"), ErrInvalidPredicate)
}

func TestControlTier(t *testing.T) {
	for _, tier := range ControlTiers() {
		assert.True(t, tier.IsValid())
	}
	assert.False(t, ControlTier("tier3").IsValid())
	assert.Equal(t, []any{"tier1-protected", "tier2", "untiered"}, ControlTier("").JSONSchema().Enum)
}

func TestBranchControls_Validate(t *testing.T) {
	require.NoError(t, BranchControls{RequiredApprovals: 2, BypassActors: []string{"admins"}}.Validate("c"))
	require.ErrorIs(t, BranchControls{RequiredApprovals: -1}.Validate("c"), ErrInvalidPredicate)
	require.ErrorIs(t, BranchControls{BypassActors: []string{""}}.Validate("c"), ErrInvalidPredicate)
}

func TestLandedCommit(t *testing.T) {
	c := LandedCommit{Repository: "https://github.com/a/b", Digest: commitA}
	require.NoError(t, c.Validate())
	assert.Equal(t, intoto.Subject{
		Name:   "git+https://github.com/a/b@" + commitA,
		Digest: map[string]string{"gitCommit": commitA},
	}, c.Subject())

	require.ErrorIs(t, LandedCommit{Repository: "b", Digest: commitA}.Validate(), ErrInvalidPredicate)
	require.ErrorIs(t, LandedCommit{Repository: c.Repository, Digest: "x"}.Validate(), ErrInvalidPredicate)
}

func TestNewStatement(t *testing.T) {
	c := LandedCommit{Repository: "https://github.com/a/b", Digest: commitA}

	stmt, err := NewStatement(testType, boundSchema, c, bound{Commit: commitA})
	require.NoError(t, err)
	require.NoError(t, stmt.Validate())
	assert.Equal(t, []intoto.Subject{c.Subject()}, stmt.Subject)

	_, err = NewStatement(testType, boundSchema, c, bound{Commit: strings.Repeat("b", 40)})
	require.ErrorIs(t, err, ErrSubjectNotLandedCommit)

	_, err = NewStatement(testType, unboundSchema, c, unbound{})
	require.ErrorIs(t, err, ErrInvalidPredicate)

	_, err = NewStatement(testType, unboundSchema, c, nil)
	require.ErrorIs(t, err, intoto.ErrNilPredicate)

	_, err = NewStatement("", unboundSchema, c, unbound{Value: "v"})
	require.ErrorIs(t, err, intoto.ErrEmptyPredicateType)
}

func TestDecodeStatement(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr error
	}{
		{
			name: "valid, multiple subjects of any digest",
			json: `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `",
				"subject":[{"digest":{"sha256":"aa"}},{"name":"x","digest":{"gitCommit":"` + commitA + `"}}],
				"predicate":{"value":"v"}}`,
		},
		{name: "malformed", json: `{`, wantErr: ErrInvalidStatement},
		{
			name:    "wrong _type",
			json:    `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"` + testType + `","subject":[{"digest":{"a":"b"}}],"predicate":{"value":"v"}}`,
			wantErr: ErrInvalidStatement,
		},
		{
			name:    "wrong predicateType",
			json:    `{"_type":"https://in-toto.io/Statement/v1","predicateType":"other","subject":[{"digest":{"a":"b"}}],"predicate":{"value":"v"}}`,
			wantErr: ErrInvalidStatement,
		},
		{
			name:    "no subjects",
			json:    `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `","subject":[],"predicate":{"value":"v"}}`,
			wantErr: intoto.ErrNoSubjects,
		},
		{
			name:    "subject without digest",
			json:    `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `","subject":[{"name":"x"}],"predicate":{"value":"v"}}`,
			wantErr: intoto.ErrNoSubjectDigests,
		},
		{
			name:    "null predicate",
			json:    `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `","subject":[{"digest":{"a":"b"}}],"predicate":null}`,
			wantErr: intoto.ErrNilPredicate,
		},
		{
			name:    "predicate wrong shape",
			json:    `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `","subject":[{"digest":{"a":"b"}}],"predicate":[]}`,
			wantErr: ErrInvalidPredicate,
		},
		{
			name:    "predicate invalid",
			json:    `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `","subject":[{"digest":{"a":"b"}}],"predicate":{}}`,
			wantErr: ErrInvalidPredicate,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var dst unbound
			stmt, err := DecodeStatement([]byte(tc.json), testType, unboundSchema, &dst)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, stmt)
				return
			}
			require.NoError(t, err)
			assert.Same(t, &dst, stmt.Predicate)
		})
	}
}

func TestDecodeSourceStatement(t *testing.T) {
	stmtJSON := func(subjects string, commit string) string {
		return `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + testType + `",
			"subject":` + subjects + `,"predicate":{"commit":"` + commit + `"}}`
	}
	one := `[{"digest":{"gitCommit":"` + commitA + `"}}]`

	var dst bound
	stmt, err := DecodeSourceStatement([]byte(stmtJSON(one, commitA)), testType, boundSchema, &dst)
	require.NoError(t, err)
	assert.Equal(t, commitA, stmt.Subject[0].Digest["gitCommit"])

	_, err = DecodeSourceStatement([]byte(stmtJSON(one, strings.Repeat("b", 40))), testType, boundSchema, &bound{})
	require.ErrorIs(t, err, ErrSubjectNotLandedCommit)

	two := `[{"digest":{"gitCommit":"` + commitA + `"}},{"digest":{"gitCommit":"` + commitA + `"}}]`
	_, err = DecodeSourceStatement([]byte(stmtJSON(two, commitA)), testType, boundSchema, &bound{})
	require.ErrorIs(t, err, ErrInvalidStatement)

	sha := `[{"digest":{"sha256":"` + commitA + `"}}]`
	_, err = DecodeSourceStatement([]byte(stmtJSON(sha, commitA)), testType, boundSchema, &bound{})
	require.ErrorIs(t, err, ErrInvalidStatement)

	_, err = DecodeSourceStatement([]byte(`{`), testType, boundSchema, &bound{})
	require.ErrorIs(t, err, ErrInvalidStatement)
}
