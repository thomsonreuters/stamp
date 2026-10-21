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

var tipD2 = strings.Repeat("d2", 20)

// upstreamVSAJSON exercises consumption of a VSA with an image subject and
// fields this package does not model (forward compatibility).
const upstreamVSAJSON = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "ghcr.io/acme/widget-svc", "digest": { "sha256": "abcd" } }],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": { "id": "https://github.com/tr/source-gate", "version": { "engine": "1.4.0" } },
    "timeVerified": "2026-05-01T09:20:00Z",
    "resourceUri": "oci://ghcr.io/acme/widget-svc",
    "policy": { "uri": "global/security/deploy-tier1/v1" },
    "inputAttestations": [{ "uri": "https://store.example/att/1", "digest": { "sha256": "1234" } }],
    "verificationResult": "PASSED",
    "verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
    "dependencyLevels": { "SLSA_BUILD_LEVEL_3": 2 },
    "slsaVersion": "1.0",
    "futureField": { "x": 1 }
  }
}`

func sourceVSA() Predicate {
	return Predicate{
		Verifier:     Verifier{ID: "https://github.com/tr/source-gate", Version: map[string]string{"engine": "1.4.0"}},
		TimeVerified: time.Date(2026, 5, 1, 9, 15, 0, 0, time.UTC),
		ResourceURI:  "git+https://github.com/acme/widget-svc@refs/heads/dev",
		Policy: sourcecommon.ResourceDescriptor{
			URI: "global/security/source-review-continuity/v1",
		},
		InputAttestations: []sourcecommon.ResourceDescriptor{
			{URI: "https://store.example/att/pr-review", Digest: sourcecommon.DigestSet{"sha256": "aa"}},
		},
		VerificationResult: VerificationResultPassed,
		VerifiedLevels:     []string{},
	}
}

func devTip() sourcecommon.LandedCommit {
	return sourcecommon.LandedCommit{Repository: "https://github.com/acme/widget-svc", Digest: tipD2}
}

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://slsa.dev/verification_summary/v1", PredicateURI)
}

func TestVerificationResult_IsValid(t *testing.T) {
	assert.True(t, VerificationResultPassed.IsValid())
	assert.True(t, VerificationResultFailed.IsValid())
	assert.False(t, VerificationResult("passed").IsValid())
}

func TestSourceStatement_RoundTrip(t *testing.T) {
	for _, result := range VerificationResults() {
		t.Run(string(result), func(t *testing.T) {
			in := sourceVSA()
			in.VerificationResult = result
			stmt, err := NewSourceStatement(devTip(), &in)
			require.NoError(t, err)
			require.NoError(t, stmt.Validate())
			assert.Equal(t, map[string]string{"gitCommit": tipD2}, stmt.Subject[0].Digest)

			data, err := stmt.ToJSON()
			require.NoError(t, err)

			parsed, out, err := ParseSourceStatement(data)
			require.NoError(t, err)
			assert.Equal(t, in, *out)
			assert.Equal(t, stmt.Subject, parsed.Subject)
			assert.Equal(t, result == VerificationResultPassed, out.Passed())
		})
	}
}

func TestParseStatement_UpstreamVSA(t *testing.T) {
	stmt, p, err := ParseStatement([]byte(upstreamVSAJSON))
	require.NoError(t, err)
	assert.Equal(t, "abcd", stmt.Subject[0].Digest["sha256"])
	assert.True(t, p.Passed())
	assert.Equal(t, "global/security/deploy-tier1/v1", p.Policy.URI)
	assert.Equal(t, map[string]int{"SLSA_BUILD_LEVEL_3": 2}, p.DependencyLevels)

	// A non-gitCommit subject is not a source-side VSA.
	_, _, err = ParseSourceStatement([]byte(upstreamVSAJSON))
	require.ErrorIs(t, err, sourcecommon.ErrInvalidStatement)
}

func TestMarshalJSON_NilVerifiedLevelsSerializeAsArray(t *testing.T) {
	p := sourceVSA()
	p.VerifiedLevels = nil
	data, err := json.Marshal(p)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"verifiedLevels":[]`)
}

func TestNewSourceStatement_RejectsInvalidInput(t *testing.T) {
	_, err := NewSourceStatement(devTip(), nil)
	require.ErrorIs(t, err, intoto.ErrNilPredicate)

	p := sourceVSA()
	p.VerificationResult = ""
	_, err = NewSourceStatement(devTip(), &p)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}

func TestPredicate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Predicate)
		wantErr string
	}{
		{name: "valid", mutate: func(*Predicate) {}},
		{name: "missing verifier", mutate: func(p *Predicate) { p.Verifier.ID = "" }, wantErr: "verifier.id"},
		{name: "relative verifier", mutate: func(p *Predicate) { p.Verifier.ID = "source-gate" }, wantErr: "verifier.id"},
		{name: "missing timeVerified", mutate: func(p *Predicate) { p.TimeVerified = time.Time{} }, wantErr: "timeVerified"},
		{name: "missing resourceUri", mutate: func(p *Predicate) { p.ResourceURI = "" }, wantErr: "resourceUri"},
		{name: "missing policy uri", mutate: func(p *Predicate) { p.Policy.URI = "" }, wantErr: "policy.uri"},
		{name: "input without uri", mutate: func(p *Predicate) { p.InputAttestations[0].URI = "" }, wantErr: "inputAttestations[0].uri"},
		{name: "input without digest", mutate: func(p *Predicate) { p.InputAttestations[0].Digest = nil }, wantErr: "inputAttestations[0].digest"},
		{name: "invalid result", mutate: func(p *Predicate) { p.VerificationResult = "OK" }, wantErr: "verificationResult"},
		{name: "blank level", mutate: func(p *Predicate) { p.VerifiedLevels = []string{""} }, wantErr: "verifiedLevels[0]"},
		{name: "negative dependency level", mutate: func(p *Predicate) { p.DependencyLevels = map[string]int{"L": -1} }, wantErr: "dependencyLevels"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := sourceVSA()
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

	def := s.Definitions["Predicate"]
	require.NotNil(t, def)
	assert.ElementsMatch(t, []string{
		"verifier", "timeVerified", "resourceUri", "policy", "verificationResult", "verifiedLevels",
	}, def.Required)
	assert.Nil(t, def.AdditionalProperties)
	assert.Equal(t, []any{"PASSED", "FAILED"}, s.Definitions["VerificationResult"].Enum)
}

func statementJSON(t *testing.T, p Predicate) []byte {
	t.Helper()
	stmt, err := NewSourceStatement(devTip(), &p)
	require.NoError(t, err)
	data, err := stmt.ToJSON()
	require.NoError(t, err)
	return data
}

func TestParseStatement_RejectsAbsentRequiredFields(t *testing.T) {
	data := statementJSON(t, sourceVSA())
	paths := sourcetest.RequiredPaths(Schema())
	assert.Subset(t, paths, []string{"verifier", "verifier.id", "timeVerified", "resourceUri", "policy", "verificationResult", "verifiedLevels"})

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			mutated, found := sourcetest.DeletePath(t, data, "predicate."+path)
			require.True(t, found, "fixture must populate %s", path)
			_, _, err := ParseSourceStatement(mutated)
			require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
		})
	}
}

func TestParseStatement_UnknownFields(t *testing.T) {
	data := sourcetest.SetPath(t, statementJSON(t, sourceVSA()), "predicate.futureField", 1)
	_, _, err := ParseSourceStatement(data)
	require.NoError(t, err, "the VSA is defined upstream, so unknown fields are tolerated")
}

func TestParseStatement_RejectsEmptyPredicate(t *testing.T) {
	data := sourcetest.SetPath(t, statementJSON(t, sourceVSA()), "predicate", map[string]any{})
	_, _, err := ParseSourceStatement(data)
	require.ErrorIs(t, err, sourcecommon.ErrInvalidPredicate)
}
