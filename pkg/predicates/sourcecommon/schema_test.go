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
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type counted struct {
	Count   int  `json:"count"   jsonschema:"required,minimum=0"`
	Enabled bool `json:"enabled" jsonschema:"required"`
}

func countedSchema(allowAdditional bool) *PredicateSchema {
	return NewPredicateSchema(func() *jsonschema.Schema {
		return ReflectSchema(&counted{}, "c", "c", allowAdditional)
	})
}

func TestPredicateSchema_ValidateJSON(t *testing.T) {
	tests := []struct {
		name            string
		json            string
		allowAdditional bool
		wantErr         bool
	}{
		{name: "zero values present", json: `{"count":0,"enabled":false}`},
		{name: "absent int", json: `{"enabled":false}`, wantErr: true},
		{name: "absent bool", json: `{"count":0}`, wantErr: true},
		{name: "wrong type", json: `{"count":"0","enabled":false}`, wantErr: true},
		{name: "below minimum", json: `{"count":-1,"enabled":false}`, wantErr: true},
		{name: "unknown field, strict", json: `{"count":0,"enabled":false,"cuont":1}`, wantErr: true},
		{name: "unknown field, lenient", json: `{"count":0,"enabled":false,"extra":1}`, allowAdditional: true},
		{name: "malformed", json: `{`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := countedSchema(tc.allowAdditional).ValidateJSON([]byte(tc.json))
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidPredicate)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPredicateSchema_ValidateValue(t *testing.T) {
	require.NoError(t, countedSchema(false).ValidateValue(counted{}))
	require.ErrorIs(t, countedSchema(false).ValidateValue(counted{Count: -1}), ErrInvalidPredicate)
}

func TestPredicateSchema_FailsClosedWithoutSchema(t *testing.T) {
	var nilSchema *PredicateSchema
	require.ErrorIs(t, nilSchema.ValidateJSON([]byte(`{}`)), ErrNilSchema)
	require.ErrorIs(t, NewPredicateSchema(nil).ValidateJSON([]byte(`{}`)), ErrNilSchema)
	require.ErrorIs(t, NewPredicateSchema(func() *jsonschema.Schema { return nil }).ValidateJSON([]byte(`{}`)), ErrNilSchema)

	c := LandedCommit{Repository: "https://github.com/a/b", Digest: commitA}
	_, err := NewStatement(testType, nil, c, bound{Commit: commitA})
	require.ErrorIs(t, err, ErrNilSchema)

	_, err = DecodeStatement([]byte(`{}`), testType, nil, &bound{})
	require.ErrorIs(t, err, ErrNilSchema)
	_, err = DecodeSourceStatement([]byte(`{}`), testType, nil, &bound{})
	assert.ErrorIs(t, err, ErrNilSchema)
}
