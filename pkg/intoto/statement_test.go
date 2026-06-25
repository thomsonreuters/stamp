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

package intoto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStatement(t *testing.T) {
	subjects := []Subject{
		{Name: "artifact.tar.gz", Digest: map[string]string{"sha256": "abc123"}},
	}
	predicate := map[string]string{"key": "value"}

	stmt, err := NewStatement("https://example.com/predicate/v1", predicate, subjects)

	require.NoError(t, err)
	assert.Equal(t, StatementType, stmt.Type)
	assert.Equal(t, "https://example.com/predicate/v1", stmt.PredicateType)
	assert.Equal(t, predicate, stmt.Predicate)
	assert.Len(t, stmt.Subject, 1)
	assert.Equal(t, "artifact.tar.gz", stmt.Subject[0].Name)
}

func TestNewStatement_EmptyPredicateType(t *testing.T) {
	subjects := []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}}

	_, err := NewStatement("", map[string]string{}, subjects)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyPredicateType)
}

func TestNewStatement_NilPredicate(t *testing.T) {
	subjects := []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}}

	_, err := NewStatement("https://example.com/predicate", nil, subjects)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilPredicate)
}

func TestNewStatement_NoSubjects(t *testing.T) {
	_, err := NewStatement("https://example.com/predicate", map[string]string{}, []Subject{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSubjects)
}

func TestStatement_ToJSON(t *testing.T) {
	stmt := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "test.txt", Digest: map[string]string{"sha256": "deadbeef"}}},
		PredicateType: "https://example.com/predicate/v1",
		Predicate:     map[string]string{"foo": "bar"},
	}

	data, err := stmt.ToJSON()

	require.NoError(t, err)
	assert.Contains(t, string(data), `"_type":"https://in-toto.io/Statement/v1"`)
	assert.Contains(t, string(data), `"predicateType":"https://example.com/predicate/v1"`)
}

func TestStatement_ToJSONIndent(t *testing.T) {
	stmt := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "test.txt", Digest: map[string]string{"sha256": "deadbeef"}}},
		PredicateType: "https://example.com/predicate/v1",
		Predicate:     map[string]string{"foo": "bar"},
	}

	data, err := stmt.ToJSONIndent()

	require.NoError(t, err)
	assert.Contains(t, string(data), "\n")
	assert.Contains(t, string(data), "  ")
}

func TestStatement_Validate(t *testing.T) {
	tests := []struct {
		name    string
		stmt    *Statement
		wantErr error
	}{
		{
			name: "valid statement",
			stmt: &Statement{
				Type:          StatementType,
				Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
				PredicateType: "https://example.com/predicate",
				Predicate:     map[string]string{},
			},
			wantErr: nil,
		},
		{
			name: "invalid type",
			stmt: &Statement{
				Type:          "wrong-type",
				Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
				PredicateType: "https://example.com/predicate",
				Predicate:     map[string]string{},
			},
			wantErr: ErrInvalidStatementType,
		},
		{
			name: "no subjects",
			stmt: &Statement{
				Type:          StatementType,
				Subject:       []Subject{},
				PredicateType: "https://example.com/predicate",
				Predicate:     map[string]string{},
			},
			wantErr: ErrNoSubjects,
		},
		{
			name: "subject with empty name",
			stmt: &Statement{
				Type:          StatementType,
				Subject:       []Subject{{Name: "", Digest: map[string]string{"sha256": "abc"}}},
				PredicateType: "https://example.com/predicate",
				Predicate:     map[string]string{},
			},
			wantErr: ErrEmptySubjectName,
		},
		{
			name: "subject with no digests",
			stmt: &Statement{
				Type:          StatementType,
				Subject:       []Subject{{Name: "test", Digest: map[string]string{}}},
				PredicateType: "https://example.com/predicate",
				Predicate:     map[string]string{},
			},
			wantErr: ErrNoSubjectDigests,
		},
		{
			name: "empty predicate type",
			stmt: &Statement{
				Type:          StatementType,
				Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
				PredicateType: "",
				Predicate:     map[string]string{},
			},
			wantErr: ErrEmptyPredicateType,
		},
		{
			name: "nil predicate",
			stmt: &Statement{
				Type:          StatementType,
				Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
				PredicateType: "https://example.com/predicate",
				Predicate:     nil,
			},
			wantErr: ErrNilPredicate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.stmt.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr, "expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestStatement_JSONRoundTrip(t *testing.T) {
	original := &Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "file1.txt", Digest: map[string]string{"sha256": "abc123", "sha512": "def456"}},
			{Name: "file2.bin", Digest: map[string]string{"sha256": "789xyz"}},
		},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: map[string]any{
			"builder":   map[string]string{"id": "https://github.com/actions"},
			"buildType": "workflow",
		},
	}

	data, err := original.ToJSON()
	require.NoError(t, err)

	var parsed Statement
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Type, parsed.Type)
	assert.Equal(t, original.PredicateType, parsed.PredicateType)
	assert.Len(t, parsed.Subject, 2)
	assert.Equal(t, "file1.txt", parsed.Subject[0].Name)
}

func TestStatement_Validate_MultipleSubjects_SecondInvalid(t *testing.T) {
	stmt := &Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "valid.txt", Digest: map[string]string{"sha256": "abc"}},
			{Name: "", Digest: map[string]string{"sha256": "def"}}, // Invalid: empty name
		},
		PredicateType: "https://example.com/predicate",
		Predicate:     map[string]string{},
	}

	err := stmt.Validate()

	require.Error(t, err)
	require.ErrorIs(t, err, ErrEmptySubjectName)
	assert.Contains(t, err.Error(), "subject 1")
}

func TestStatement_Validate_MultipleSubjects_AllValid(t *testing.T) {
	stmt := &Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "file1.txt", Digest: map[string]string{"sha256": "abc"}},
			{Name: "file2.txt", Digest: map[string]string{"sha256": "def"}},
			{Name: "file3.txt", Digest: map[string]string{"sha256": "ghi", "sha512": "jkl"}},
		},
		PredicateType: "https://example.com/predicate",
		Predicate:     map[string]string{"key": "value"},
	}

	err := stmt.Validate()

	assert.NoError(t, err)
}

func TestNewStatement_MultipleSubjects(t *testing.T) {
	subjects := []Subject{
		{Name: "artifact1.tar.gz", Digest: map[string]string{"sha256": "abc123"}},
		{Name: "artifact2.tar.gz", Digest: map[string]string{"sha256": "def456"}},
	}
	predicate := map[string]any{"version": "1.0", "build": true}

	stmt, err := NewStatement("https://example.com/predicate/v1", predicate, subjects)

	require.NoError(t, err)
	assert.Len(t, stmt.Subject, 2)
	assert.Equal(t, "artifact1.tar.gz", stmt.Subject[0].Name)
	assert.Equal(t, "artifact2.tar.gz", stmt.Subject[1].Name)
}

func TestStatementType_Constant(t *testing.T) {
	assert.Equal(t, "https://in-toto.io/Statement/v1", StatementType)
}

func TestSubject_MultipleDigests(t *testing.T) {
	subject := Subject{
		Name: "artifact.tar.gz",
		Digest: map[string]string{
			"sha256": "abc123",
			"sha512": "def456789",
			"sha1":   "xyz",
		},
	}

	assert.Equal(t, "artifact.tar.gz", subject.Name)
	assert.Len(t, subject.Digest, 3)
	assert.Equal(t, "abc123", subject.Digest["sha256"])
	assert.Equal(t, "def456789", subject.Digest["sha512"])
}
