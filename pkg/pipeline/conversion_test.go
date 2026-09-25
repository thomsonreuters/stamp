// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

func createTestStatementJSON(t *testing.T, predicateType string, subjectName string) []byte {
	t.Helper()

	subjects := []intoto.Subject{
		{
			Name: subjectName,
			Digest: map[string]string{
				"sha256": "abc123",
			},
		},
	}

	predicate := map[string]any{
		"test": "data",
	}

	statement, err := intoto.NewStatement(predicateType, predicate, subjects)
	require.NoError(t, err)

	data, err := statement.ToJSON()
	require.NoError(t, err)

	return data
}

func TestCreateStructuredCollectionStatement_EmptyStatements(t *testing.T) {
	collection, err := CreateStructuredCollectionStatement("test-collection", nil)

	assert.Nil(t, collection)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot create collection")
	assert.Contains(t, err.Error(), "test-collection")
}

func TestCreateStructuredCollectionStatement_SingleStatement(t *testing.T) {
	payload := createTestStatementJSON(t, "https://example.com/predicate/v1", "file1.txt")

	stmt, err := CreateStructuredCollectionStatement("single-collection", [][]byte{payload})

	require.NoError(t, err)
	require.NotNil(t, stmt)

	assert.Contains(t, stmt.PredicateType, "collection")
	assert.Len(t, stmt.Subject, 1)
	assert.Equal(t, "file1.txt", stmt.Subject[0].Name)
}

func TestCreateStructuredCollectionStatement_MultipleStatements(t *testing.T) {
	p1 := createTestStatementJSON(t, "https://example.com/predicate/v1", "file1.txt")
	p2 := createTestStatementJSON(t, "https://example.com/predicate/v2", "file2.txt")

	stmt, err := CreateStructuredCollectionStatement("multi-collection", [][]byte{p1, p2})

	require.NoError(t, err)
	require.NotNil(t, stmt)

	assert.Contains(t, stmt.PredicateType, "collection")
	assert.Len(t, stmt.Subject, 2)
}

func TestCreateStructuredCollectionStatement_DuplicateSubjects(t *testing.T) {
	p1 := createTestStatementJSON(t, "https://example.com/predicate/v1", "same-file.txt")
	p2 := createTestStatementJSON(t, "https://example.com/predicate/v2", "same-file.txt")

	stmt, err := CreateStructuredCollectionStatement("dedup-collection", [][]byte{p1, p2})

	require.NoError(t, err)
	require.NotNil(t, stmt)

	assert.Len(t, stmt.Subject, 1)
	assert.Equal(t, "same-file.txt", stmt.Subject[0].Name)
}
