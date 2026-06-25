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

func createTestEnvelope(t *testing.T, predicateType string, subjectName string) *intoto.Envelope {
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

	envelope, err := intoto.NewEnvelope(statement)
	require.NoError(t, err)

	return envelope
}

func TestCreateStructuredCollectionEnvelope_EmptyEnvelopes(t *testing.T) {
	collection, err := CreateStructuredCollectionEnvelope("test-collection", []*intoto.Envelope{})

	assert.Nil(t, collection)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot create collection")
	assert.Contains(t, err.Error(), "test-collection")
}

func TestCreateStructuredCollectionEnvelope_NilSlice(t *testing.T) {
	collection, err := CreateStructuredCollectionEnvelope("test-collection", nil)

	assert.Nil(t, collection)
	assert.Error(t, err)
}

func TestCreateStructuredCollectionEnvelope_SingleEnvelope(t *testing.T) {
	env := createTestEnvelope(t, "https://example.com/predicate/v1", "file1.txt")

	collection, err := CreateStructuredCollectionEnvelope("single-collection", []*intoto.Envelope{env})

	require.NoError(t, err)
	require.NotNil(t, collection)

	// Verify the collection envelope structure
	statement, err := collection.GetStatement()
	require.NoError(t, err)

	assert.Contains(t, statement.PredicateType, "collection")
	assert.Len(t, statement.Subject, 1)
	assert.Equal(t, "file1.txt", statement.Subject[0].Name)
}

func TestCreateStructuredCollectionEnvelope_MultipleEnvelopes(t *testing.T) {
	env1 := createTestEnvelope(t, "https://example.com/predicate/v1", "file1.txt")
	env2 := createTestEnvelope(t, "https://example.com/predicate/v2", "file2.txt")

	collection, err := CreateStructuredCollectionEnvelope("multi-collection", []*intoto.Envelope{env1, env2})

	require.NoError(t, err)
	require.NotNil(t, collection)

	statement, err := collection.GetStatement()
	require.NoError(t, err)

	assert.Contains(t, statement.PredicateType, "collection")
	assert.Len(t, statement.Subject, 2)
}

func TestCreateStructuredCollectionEnvelope_DuplicateSubjects(t *testing.T) {
	// Create two envelopes with the same subject
	env1 := createTestEnvelope(t, "https://example.com/predicate/v1", "same-file.txt")
	env2 := createTestEnvelope(t, "https://example.com/predicate/v2", "same-file.txt")

	collection, err := CreateStructuredCollectionEnvelope("dedup-collection", []*intoto.Envelope{env1, env2})

	require.NoError(t, err)
	require.NotNil(t, collection)

	statement, err := collection.GetStatement()
	require.NoError(t, err)

	// Subjects should be deduplicated
	assert.Len(t, statement.Subject, 1)
	assert.Equal(t, "same-file.txt", statement.Subject[0].Name)
}

func TestCreateStructuredCollectionEnvelope_CollectionName(t *testing.T) {
	env := createTestEnvelope(t, "https://example.com/predicate/v1", "file.txt")

	collectionName := "example-workflow-collection"
	collection, err := CreateStructuredCollectionEnvelope(collectionName, []*intoto.Envelope{env})

	require.NoError(t, err)
	require.NotNil(t, collection)

	statement, err := collection.GetStatement()
	require.NoError(t, err)

	// The collection name should be in the predicate
	predicate, ok := statement.Predicate.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, collectionName, predicate["name"])
}

func TestCreateStructuredCollectionEnvelope_PreservesAttestations(t *testing.T) {
	predicateType1 := "https://example.com/git/v1"
	predicateType2 := "https://example.com/sbom/v1"

	env1 := createTestEnvelope(t, predicateType1, "file1.txt")
	env2 := createTestEnvelope(t, predicateType2, "file2.txt")

	collection, err := CreateStructuredCollectionEnvelope("preserving-collection", []*intoto.Envelope{env1, env2})

	require.NoError(t, err)
	require.NotNil(t, collection)

	statement, err := collection.GetStatement()
	require.NoError(t, err)

	predicate, ok := statement.Predicate.(map[string]any)
	require.True(t, ok)

	attestations, ok := predicate["attestations"].([]any)
	require.True(t, ok)
	assert.Len(t, attestations, 2)
}

func TestCreateStructuredCollectionEnvelope_MixedSubjects(t *testing.T) {
	// Create envelopes with different subjects
	env1 := createTestEnvelope(t, "https://example.com/predicate/v1", "unique1.txt")
	env2 := createTestEnvelope(t, "https://example.com/predicate/v2", "unique2.txt")
	env3 := createTestEnvelope(t, "https://example.com/predicate/v3", "unique1.txt") // duplicate subject

	collection, err := CreateStructuredCollectionEnvelope("mixed-collection", []*intoto.Envelope{env1, env2, env3})

	require.NoError(t, err)
	require.NotNil(t, collection)

	statement, err := collection.GetStatement()
	require.NoError(t, err)

	// Should have 2 unique subjects (unique1.txt and unique2.txt)
	assert.Len(t, statement.Subject, 2)

	subjectNames := make(map[string]bool)
	for _, s := range statement.Subject {
		subjectNames[s.Name] = true
	}
	assert.True(t, subjectNames["unique1.txt"])
	assert.True(t, subjectNames["unique2.txt"])
}
