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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

func TestCollectionV1URI(t *testing.T) {
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/collection/v1", CollectionV1URI)
}

func TestCollectionPredicate_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := CollectionPredicate{
		Name:    "build-attestations",
		Created: now,
		Attestations: []CollectionAttestation{
			{
				AttestorID:    "git-attestor",
				PredicateType: "https://github.com/thomsonreuters/stamp/git/v1",
				Predicate: map[string]any{
					"commit": "abc123",
					"branch": "main",
				},
				Subjects: []intoto.Subject{
					{
						Name: "source-code",
						Digest: map[string]string{
							"sha256": "source123",
						},
					},
				},
			},
			{
				AttestorID:    "file-attestor",
				PredicateType: "https://github.com/thomsonreuters/stamp/file/v1",
				Predicate: map[string]any{
					"totalFiles": 100,
				},
				Subjects: []intoto.Subject{
					{
						Name: "artifact.tar.gz",
						Digest: map[string]string{
							"sha256": "artifact123",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "name")
	assert.Contains(t, string(data), "created")
	assert.Contains(t, string(data), "attestations")
	assert.Contains(t, string(data), "git-attestor")
	assert.Contains(t, string(data), "file-attestor")
}

func TestCollectionPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"name": "test-collection",
		"created": "2025-11-12T10:00:00Z",
		"attestations": [
			{
				"attestor_id": "jwt-attestor",
				"predicate_type": "https://github.com/thomsonreuters/stamp/jwt/v1",
				"predicate": {
					"token": "verified"
				},
				"subjects": [
					{
						"name": "token.jwt",
						"digest": {
							"sha256": "token123"
						}
					}
				]
			}
		]
	}`

	var predicate CollectionPredicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "test-collection", predicate.Name)
	assert.Len(t, predicate.Attestations, 1)
	assert.Equal(t, "jwt-attestor", predicate.Attestations[0].AttestorID)
}

func TestCollectionPredicate_Empty(t *testing.T) {
	now := time.Now()

	predicate := CollectionPredicate{
		Name:         "empty-collection",
		Created:      now,
		Attestations: []CollectionAttestation{},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result CollectionPredicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "empty-collection", result.Name)
	assert.Empty(t, result.Attestations)
}

func TestCollectionAttestation_Complete(t *testing.T) {
	attestation := CollectionAttestation{
		AttestorID:    "ec2-attestor",
		PredicateType: "https://github.com/thomsonreuters/stamp/ec2/v1",
		Predicate: map[string]any{
			"instanceId":   "i-123456",
			"instanceType": "t3.medium",
			"region":       "us-east-1",
		},
		Subjects: []intoto.Subject{
			{
				Name: "instance-metadata",
				Digest: map[string]string{
					"sha256": "instance123",
				},
			},
		},
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)

	var result CollectionAttestation
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "ec2-attestor", result.AttestorID)
	assert.Equal(t, "https://github.com/thomsonreuters/stamp/ec2/v1", result.PredicateType)
	assert.NotNil(t, result.Predicate)
	assert.Len(t, result.Subjects, 1)
}

func TestCollectionAttestation_MultipleSubjects(t *testing.T) {
	attestation := CollectionAttestation{
		AttestorID:    "multi-attestor",
		PredicateType: "https://example.com/custom/v1",
		Predicate: map[string]any{
			"status": "success",
		},
		Subjects: []intoto.Subject{
			{
				Name: "artifact1.tar.gz",
				Digest: map[string]string{
					"sha256": "artifact1-sha256",
					"sha512": "artifact1-sha512",
				},
			},
			{
				Name: "artifact2.tar.gz",
				Digest: map[string]string{
					"sha256": "artifact2-sha256",
				},
			},
			{
				Name: "artifact3.tar.gz",
				Digest: map[string]string{
					"sha256": "artifact3-sha256",
				},
			},
		},
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)

	var result CollectionAttestation
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Subjects, 3)
	assert.Equal(t, "artifact1.tar.gz", result.Subjects[0].Name)
	assert.Equal(t, "artifact2.tar.gz", result.Subjects[1].Name)
	assert.Equal(t, "artifact3.tar.gz", result.Subjects[2].Name)
}

func TestCollectionPredicate_MultipleAttestations(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := CollectionPredicate{
		Name:    "complete-build",
		Created: now,
		Attestations: []CollectionAttestation{
			{
				AttestorID:    "git-attestor",
				PredicateType: "https://github.com/thomsonreuters/stamp/git/v1",
				Predicate: map[string]any{
					"commit": "abc123",
				},
				Subjects: []intoto.Subject{
					{
						Name:   "repo",
						Digest: map[string]string{"sha256": "repo123"},
					},
				},
			},
			{
				AttestorID:    "file-attestor",
				PredicateType: "https://github.com/thomsonreuters/stamp/file/v1",
				Predicate: map[string]any{
					"totalFiles": 50,
				},
				Subjects: []intoto.Subject{
					{
						Name:   "source",
						Digest: map[string]string{"sha256": "source123"},
					},
				},
			},
			{
				AttestorID:    "jwt-attestor",
				PredicateType: "https://github.com/thomsonreuters/stamp/jwt/v1",
				Predicate: map[string]any{
					"verified": true,
				},
				Subjects: []intoto.Subject{
					{
						Name:   "token",
						Digest: map[string]string{"sha256": "token123"},
					},
				},
			},
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result CollectionPredicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Attestations, 3)
	assert.Equal(t, "git-attestor", result.Attestations[0].AttestorID)
	assert.Equal(t, "file-attestor", result.Attestations[1].AttestorID)
	assert.Equal(t, "jwt-attestor", result.Attestations[2].AttestorID)
}

func TestCollectionAttestation_PredicateTypes(t *testing.T) {
	tests := []struct {
		name          string
		attestorID    string
		predicateType string
	}{
		{
			name:          "Git Predicate",
			attestorID:    "git-attestor",
			predicateType: "https://github.com/thomsonreuters/stamp/git/v1",
		},
		{
			name:          "File Predicate",
			attestorID:    "file-attestor",
			predicateType: "https://github.com/thomsonreuters/stamp/file/v1",
		},
		{
			name:          "JWT Predicate",
			attestorID:    "jwt-attestor",
			predicateType: "https://github.com/thomsonreuters/stamp/jwt/v1",
		},
		{
			name:          "EC2 Predicate",
			attestorID:    "ec2-attestor",
			predicateType: "https://github.com/thomsonreuters/stamp/ec2/v1",
		},
		{
			name:          "GitHub Workflow Predicate",
			attestorID:    "github-workflow-attestor",
			predicateType: "https://github.com/thomsonreuters/stamp/github-workflow/v1",
		},
		{
			name:          "SLSA Provenance",
			attestorID:    "provenance-attestor",
			predicateType: "https://slsa.dev/provenance/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := CollectionAttestation{
				AttestorID:    tt.attestorID,
				PredicateType: tt.predicateType,
				Predicate: map[string]any{
					"test": "data",
				},
				Subjects: []intoto.Subject{
					{
						Name:   "subject",
						Digest: map[string]string{"sha256": "hash123"},
					},
				},
			}

			data, err := json.Marshal(attestation)
			require.NoError(t, err)

			var result CollectionAttestation
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.attestorID, result.AttestorID)
			assert.Equal(t, tt.predicateType, result.PredicateType)
		})
	}
}

func TestCollectionPredicate_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"name":"test","created":"2025-11-12T10:00:00Z","attestations":[]}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"name":"test","created":"2025-11-12T10:00:00+05:30","attestations":[]}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"name":"test","created":"2025-11-12T10:00:00.123456Z","attestations":[]}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var predicate CollectionPredicate
			err := json.Unmarshal([]byte(tt.jsonTime), &predicate)

			if tt.valid {
				require.NoError(t, err)
				assert.False(t, predicate.Created.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCollectionAttestation_PredicateAsStruct(t *testing.T) {
	type CustomPredicate struct {
		Field1 string `json:"field1"`
		Field2 int    `json:"field2"`
		Field3 bool   `json:"field3"`
	}

	predicate := CustomPredicate{
		Field1: "value1",
		Field2: 42,
		Field3: true,
	}

	attestation := CollectionAttestation{
		AttestorID:    "custom-attestor",
		PredicateType: "https://example.com/custom/v1",
		Predicate:     predicate,
		Subjects: []intoto.Subject{
			{
				Name:   "custom-subject",
				Digest: map[string]string{"sha256": "custom123"},
			},
		},
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)

	var result CollectionAttestation
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "custom-attestor", result.AttestorID)

	// Verify predicate was marshaled correctly
	predicateMap, ok := result.Predicate.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value1", predicateMap["field1"])
	assert.InDelta(t, 42.0, predicateMap["field2"], 0.001)
	assert.Equal(t, true, predicateMap["field3"])
}

func TestCollectionPredicate_LargeCollection(t *testing.T) {
	now := time.Now()

	predicate := CollectionPredicate{
		Name:         "large-collection",
		Created:      now,
		Attestations: make([]CollectionAttestation, 0, 100),
	}

	// Add 100 attestations
	for i := range 100 {
		attestation := CollectionAttestation{
			AttestorID:    "attestor-" + string(rune('0'+i%10)),
			PredicateType: "https://example.com/type/v1",
			Predicate: map[string]any{
				"index": i,
			},
			Subjects: []intoto.Subject{
				{
					Name:   "subject-" + string(rune('0'+i%10)),
					Digest: map[string]string{"sha256": "hash" + string(rune('0'+i%10))},
				},
			},
		}
		predicate.Attestations = append(predicate.Attestations, attestation)
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result CollectionPredicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Attestations, 100)
	assert.Equal(t, "large-collection", result.Name)
}

func TestCollectionAttestation_EmptySubjects(t *testing.T) {
	attestation := CollectionAttestation{
		AttestorID:    "no-subjects-attestor",
		PredicateType: "https://example.com/type/v1",
		Predicate: map[string]any{
			"data": "test",
		},
		Subjects: []intoto.Subject{},
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)

	var result CollectionAttestation
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Empty(t, result.Subjects)
}

func TestCollectionPredicate_NameVariations(t *testing.T) {
	names := []string{
		"simple",
		"build-2024-11-12",
		"production_release_v1.0.0",
		"test-attestation-collection",
		"UPPERCASE_NAME",
		"name-with-many-dashes-and-numbers-123-456",
	}

	now := time.Now()

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			predicate := CollectionPredicate{
				Name:         name,
				Created:      now,
				Attestations: []CollectionAttestation{},
			}

			data, err := json.Marshal(predicate)
			require.NoError(t, err)

			var result CollectionPredicate
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, name, result.Name)
		})
	}
}

func TestCollectionAttestation_SubjectDigestAlgorithms(t *testing.T) {
	attestation := CollectionAttestation{
		AttestorID:    "multi-hash-attestor",
		PredicateType: "https://example.com/type/v1",
		Predicate: map[string]any{
			"test": "data",
		},
		Subjects: []intoto.Subject{
			{
				Name: "multi-hash-artifact",
				Digest: map[string]string{
					"md5":    "md5hash",
					"sha1":   "sha1hash",
					"sha256": "sha256hash",
					"sha512": "sha512hash",
				},
			},
		},
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)

	var result CollectionAttestation
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.Subjects, 1)
	assert.Len(t, result.Subjects[0].Digest, 4)
	assert.Equal(t, "sha256hash", result.Subjects[0].Digest["sha256"])
}
