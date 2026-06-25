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

package transparency

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchResult_JSONSerialization(t *testing.T) {
	logIndex := int64(12345)
	treeSize := int64(67890)
	timestamp := "2024-01-15T10:30:00Z"

	result := &FetchResult{
		UUID:                   "test-uuid-123",
		Timestamp:              &timestamp,
		LogIndex:               &logIndex,
		TreeSize:               &treeSize,
		InclusionProofVerified: true,
		EntryBody:              map[string]any{"encoded": "base64data"},
	}

	// Marshal to JSON
	data, err := json.Marshal(result)
	require.NoError(t, err)

	// Verify JSON keys are camelCase
	var jsonMap map[string]any
	err = json.Unmarshal(data, &jsonMap)
	require.NoError(t, err)

	assert.Equal(t, "test-uuid-123", jsonMap["uuid"])
	assert.Equal(t, "2024-01-15T10:30:00Z", jsonMap["timestamp"])
	assert.InDelta(t, float64(12345), jsonMap["logIndex"], 0.0001)
	assert.InDelta(t, float64(67890), jsonMap["treeSize"], 0.0001)
	assert.Equal(t, true, jsonMap["inclusionProofVerified"])

	// Verify entryBody
	entryBody, ok := jsonMap["entryBody"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "base64data", entryBody["encoded"])
}

func TestFetchResult_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"uuid": "abc-123",
		"timestamp": "2024-06-01T12:00:00Z",
		"logIndex": 999,
		"treeSize": 10000,
		"inclusionProofVerified": true,
		"entryBody": {"encoded": "test"},
		"rawResponse": {"key": "value"}
	}`

	var result FetchResult
	err := json.Unmarshal([]byte(jsonData), &result)
	require.NoError(t, err)

	assert.Equal(t, "abc-123", result.UUID)
	assert.NotNil(t, result.Timestamp)
	assert.Equal(t, "2024-06-01T12:00:00Z", *result.Timestamp)
	assert.NotNil(t, result.LogIndex)
	assert.Equal(t, int64(999), *result.LogIndex)
	assert.NotNil(t, result.TreeSize)
	assert.Equal(t, int64(10000), *result.TreeSize)
	assert.True(t, result.InclusionProofVerified)
	assert.NotNil(t, result.EntryBody)
	assert.NotNil(t, result.RawResponse)
}

func TestFetchResult_OmitEmpty(t *testing.T) {
	// Test that optional fields are omitted when empty/nil
	result := &FetchResult{
		UUID: "minimal-uuid",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var jsonMap map[string]any
	err = json.Unmarshal(data, &jsonMap)
	require.NoError(t, err)

	assert.Equal(t, "minimal-uuid", jsonMap["uuid"])
	assert.NotContains(t, jsonMap, "timestamp")
	assert.NotContains(t, jsonMap, "logIndex")
	assert.NotContains(t, jsonMap, "treeSize")
	assert.NotContains(t, jsonMap, "inclusionProof")
	assert.NotContains(t, jsonMap, "entryBody")
	assert.NotContains(t, jsonMap, "rawResponse")
}
