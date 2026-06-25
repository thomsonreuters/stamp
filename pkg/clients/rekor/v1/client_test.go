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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client, err := New(Options{})
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNew_WithCustomURL(t *testing.T) {
	customURL := "https://custom.rekor.example.com"
	client, err := New(Options{
		URL: customURL,
	})
	require.NoError(t, err)
	assert.NotNil(t, client)

	c, _ := client.(*Client)
	assert.Equal(t, customURL, c.opts.URL)
}

func TestNew_DefaultValues(t *testing.T) {
	client, err := New(Options{})
	require.NoError(t, err)

	c, _ := client.(*Client)
	assert.Equal(t, DefaultRekorURL, c.opts.URL)
	assert.Equal(t, DefaultTimeout, c.opts.Timeout)
}

func TestGetLogInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/log", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		response := LogInfo{
			TreeSize: 1000,
			RootHash: "abc123",
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	logInfo, err := client.GetLogInfo(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1000), logInfo.TreeSize)
	assert.Equal(t, "abc123", logInfo.RootHash)
}

func TestGetLogInfo_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetLogInfo(t.Context())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestGetEntry(t *testing.T) {
	testUUID := "24296fb24b8ad77aa9cc848b65a0bc8b8d03ad57ea14dd3a2c63e03d129e0405e8dbd82b6fae0348"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/log/entries/"+testUUID, r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		response := map[string]LogEntry{
			testUUID: {
				Body:           "test-body",
				IntegratedTime: 1234567890,
				LogIndex:       100,
				LogID:          "test-log-id",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	entry, err := client.GetEntry(t.Context(), testUUID)
	require.NoError(t, err)
	assert.Equal(t, testUUID, entry.UUID)
	assert.Equal(t, "test-body", entry.Body)
	assert.Equal(t, int64(1234567890), entry.IntegratedTime)
	assert.Equal(t, int64(100), entry.LogIndex)
}

func TestGetEntry_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntry(t.Context(), "nonexistent")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestGetEntryByLogIndex(t *testing.T) {
	testUUID := "test-uuid-123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/log/entries/retrieve", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var payload map[string]any
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Contains(t, payload, "logIndexes")

		response := []map[string]LogEntry{
			{
				testUUID: {
					Body:           "test-body",
					IntegratedTime: 1234567890,
					LogIndex:       50,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	entry, err := client.GetEntryByLogIndex(t.Context(), 50)
	require.NoError(t, err)
	assert.Equal(t, testUUID, entry.UUID)
	assert.Equal(t, int64(50), entry.LogIndex)
}

func TestSearchByHash(t *testing.T) {
	testHash := "abc123def456"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/index/retrieve", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var payload map[string]any
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Equal(t, "sha256:"+testHash, payload["hash"])

		response := []string{"uuid1", "uuid2"}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	uuids, err := client.SearchByHash(t.Context(), testHash)
	require.NoError(t, err)
	assert.Len(t, uuids, 2)
	assert.Equal(t, "uuid1", uuids[0])
	assert.Equal(t, "uuid2", uuids[1])
}

func TestSearchByHash_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	uuids, err := client.SearchByHash(t.Context(), "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, uuids)
}

func TestCreateEntry(t *testing.T) {
	testUUID := "new-entry-uuid"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/log/entries", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var entry ProposedEntry
		err := json.NewDecoder(r.Body).Decode(&entry)
		assert.NoError(t, err)
		assert.Equal(t, "0.0.1", entry.APIVersion)
		assert.Equal(t, "dsse", entry.Kind)

		response := map[string]LogEntry{
			testUUID: {
				Body:           "created-body",
				IntegratedTime: time.Now().Unix(),
				LogIndex:       999,
			},
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	proposedEntry := &ProposedEntry{
		APIVersion: "0.0.1",
		Kind:       "dsse",
		Spec: DSSESpec{
			ProposedContent: ProposedContent{
				Envelope:  `{"test": "envelope"}`,
				Verifiers: []string{"verifier1"},
			},
		},
	}

	entry, err := client.CreateEntry(t.Context(), proposedEntry, nil)
	require.NoError(t, err)
	assert.Equal(t, testUUID, entry.UUID)
	assert.Equal(t, int64(999), entry.LogIndex)
}

func TestCreateEntry_Conflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("entry already exists"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEntryAlreadyExists)
}

func TestGetInclusionProof(t *testing.T) {
	testUUID := "test-uuid-proof"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/log/entries/"+testUUID, r.URL.Path)

		response := map[string]LogEntry{
			testUUID: {
				Body:           "test-body",
				IntegratedTime: 1234567890,
				LogIndex:       100,
				Verification: &Verification{
					InclusionProof: &InclusionProof{
						TreeSize: 1000,
						LogIndex: 100,
						RootHash: "roothash123",
						Hashes:   []string{"hash1", "hash2", "hash3"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	proof, err := client.GetInclusionProof(t.Context(), testUUID)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), proof.TreeSize)
	assert.Equal(t, int64(100), proof.LogIndex)
	assert.Equal(t, "roothash123", proof.RootHash)
	assert.Len(t, proof.Hashes, 3)
}

func TestGetInclusionProof_NoVerificationData(t *testing.T) {
	testUUID := "test-uuid-no-verification"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]LogEntry{
			testUUID: {
				Body:           "test-body",
				IntegratedTime: 1234567890,
				LogIndex:       100,
				Verification:   nil,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetInclusionProof(t.Context(), testUUID)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoVerificationData)
}

func TestGetInclusionProof_NoInclusionProof(t *testing.T) {
	testUUID := "test-uuid-no-proof"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]LogEntry{
			testUUID: {
				Body:           "test-body",
				IntegratedTime: 1234567890,
				LogIndex:       100,
				Verification: &Verification{
					SignedEntryTimestamp: "some-timestamp",
					InclusionProof:       nil,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetInclusionProof(t.Context(), testUUID)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoInclusionProof)
}

func TestGetEntryByLogIndex_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := []map[string]LogEntry{}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntryByLogIndex(t.Context(), 999)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEntryNotFound)
}

func TestGetEntry_EntryNotInResponse(t *testing.T) {
	testUUID := "requested-uuid"
	differentUUID := "different-uuid"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]LogEntry{
			differentUUID: {
				Body:           "test-body",
				IntegratedTime: 1234567890,
				LogIndex:       100,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntry(t.Context(), testUUID)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEntryNotFound)
}

func TestMockClient(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetLogInfo", t.Context()).Return(&LogInfo{
		TreeSize: 500,
		RootHash: "mockhash",
	}, nil)

	logInfo, err := mockClient.GetLogInfo(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(500), logInfo.TreeSize)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetEntry(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetEntry", t.Context(), "test-uuid").Return(&LogEntry{
		UUID:     "test-uuid",
		LogIndex: 100,
	}, nil)

	entry, err := mockClient.GetEntry(t.Context(), "test-uuid")
	require.NoError(t, err)
	assert.Equal(t, "test-uuid", entry.UUID)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetEntry_NilReturn(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetEntry", t.Context(), "nonexistent").Return(nil, ErrEntryNotFound)

	entry, err := mockClient.GetEntry(t.Context(), "nonexistent")
	require.Error(t, err)
	assert.Nil(t, entry)
	require.ErrorIs(t, err, ErrEntryNotFound)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetEntryByLogIndex(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetEntryByLogIndex", t.Context(), int64(50)).Return(&LogEntry{
		UUID:     "test-uuid",
		LogIndex: 50,
	}, nil)

	entry, err := mockClient.GetEntryByLogIndex(t.Context(), 50)
	require.NoError(t, err)
	assert.Equal(t, int64(50), entry.LogIndex)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetEntryByLogIndex_NilReturn(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetEntryByLogIndex", t.Context(), int64(999)).Return(nil, ErrEntryNotFound)

	entry, err := mockClient.GetEntryByLogIndex(t.Context(), 999)
	require.Error(t, err)
	assert.Nil(t, entry)

	mockClient.AssertExpectations(t)
}

func TestMockClient_SearchByHash(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("SearchByHash", t.Context(), "testhash").Return([]string{"uuid1", "uuid2"}, nil)

	uuids, err := mockClient.SearchByHash(t.Context(), "testhash")
	require.NoError(t, err)
	assert.Len(t, uuids, 2)

	mockClient.AssertExpectations(t)
}

func TestMockClient_SearchByHash_NilReturn(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("SearchByHash", t.Context(), "unknown").Return(nil, ErrNonSuccessfulResponse)

	uuids, err := mockClient.SearchByHash(t.Context(), "unknown")
	require.Error(t, err)
	assert.Nil(t, uuids)

	mockClient.AssertExpectations(t)
}

func TestMockClient_CreateEntry(t *testing.T) {
	mockClient := &MockClient{}
	entry := &ProposedEntry{Kind: "dsse"}
	retryPolicy := &RetryPolicy{MaxAttempts: 1}

	mockClient.On("CreateEntry", t.Context(), entry, retryPolicy).Return(&LogEntry{
		UUID:     "new-uuid",
		LogIndex: 999,
	}, nil)

	result, err := mockClient.CreateEntry(t.Context(), entry, retryPolicy)
	require.NoError(t, err)
	assert.Equal(t, "new-uuid", result.UUID)

	mockClient.AssertExpectations(t)
}

func TestMockClient_CreateEntry_NilReturn(t *testing.T) {
	mockClient := &MockClient{}
	entry := &ProposedEntry{Kind: "dsse"}

	mockClient.On("CreateEntry", t.Context(), entry, (*RetryPolicy)(nil)).Return(nil, ErrEntryAlreadyExists)

	result, err := mockClient.CreateEntry(t.Context(), entry, nil)
	require.Error(t, err)
	assert.Nil(t, result)
	require.ErrorIs(t, err, ErrEntryAlreadyExists)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetInclusionProof(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetInclusionProof", t.Context(), "test-uuid").Return(&InclusionProof{
		TreeSize: 1000,
		LogIndex: 100,
		RootHash: "roothash",
	}, nil)

	proof, err := mockClient.GetInclusionProof(t.Context(), "test-uuid")
	require.NoError(t, err)
	assert.Equal(t, int64(1000), proof.TreeSize)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetInclusionProof_NilReturn(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetInclusionProof", t.Context(), "no-proof").Return(nil, ErrNoInclusionProof)

	proof, err := mockClient.GetInclusionProof(t.Context(), "no-proof")
	require.Error(t, err)
	assert.Nil(t, proof)

	mockClient.AssertExpectations(t)
}

func TestMockClient_GetLogInfo_NilReturn(t *testing.T) {
	mockClient := &MockClient{}

	mockClient.On("GetLogInfo", t.Context()).Return(nil, ErrNonSuccessfulResponse)

	logInfo, err := mockClient.GetLogInfo(t.Context())
	require.Error(t, err)
	assert.Nil(t, logInfo)

	mockClient.AssertExpectations(t)
}

func TestSetupMockClient(t *testing.T) {
	mockClient := SetupMockClient(t)
	require.NotNil(t, mockClient)

	// Verify that New returns the mock
	client, err := New(Options{})
	require.NoError(t, err)
	assert.Equal(t, mockClient, client)
}

func TestGetLogInfo_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetLogInfo(t.Context())
	assert.Error(t, err)
}

func TestGetEntry_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntry(t.Context(), "test-uuid")
	assert.Error(t, err)
}

func TestGetEntryByLogIndex_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntryByLogIndex(t.Context(), 50)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestGetEntryByLogIndex_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntryByLogIndex(t.Context(), 50)
	assert.Error(t, err)
}

func TestSearchByHash_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.SearchByHash(t.Context(), "testhash")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestSearchByHash_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.SearchByHash(t.Context(), "testhash")
	assert.Error(t, err)
}

func TestCreateEntry_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestCreateEntry_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestCreateEntry_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestCreateEntry_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
}

func TestCreateEntry_InvalidResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	assert.Error(t, err)
}

func TestCreateEntry_EmptyResponseMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEntryNotFound)
}

//nolint:dupl // Retry test scenarios have similar structure but test different retry behaviors
func TestCreateEntry_RetryWithCustomPolicy(t *testing.T) {
	attempts := 0
	testUUID := "retry-test-uuid"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		response := map[string]LogEntry{
			testUUID: {
				Body:     "success",
				LogIndex: 123,
			},
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	customRetry := &RetryPolicy{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	entry, err := client.CreateEntry(t.Context(), &ProposedEntry{}, customRetry)
	require.NoError(t, err)
	assert.Equal(t, testUUID, entry.UUID)
	assert.Equal(t, 2, attempts)
}

func TestCreateEntry_MaxRetriesExceeded(t *testing.T) {
	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	customRetry := &RetryPolicy{
		MaxAttempts:  2,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, customRetry)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNonSuccessfulResponse)
	assert.Equal(t, 2, attempts)
}

func TestCreateEntry_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())

	customRetry := &RetryPolicy{
		MaxAttempts:  10,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	// Cancel context after short delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err = client.CreateEntry(ctx, &ProposedEntry{}, customRetry)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

//nolint:dupl // Retry test scenarios have similar structure but test different retry behaviors
func TestCreateEntry_DelayCapAtMaxDelay(t *testing.T) {
	attempts := 0
	testUUID := "delay-cap-uuid"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 4 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		response := map[string]LogEntry{
			testUUID: {
				Body:     "success",
				LogIndex: 456,
			},
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	// Set MaxDelay smaller than calculated delay after multiplier
	customRetry := &RetryPolicy{
		MaxAttempts:  5,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     15 * time.Millisecond, // Will cap delay
		Multiplier:   10.0,
	}

	entry, err := client.CreateEntry(t.Context(), &ProposedEntry{}, customRetry)
	require.NoError(t, err)
	assert.Equal(t, testUUID, entry.UUID)
	assert.Equal(t, 4, attempts)
}

func TestNew_WithCustomTimeout(t *testing.T) {
	customTimeout := 60 * time.Second
	client, err := New(Options{
		Timeout: customTimeout,
	})
	require.NoError(t, err)

	c, _ := client.(*Client)
	assert.Equal(t, customTimeout, c.opts.Timeout)
}

func TestGetEntryByLogIndex_EmptyMapInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Response with empty map in array
		response := []map[string]LogEntry{{}}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntryByLogIndex(t.Context(), 50)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEntryNotFound)
}

func TestGetLogInfo_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.Close() // Close immediately to cause connection error

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetLogInfo(t.Context())
	assert.Error(t, err)
}

func TestGetEntry_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntry(t.Context(), "test-uuid")
	assert.Error(t, err)
}

func TestGetEntryByLogIndex_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetEntryByLogIndex(t.Context(), 50)
	assert.Error(t, err)
}

func TestSearchByHash_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.SearchByHash(t.Context(), "testhash")
	assert.Error(t, err)
}

func TestCreateEntry_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	retryPolicy := &RetryPolicy{
		MaxAttempts:  1,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		Multiplier:   1.0,
	}

	_, err = client.CreateEntry(t.Context(), &ProposedEntry{}, retryPolicy)
	assert.Error(t, err)
}

func TestGetInclusionProof_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.Close()

	client, err := New(Options{URL: server.URL})
	require.NoError(t, err)

	_, err = client.GetInclusionProof(t.Context(), "test-uuid")
	assert.Error(t, err)
}

func TestNew_Insecure(t *testing.T) {
	client, err := New(Options{
		URL:      "https://custom.rekor.example.com",
		Insecure: true,
	})
	require.NoError(t, err)

	c, _ := client.(*Client)
	assert.True(t, c.opts.Insecure)
}
