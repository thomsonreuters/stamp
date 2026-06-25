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
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

func createTestEnvelope(t *testing.T) *intoto.Envelope {
	t.Helper()
	return &intoto.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`)),
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  []intoto.Signature{},
	}
}

func createTestLogEntry(uuid string, withVerification bool) *rekor.LogEntry {
	entry := &rekor.LogEntry{
		UUID:           uuid,
		Body:           base64.StdEncoding.EncodeToString([]byte("test-body")),
		IntegratedTime: time.Now().Unix(),
		LogIndex:       12345,
		LogID:          "test-log-id",
	}

	if withVerification {
		entry.Verification = &rekor.Verification{
			InclusionProof: &rekor.InclusionProof{
				LogIndex: 12345,
				RootHash: "abc123",
				TreeSize: 99999,
				Hashes:   []string{"hash1", "hash2"},
			},
		}
	}

	return entry
}

func TestFetchFromFile(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name       string
		setupFile  func(t *testing.T) string
		setupMock  func(m *rekor.MockClient)
		rawOutput  bool
		wantErr    bool
		errContain string
	}{
		{
			name: "success",
			setupFile: func(t *testing.T) string {
				env := createTestEnvelope(t)
				data, _ := json.Marshal(env)
				path := filepath.Join(t.TempDir(), "attestation.json")
				require.NoError(t, os.WriteFile(path, data, 0644))
				return path
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-123"}, nil)
				m.On("GetEntry", mock.Anything, "uuid-123").Return(createTestLogEntry("uuid-123", true), nil)
			},
			rawOutput: false,
			wantErr:   false,
		},
		{
			name: "file not found",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/path/file.json"
			},
			setupMock:  func(m *rekor.MockClient) {},
			wantErr:    true,
			errContain: "failed to read attestation file",
		},
		{
			name: "invalid JSON",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "invalid.json")
				require.NoError(t, os.WriteFile(path, []byte("not json"), 0644))
				return path
			},
			setupMock:  func(m *rekor.MockClient) {},
			wantErr:    true,
			errContain: "failed to parse attestation",
		},
		{
			name: "search returns no results",
			setupFile: func(t *testing.T) string {
				env := createTestEnvelope(t)
				data, _ := json.Marshal(env)
				path := filepath.Join(t.TempDir(), "attestation.json")
				require.NoError(t, os.WriteFile(path, data, 0644))
				return path
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{}, nil)
			},
			wantErr:    true,
			errContain: ErrNoEntryFound.Error(),
		},
		{
			name: "search error",
			setupFile: func(t *testing.T) string {
				env := createTestEnvelope(t)
				data, _ := json.Marshal(env)
				path := filepath.Join(t.TempDir(), "attestation.json")
				require.NoError(t, os.WriteFile(path, data, 0644))
				return path
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return(nil, errors.New("search failed"))
			},
			wantErr:    true,
			errContain: "failed to search entries",
		},
		{
			name: "with raw output",
			setupFile: func(t *testing.T) string {
				env := createTestEnvelope(t)
				data, _ := json.Marshal(env)
				path := filepath.Join(t.TempDir(), "attestation.json")
				require.NoError(t, os.WriteFile(path, data, 0644))
				return path
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-456"}, nil)
				m.On("GetEntry", mock.Anything, "uuid-456").Return(createTestLogEntry("uuid-456", true), nil)
			},
			rawOutput: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := rekor.SetupMockClient(t)
			tt.setupMock(mockClient)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			filePath := tt.setupFile(t)
			result, err := client.FetchFromFile(ctx, filePath, tt.rawOutput)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.NotEmpty(t, result.UUID)

			if tt.rawOutput {
				assert.NotNil(t, result.RawResponse)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestFetchFromUUID(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name       string
		uuid       string
		setupMock  func(m *rekor.MockClient)
		rawOutput  bool
		wantErr    bool
		errContain string
	}{
		{
			name: "success without raw output",
			uuid: "test-uuid-123",
			setupMock: func(m *rekor.MockClient) {
				m.On("GetEntry", mock.Anything, "test-uuid-123").Return(createTestLogEntry("test-uuid-123", true), nil)
			},
			rawOutput: false,
			wantErr:   false,
		},
		{
			name: "success with raw output",
			uuid: "test-uuid-456",
			setupMock: func(m *rekor.MockClient) {
				m.On("GetEntry", mock.Anything, "test-uuid-456").Return(createTestLogEntry("test-uuid-456", true), nil)
			},
			rawOutput: true,
			wantErr:   false,
		},
		{
			name: "entry not found",
			uuid: "nonexistent-uuid",
			setupMock: func(m *rekor.MockClient) {
				m.On("GetEntry", mock.Anything, "nonexistent-uuid").Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			errContain: "failed to get entry",
		},
		{
			name: "entry without verification",
			uuid: "uuid-no-verification",
			setupMock: func(m *rekor.MockClient) {
				m.On("GetEntry", mock.Anything, "uuid-no-verification").Return(createTestLogEntry("uuid-no-verification", false), nil)
			},
			rawOutput: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := rekor.SetupMockClient(t)
			tt.setupMock(mockClient)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			result, err := client.FetchFromUUID(ctx, tt.uuid, tt.rawOutput)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.uuid, result.UUID)

			if tt.rawOutput {
				assert.NotNil(t, result.RawResponse)
			} else {
				assert.Nil(t, result.RawResponse)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestFetchFromLogIndex(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name         string
		logIndexStr  string
		setupMock    func(m *rekor.MockClient)
		rawOutput    bool
		wantErr      bool
		errContain   string
		wantLogIndex int64
	}{
		{
			name:        "success",
			logIndexStr: "12345",
			setupMock: func(m *rekor.MockClient) {
				entry := createTestLogEntry("uuid-from-index", true)
				entry.LogIndex = 12345
				m.On("GetEntryByLogIndex", mock.Anything, int64(12345)).Return(entry, nil)
			},
			rawOutput:    false,
			wantErr:      false,
			wantLogIndex: 12345,
		},
		{
			name:        "invalid log index format",
			logIndexStr: "not-a-number",
			setupMock:   func(m *rekor.MockClient) {},
			wantErr:     true,
			errContain:  "invalid log index format",
		},
		{
			name:        "entry not found",
			logIndexStr: "99999",
			setupMock: func(m *rekor.MockClient) {
				m.On("GetEntryByLogIndex", mock.Anything, int64(99999)).Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			errContain: "failed to get entry",
		},
		{
			name:        "with raw output",
			logIndexStr: "54321",
			setupMock: func(m *rekor.MockClient) {
				entry := createTestLogEntry("uuid-raw", true)
				entry.LogIndex = 54321
				m.On("GetEntryByLogIndex", mock.Anything, int64(54321)).Return(entry, nil)
			},
			rawOutput:    true,
			wantErr:      false,
			wantLogIndex: 54321,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := rekor.SetupMockClient(t)
			tt.setupMock(mockClient)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			result, err := client.FetchFromLogIndex(ctx, tt.logIndexStr, tt.rawOutput)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.NotEmpty(t, result.UUID)
			assert.NotNil(t, result.LogIndex)
			assert.Equal(t, tt.wantLogIndex, *result.LogIndex)

			mockClient.AssertExpectations(t)
		})
	}
}

func TestToFetchResult(t *testing.T) {
	tests := []struct {
		name               string
		uuid               string
		entry              *rekor.LogEntry
		includeRaw         bool
		wantTimestamp      bool
		wantEntryBody      bool
		wantInclusionProof bool
		wantRawResponse    bool
	}{
		{
			name: "full entry with verification",
			uuid: "test-uuid",
			entry: &rekor.LogEntry{
				UUID:           "test-uuid",
				Body:           "encoded-body",
				IntegratedTime: 1704067200, // 2024-01-01 00:00:00 UTC
				LogIndex:       100,
				LogID:          "log-id",
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						LogIndex: 100,
						RootHash: "root-hash",
						TreeSize: 1000,
						Hashes:   []string{"h1", "h2"},
					},
				},
			},
			includeRaw:         false,
			wantTimestamp:      true,
			wantEntryBody:      true,
			wantInclusionProof: true,
			wantRawResponse:    false,
		},
		{
			name: "entry without verification",
			uuid: "uuid-no-verify",
			entry: &rekor.LogEntry{
				UUID:           "uuid-no-verify",
				Body:           "body",
				IntegratedTime: 1704067200,
				LogIndex:       200,
			},
			includeRaw:         false,
			wantTimestamp:      true,
			wantEntryBody:      true,
			wantInclusionProof: false,
			wantRawResponse:    false,
		},
		{
			name: "entry with raw output",
			uuid: "uuid-raw",
			entry: &rekor.LogEntry{
				UUID:           "uuid-raw",
				Body:           "body",
				IntegratedTime: 1704067200,
				LogIndex:       300,
			},
			includeRaw:      true,
			wantTimestamp:   true,
			wantEntryBody:   true,
			wantRawResponse: true,
		},
		{
			name: "entry without timestamp",
			uuid: "uuid-no-ts",
			entry: &rekor.LogEntry{
				UUID:           "uuid-no-ts",
				Body:           "body",
				IntegratedTime: 0,
				LogIndex:       400,
			},
			includeRaw:    false,
			wantTimestamp: false,
			wantEntryBody: true,
		},
		{
			name: "entry without body",
			uuid: "uuid-no-body",
			entry: &rekor.LogEntry{
				UUID:           "uuid-no-body",
				Body:           "",
				IntegratedTime: 1704067200,
				LogIndex:       500,
			},
			includeRaw:    false,
			wantTimestamp: true,
			wantEntryBody: false,
		},
		{
			name: "entry with nil inclusion proof",
			uuid: "uuid-nil-proof",
			entry: &rekor.LogEntry{
				UUID:     "uuid-nil-proof",
				LogIndex: 600,
				Verification: &rekor.Verification{
					InclusionProof: nil,
				},
			},
			wantInclusionProof: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toFetchResult(tt.uuid, tt.entry, tt.includeRaw)

			assert.Equal(t, tt.uuid, result.UUID)
			assert.NotNil(t, result.LogIndex)
			assert.Equal(t, tt.entry.LogIndex, *result.LogIndex)

			if tt.wantTimestamp {
				assert.NotNil(t, result.Timestamp)
			} else {
				assert.Nil(t, result.Timestamp)
			}

			if tt.wantEntryBody {
				assert.NotNil(t, result.EntryBody)
			} else {
				assert.Nil(t, result.EntryBody)
			}

			if tt.wantInclusionProof {
				assert.NotNil(t, result.InclusionProof)
				assert.NotNil(t, result.TreeSize)
				assert.True(t, result.InclusionProofVerified)
			} else {
				assert.Nil(t, result.InclusionProof)
			}

			if tt.wantRawResponse {
				assert.NotNil(t, result.RawResponse)
				_, hasUUID := result.RawResponse[tt.uuid]
				assert.True(t, hasUUID)
			} else {
				assert.Nil(t, result.RawResponse)
			}
		})
	}
}
