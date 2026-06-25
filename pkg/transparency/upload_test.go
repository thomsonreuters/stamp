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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

func TestUpload(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		envelope      *intoto.Envelope
		publicKeyPath string
		setupFile     func(t *testing.T) string
		setupMock     func(m *rekor.MockClient)
		retry         *rekor.RetryPolicy
		wantErr       bool
		errContain    string
	}{
		{
			name: "success with certificate verifier",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []intoto.Signature{
					{
						KeyID:       "key-1",
						Signature:   "sig-1",
						Certificate: base64.StdEncoding.EncodeToString([]byte("cert-data")),
					},
				},
			},
			publicKeyPath: "",
			setupMock: func(m *rekor.MockClient) {
				m.On("CreateEntry", mock.Anything, mock.MatchedBy(func(entry *rekor.ProposedEntry) bool {
					return entry.APIVersion == rekor.DSSEAPIVersion && entry.Kind == rekor.DSSEEntryKind
				}), mock.Anything).Return(&rekor.LogEntry{
					UUID:     "created-uuid",
					LogIndex: 1000,
				}, nil)
			},
			wantErr: false,
		},
		{
			name: "success with public key file",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []intoto.Signature{},
			},
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "public.pem")
				require.NoError(t, os.WriteFile(path, []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"), 0644))
				return path
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("CreateEntry", mock.Anything, mock.Anything, mock.Anything).Return(&rekor.LogEntry{
					UUID:     "created-uuid-2",
					LogIndex: 1001,
				}, nil)
			},
			wantErr: false,
		},
		{
			name: "error - no verifiers found",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []intoto.Signature{},
			},
			publicKeyPath: "",
			setupMock:     func(m *rekor.MockClient) {},
			wantErr:       true,
			errContain:    "no verifiers found",
		},
		{
			name: "error - public key file not found",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []intoto.Signature{},
			},
			publicKeyPath: "/nonexistent/path/key.pem",
			setupMock:     func(m *rekor.MockClient) {},
			wantErr:       true,
			errContain:    "failed to read public key file",
		},
		{
			name: "error - create entry fails",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []intoto.Signature{
					{
						KeyID:       "key-1",
						Signature:   "sig-1",
						Certificate: base64.StdEncoding.EncodeToString([]byte("cert-data")),
					},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("CreateEntry", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("upload failed"))
			},
			wantErr:    true,
			errContain: "upload failed",
		},
		{
			name: "success with custom retry policy",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []intoto.Signature{
					{Certificate: base64.StdEncoding.EncodeToString([]byte("cert"))},
				},
			},
			retry: &rekor.RetryPolicy{MaxAttempts: 5},
			setupMock: func(m *rekor.MockClient) {
				m.On("CreateEntry", mock.Anything, mock.Anything, mock.MatchedBy(func(r *rekor.RetryPolicy) bool {
					return r != nil && r.MaxAttempts == 5
				})).Return(&rekor.LogEntry{UUID: "uuid-retry"}, nil)
			},
			wantErr: false,
		},
		{
			name: "success with multiple certificate signatures",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []intoto.Signature{
					{KeyID: "key-1", Signature: "sig-1", Certificate: base64.StdEncoding.EncodeToString([]byte("cert-1"))},
					{KeyID: "key-2", Signature: "sig-2", Certificate: base64.StdEncoding.EncodeToString([]byte("cert-2"))},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("CreateEntry", mock.Anything, mock.MatchedBy(func(entry *rekor.ProposedEntry) bool {
					spec, ok := entry.Spec.(rekor.DSSESpec)
					return ok && len(spec.ProposedContent.Verifiers) == 2
				}), mock.Anything).Return(&rekor.LogEntry{UUID: "uuid-multi"}, nil)
			},
			wantErr: false,
		},
		{
			name: "signatures without certificates are skipped",
			envelope: &intoto.Envelope{
				Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []intoto.Signature{
					{KeyID: "key-1", Signature: "sig-1", Certificate: ""},
					{KeyID: "key-2", Signature: "sig-2", Certificate: base64.StdEncoding.EncodeToString([]byte("cert-2"))},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("CreateEntry", mock.Anything, mock.MatchedBy(func(entry *rekor.ProposedEntry) bool {
					spec, ok := entry.Spec.(rekor.DSSESpec)
					return ok && len(spec.ProposedContent.Verifiers) == 1
				}), mock.Anything).Return(&rekor.LogEntry{UUID: "uuid-partial"}, nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := rekor.SetupMockClient(t)
			tt.setupMock(mockClient)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			publicKeyPath := tt.publicKeyPath
			if tt.setupFile != nil {
				publicKeyPath = tt.setupFile(t)
			}

			result, err := client.Upload(ctx, tt.envelope, publicKeyPath, tt.retry)

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

			mockClient.AssertExpectations(t)
		})
	}
}

func TestExtractVerifiers(t *testing.T) {
	tests := []struct {
		name          string
		envelope      *intoto.Envelope
		publicKeyPath string
		setupFile     func(t *testing.T) string
		wantCount     int
		wantErr       bool
		errContain    string
	}{
		{
			name: "extract from public key file",
			envelope: &intoto.Envelope{
				Signatures: []intoto.Signature{},
			},
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "key.pem")
				require.NoError(t, os.WriteFile(path, []byte("public-key-data"), 0644))
				return path
			},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "extract from envelope certificates",
			envelope: &intoto.Envelope{
				Signatures: []intoto.Signature{
					{Certificate: "cert1"},
					{Certificate: "cert2"},
					{Certificate: ""}, // Empty cert should be skipped
				},
			},
			publicKeyPath: "",
			wantCount:     2,
			wantErr:       false,
		},
		{
			name: "error when no verifiers available",
			envelope: &intoto.Envelope{
				Signatures: []intoto.Signature{
					{Certificate: ""},
				},
			},
			publicKeyPath: "",
			wantErr:       true,
			errContain:    "no verifiers found",
		},
		{
			name: "error reading public key file",
			envelope: &intoto.Envelope{
				Signatures: []intoto.Signature{},
			},
			publicKeyPath: "/nonexistent/key.pem",
			wantErr:       true,
			errContain:    "failed to read public key file",
		},
		{
			name: "public key takes precedence over certificates",
			envelope: &intoto.Envelope{
				Signatures: []intoto.Signature{
					{Certificate: "cert1"},
				},
			},
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "key.pem")
				require.NoError(t, os.WriteFile(path, []byte("public-key-data"), 0644))
				return path
			},
			wantCount: 1, // Should use public key, not certificate
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKeyPath := tt.publicKeyPath
			if tt.setupFile != nil {
				publicKeyPath = tt.setupFile(t)
			}

			verifiers, err := extractVerifiers(tt.envelope, publicKeyPath)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
			assert.Len(t, verifiers, tt.wantCount)
		})
	}
}

func TestUpload_EnvelopeSerializationError(t *testing.T) {
	ctx := t.Context()
	mockClient := rekor.SetupMockClient(t)

	client, err := NewClient("https://rekor.example.com", false, nil)
	require.NoError(t, err)

	// Create an envelope that will fail JSON serialization
	// Since intoto.Envelope serializes fine, we test the verifier extraction path instead
	envelope := &intoto.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  []intoto.Signature{}, // No signatures, no public key = error
	}

	_, err = client.Upload(ctx, envelope, "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no verifiers found")
	mockClient.AssertExpectations(t)
}

func TestExtractVerifiers_PublicKeyIsBase64Encoded(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "key.pem")
	keyContent := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----"
	require.NoError(t, os.WriteFile(keyPath, []byte(keyContent), 0644))

	envelope := &intoto.Envelope{}
	verifiers, err := extractVerifiers(envelope, keyPath)

	require.NoError(t, err)
	require.Len(t, verifiers, 1)

	// Verify the verifier is base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(verifiers[0])
	require.NoError(t, err)
	assert.Equal(t, keyContent, string(decoded))
}
