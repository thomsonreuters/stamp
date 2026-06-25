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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/types"
	"github.com/transparency-dev/merkle/rfc6962"
)

func createValidInclusionProof() *rekor.InclusionProof {
	body := "test-body"
	bodyBytes := []byte(body)
	leafHash := rfc6962.DefaultHasher.HashLeaf(bodyBytes)

	return &rekor.InclusionProof{
		LogIndex: 0,
		RootHash: hex.EncodeToString(leafHash),
		TreeSize: 1,
		Hashes:   []string{},
	}
}

// mustCreateTestCertificate creates a test certificate, panics on error (use only in tests).
func mustCreateTestCertificate(notBefore, notAfter time.Time) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	return certDER
}

func createEnvelopeWithExpiredCert() *intoto.Envelope {
	certDER := mustCreateTestCertificate(
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	)
	return &intoto.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
		PayloadType: "application/vnd.in-toto+json",
		Signatures: []intoto.Signature{
			{Certificate: base64.StdEncoding.EncodeToString(certDER)},
		},
	}
}

func createEnvelopeWithValidCert() *intoto.Envelope {
	certDER := mustCreateTestCertificate(
		time.Now().Add(-24*time.Hour),
		time.Now().Add(24*time.Hour),
	)
	return &intoto.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
		PayloadType: "application/vnd.in-toto+json",
		Signatures: []intoto.Signature{
			{Certificate: base64.StdEncoding.EncodeToString(certDER)},
		},
	}
}

func createEnvelopeWithFutureCert() *intoto.Envelope {
	certDER := mustCreateTestCertificate(
		time.Now().Add(24*time.Hour),
		time.Now().Add(48*time.Hour),
	)
	return &intoto.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
		PayloadType: "application/vnd.in-toto+json",
		Signatures: []intoto.Signature{
			{Certificate: base64.StdEncoding.EncodeToString(certDER)},
		},
	}
}

func createBasicEnvelope() *intoto.Envelope {
	return &intoto.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  []intoto.Signature{},
	}
}

func TestVerifyInclusionWithPolicyDetails(t *testing.T) {
	tests := []struct {
		name           string
		envelope       *intoto.Envelope
		temporalPolicy types.TemporalPolicy
		setupMock      func(m *rekor.MockClient)
		wantVerified   bool
		wantWarnings   bool
		wantUUID       string
		wantErr        bool
		errContain     string
	}{
		{
			name:           "success - attestation found and verified",
			envelope:       createBasicEnvelope(),
			temporalPolicy: types.TemporalPolicyIgnore,
			setupMock: func(m *rekor.MockClient) {
				proof := createValidInclusionProof()
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"found-uuid"}, nil)
				m.On("GetEntry", mock.Anything, "found-uuid").Return(&rekor.LogEntry{
					UUID:           "found-uuid",
					Body:           base64.StdEncoding.EncodeToString([]byte("test-body")),
					IntegratedTime: time.Now().Unix(),
					LogIndex:       0,
					Verification: &rekor.Verification{
						InclusionProof: proof,
					},
				}, nil)
				m.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
					TreeSize: 1,
					RootHash: proof.RootHash,
				}, nil)
			},
			wantVerified: true,
			wantUUID:     "found-uuid",
			wantErr:      false,
		},
		{
			name:           "error - search fails",
			envelope:       createBasicEnvelope(),
			temporalPolicy: types.TemporalPolicyIgnore,
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return(nil, errors.New("search error"))
			},
			wantErr:    true,
			errContain: "search failed",
		},
		{
			name:           "error - attestation not found",
			envelope:       createBasicEnvelope(),
			temporalPolicy: types.TemporalPolicyIgnore,
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{}, nil)
			},
			wantErr:    true,
			errContain: "attestation not found",
		},
		{
			name:           "error - duplicate entries found",
			envelope:       createBasicEnvelope(),
			temporalPolicy: types.TemporalPolicyIgnore,
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-1", "uuid-2"}, nil)
			},
			wantErr:    true,
			errContain: "duplicate entries",
		},
		{
			name:           "error - get entry fails",
			envelope:       createBasicEnvelope(),
			temporalPolicy: types.TemporalPolicyIgnore,
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-1"}, nil)
				m.On("GetEntry", mock.Anything, "uuid-1").Return(nil, errors.New("entry error"))
			},
			wantErr:    true,
			errContain: "failed to get entry",
		},
		{
			name:           "error - no verification data",
			envelope:       createBasicEnvelope(),
			temporalPolicy: types.TemporalPolicyIgnore,
			setupMock: func(m *rekor.MockClient) {
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-1"}, nil)
				m.On("GetEntry", mock.Anything, "uuid-1").Return(&rekor.LogEntry{
					UUID:         "uuid-1",
					Body:         base64.StdEncoding.EncodeToString([]byte("body")),
					Verification: nil,
				}, nil)
			},
			wantErr:    true,
			errContain: "inclusion proof failed",
		},
		{
			name:           "temporal policy warn - adds warning",
			envelope:       createEnvelopeWithExpiredCert(),
			temporalPolicy: types.TemporalPolicyWarn,
			setupMock: func(m *rekor.MockClient) {
				proof := createValidInclusionProof()
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-warn"}, nil)
				m.On("GetEntry", mock.Anything, "uuid-warn").Return(&rekor.LogEntry{
					UUID:           "uuid-warn",
					Body:           base64.StdEncoding.EncodeToString([]byte("test-body")),
					IntegratedTime: time.Now().Unix(),
					LogIndex:       0,
					Verification: &rekor.Verification{
						InclusionProof: proof,
					},
				}, nil)
				m.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
					TreeSize: 1,
					RootHash: proof.RootHash,
				}, nil)
			},
			wantVerified: true,
			wantWarnings: true,
			wantUUID:     "uuid-warn",
			wantErr:      false,
		},
		{
			name:           "temporal policy strict - returns error",
			envelope:       createEnvelopeWithExpiredCert(),
			temporalPolicy: types.TemporalPolicyStrict,
			setupMock: func(m *rekor.MockClient) {
				proof := createValidInclusionProof()
				m.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-strict"}, nil)
				m.On("GetEntry", mock.Anything, "uuid-strict").Return(&rekor.LogEntry{
					UUID:           "uuid-strict",
					Body:           base64.StdEncoding.EncodeToString([]byte("test-body")),
					IntegratedTime: time.Now().Unix(),
					LogIndex:       0,
					Verification: &rekor.Verification{
						InclusionProof: proof,
					},
				}, nil)
				m.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
					TreeSize: 1,
					RootHash: proof.RootHash,
				}, nil)
			},
			wantUUID:   "uuid-strict",
			wantErr:    true,
			errContain: "temporal validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			mockClient := rekor.SetupMockClient(t)
			tt.setupMock(mockClient)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			verified, warnings, uuid, err := client.VerifyInclusionWithPolicyDetails(ctx, tt.envelope, tt.temporalPolicy)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				if tt.wantUUID != "" {
					assert.Equal(t, tt.wantUUID, uuid)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantVerified, verified)
			assert.Equal(t, tt.wantUUID, uuid)

			if tt.wantWarnings {
				assert.NotEmpty(t, warnings)
			} else {
				assert.Empty(t, warnings)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestVerifyInclusionProof(t *testing.T) {
	tests := []struct {
		name       string
		entry      *rekor.LogEntry
		setupMock  func(m *rekor.MockClient)
		wantErr    bool
		errContain string
	}{
		{
			name: "error - no verification data",
			entry: &rekor.LogEntry{
				UUID:         "uuid-1",
				Verification: nil,
			},
			setupMock:  func(m *rekor.MockClient) {},
			wantErr:    true,
			errContain: "no verification data",
		},
		{
			name: "error - no inclusion proof",
			entry: &rekor.LogEntry{
				UUID: "uuid-2",
				Verification: &rekor.Verification{
					InclusionProof: nil,
				},
			},
			setupMock:  func(m *rekor.MockClient) {},
			wantErr:    true,
			errContain: "no inclusion proof",
		},
		{
			name: "error - missing tree size",
			entry: &rekor.LogEntry{
				UUID: "uuid-3",
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						TreeSize: 0,
						RootHash: "abc",
					},
				},
			},
			setupMock:  func(m *rekor.MockClient) {},
			wantErr:    true,
			errContain: "missing proof fields",
		},
		{
			name: "error - missing root hash",
			entry: &rekor.LogEntry{
				UUID: "uuid-4",
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						TreeSize: 100,
						RootHash: "",
					},
				},
			},
			setupMock:  func(m *rekor.MockClient) {},
			wantErr:    true,
			errContain: "missing proof fields",
		},
		{
			name: "error - GetLogInfo fails",
			entry: &rekor.LogEntry{
				UUID: "uuid-5",
				Body: base64.StdEncoding.EncodeToString([]byte("body")),
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						TreeSize: 100,
						RootHash: "abc123",
					},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("GetLogInfo", mock.Anything).Return(nil, errors.New("log info error"))
			},
			wantErr:    true,
			errContain: "log info error",
		},
		{
			name: "error - proof tree size exceeds current",
			entry: &rekor.LogEntry{
				UUID: "uuid-6",
				Body: base64.StdEncoding.EncodeToString([]byte("body")),
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						TreeSize: 1000,
						RootHash: "abc123",
					},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
					TreeSize: 500,
				}, nil)
			},
			wantErr:    true,
			errContain: "proof tree size exceeds",
		},
		{
			name: "error - no body in entry",
			entry: &rekor.LogEntry{
				UUID: "uuid-7",
				Body: "",
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						TreeSize: 100,
						RootHash: "abc123",
					},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
					TreeSize: 200,
				}, nil)
			},
			wantErr:    true,
			errContain: "no body in entry",
		},
		{
			name: "error - invalid base64 body",
			entry: &rekor.LogEntry{
				UUID: "uuid-8",
				Body: "not-valid-base64!!!",
				Verification: &rekor.Verification{
					InclusionProof: &rekor.InclusionProof{
						TreeSize: 100,
						RootHash: "abc123",
					},
				},
			},
			setupMock: func(m *rekor.MockClient) {
				m.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
					TreeSize: 200,
				}, nil)
			},
			wantErr:    true,
			errContain: "failed to decode body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			mockClient := rekor.SetupMockClient(t)
			tt.setupMock(mockClient)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			err = client.verifyInclusionProof(ctx, tt.entry)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
			mockClient.AssertExpectations(t)
		})
	}
}

func TestVerifyMerkleProof(t *testing.T) {
	tests := []struct {
		name       string
		leafHex    string
		logIndex   int64
		treeSize   int64
		rootHex    string
		proofHex   []string
		wantErr    bool
		errContain string
	}{
		{
			name:       "error - invalid leaf hash",
			leafHex:    "not-hex",
			logIndex:   0,
			treeSize:   1,
			rootHex:    "abc123",
			proofHex:   []string{},
			wantErr:    true,
			errContain: "invalid leaf hash",
		},
		{
			name:       "error - invalid root hash",
			leafHex:    "abc123",
			logIndex:   0,
			treeSize:   1,
			rootHex:    "not-hex!!!",
			proofHex:   []string{},
			wantErr:    true,
			errContain: "invalid root hash",
		},
		{
			name:       "error - invalid proof hash",
			leafHex:    "abc123",
			logIndex:   0,
			treeSize:   2,
			rootHex:    "def456",
			proofHex:   []string{"not-hex!!!"},
			wantErr:    true,
			errContain: "invalid proof hash",
		},
		{
			name: "success - single leaf tree (trivial case)",
			leafHex: func() string {
				leaf := rfc6962.DefaultHasher.HashLeaf([]byte("data"))
				return hex.EncodeToString(leaf)
			}(),
			logIndex: 0,
			treeSize: 1,
			rootHex: func() string {
				leaf := rfc6962.DefaultHasher.HashLeaf([]byte("data"))
				return hex.EncodeToString(leaf)
			}(),
			proofHex: []string{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyMerkleProof(tt.leafHex, tt.logIndex, tt.treeSize, tt.rootHex, tt.proofHex)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestValidateTimestamp(t *testing.T) {
	tests := []struct {
		name       string
		entry      *rekor.LogEntry
		envelope   *intoto.Envelope
		wantErr    bool
		errContain string
	}{
		{
			name: "success - no certificate (key-based signing)",
			entry: &rekor.LogEntry{
				IntegratedTime: time.Now().Unix(),
			},
			envelope: &intoto.Envelope{
				Signatures: []intoto.Signature{
					{KeyID: "key-1", Signature: "sig", Certificate: ""},
				},
			},
			wantErr: false,
		},
		{
			name: "success - timestamp within cert validity",
			entry: &rekor.LogEntry{
				IntegratedTime: time.Now().Unix(),
			},
			envelope: createEnvelopeWithValidCert(),
			wantErr:  false,
		},
		{
			name: "error - no timestamp in entry",
			entry: &rekor.LogEntry{
				IntegratedTime: 0,
			},
			envelope:   createEnvelopeWithValidCert(),
			wantErr:    true,
			errContain: "no timestamp in entry",
		},
		{
			name: "error - entry added after cert expired",
			entry: &rekor.LogEntry{
				IntegratedTime: time.Now().Unix(),
			},
			envelope:   createEnvelopeWithExpiredCert(),
			wantErr:    true,
			errContain: "entry added after certificate expired",
		},
		{
			name: "error - entry added before cert valid",
			entry: &rekor.LogEntry{
				IntegratedTime: time.Now().Unix(),
			},
			envelope:   createEnvelopeWithFutureCert(),
			wantErr:    true,
			errContain: "entry added before certificate valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := rekor.SetupMockClient(t)

			client, err := NewClient("https://rekor.example.com", false, nil)
			require.NoError(t, err)

			err = client.validateTimestamp(tt.entry, tt.envelope)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}

			require.NoError(t, err)
			mockClient.AssertExpectations(t)
		})
	}
}

func TestVerifyMerkleProof_SuccessWithProof(t *testing.T) {
	// Build a two-leaf tree and verify inclusion
	// Leaf 0: hash of "data0", Leaf 1: hash of "data1"
	leaf0 := rfc6962.DefaultHasher.HashLeaf([]byte("data0"))
	leaf1 := rfc6962.DefaultHasher.HashLeaf([]byte("data1"))

	// For a two-leaf tree, root = hash(leaf0 || leaf1)
	root := rfc6962.DefaultHasher.HashChildren(leaf0, leaf1)

	// To prove leaf0 is at index 0 in tree of size 2, we need leaf1 as proof
	err := verifyMerkleProof(
		hex.EncodeToString(leaf0),
		0, // logIndex
		2, // treeSize
		hex.EncodeToString(root),
		[]string{hex.EncodeToString(leaf1)},
	)
	require.NoError(t, err)
}

func TestVerifyInclusionWithPolicyDetails_TemporalPolicyIgnore(t *testing.T) {
	ctx := t.Context()
	mockClient := rekor.SetupMockClient(t)

	proof := createValidInclusionProof()
	mockClient.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{"uuid-ignore"}, nil)
	mockClient.On("GetEntry", mock.Anything, "uuid-ignore").Return(&rekor.LogEntry{
		UUID:           "uuid-ignore",
		Body:           base64.StdEncoding.EncodeToString([]byte("test-body")),
		IntegratedTime: time.Now().Unix(),
		LogIndex:       0,
		Verification: &rekor.Verification{
			InclusionProof: proof,
		},
	}, nil)
	mockClient.On("GetLogInfo", mock.Anything).Return(&rekor.LogInfo{
		TreeSize: 1,
		RootHash: proof.RootHash,
	}, nil)

	client, err := NewClient("https://rekor.example.com", false, nil)
	require.NoError(t, err)

	// Use expired cert but with ignore policy - should still succeed without warnings
	envelope := createEnvelopeWithExpiredCert()
	verified, warnings, uuid, err := client.VerifyInclusionWithPolicyDetails(ctx, envelope, types.TemporalPolicyIgnore)

	require.NoError(t, err)
	assert.True(t, verified)
	assert.Equal(t, "uuid-ignore", uuid)
	assert.Empty(t, warnings) // No warnings when policy is ignore
}
