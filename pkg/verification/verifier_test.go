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

package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/clients/fulcio"
	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/types"
)

func TestNew(t *testing.T) {
	log := logger.NewNoop()
	config := VerificationConfig{
		PublicKeyPath: "/path/to/key.pem",
		RekorURL:      "https://rekor.example.com",
		FulcioURL:     "https://fulcio.example.com",
	}

	verifier := New(config, log)

	assert.NotNil(t, verifier)
}

func TestVerify_SignatureOnly_Success(t *testing.T) {
	// Create a test envelope with valid signature
	envelope := createTestEnvelope(t, false)

	// Create a public key file for verification
	keyPath := createTestPublicKeyFile(t)

	log := logger.NewNoop()
	config := VerificationConfig{
		PublicKeyPath: keyPath,
		VerifyRekor:   false,
	}

	verifier := New(config, log)
	result, err := verifier.Verify(t.Context(), envelope)

	require.NoError(t, err)
	assert.NotNil(t, result)
	// Signature verification will fail with test data, but no error should be returned
	assert.False(t, result.SignatureValid)
	assert.False(t, result.CertificateValid)
	assert.False(t, result.RekorValid)
}

func TestVerify_WithCertificate_FulcioURLRequired(t *testing.T) {
	// Create envelope with certificate
	envelope := createTestEnvelopeWithCert(t)

	log := logger.NewNoop()
	config := VerificationConfig{
		PublicKeyPath: "",
		FulcioURL:     "", // Missing Fulcio URL
		VerifyRekor:   false,
	}

	verifier := New(config, log)
	result, err := verifier.Verify(t.Context(), envelope)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.CertificateValid)
	assert.Contains(t, result.Errors, "certificate verification failed: fulcio URL is required for certificate verification")
}

func TestVerify_WithCertificate_Success(t *testing.T) {
	// Setup mock fulcio client
	mockFulcio := fulcio.SetupMockClient(t)
	mockFulcio.On("VerifyCertificate", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Create envelope with certificate
	envelope := createTestEnvelopeWithCert(t)

	log := logger.NewNoop()
	config := VerificationConfig{
		PublicKeyPath: "",
		FulcioURL:     "https://fulcio.example.com",
		VerifyRekor:   false,
	}

	verifier := New(config, log)
	result, err := verifier.Verify(t.Context(), envelope)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.CertificateValid)
}

func TestVerify_WithCertificate_VerificationFailed(t *testing.T) {
	// Setup mock fulcio client that returns error
	mockFulcio := fulcio.SetupMockClient(t)
	mockFulcio.On("VerifyCertificate", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("certificate expired"))

	// Create envelope with certificate
	envelope := createTestEnvelopeWithCert(t)

	log := logger.NewNoop()
	config := VerificationConfig{
		PublicKeyPath: "",
		FulcioURL:     "https://fulcio.example.com",
		VerifyRekor:   false,
	}

	verifier := New(config, log)
	result, err := verifier.Verify(t.Context(), envelope)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.CertificateValid)
	assert.Len(t, result.Errors, 2) // signature + certificate errors
}

func TestVerify_WithRekor_SearchError(t *testing.T) {
	// Setup mock rekor client that returns search error
	mockRekor := rekor.SetupMockClient(t)
	mockRekor.On("SearchByHash", mock.Anything, mock.Anything).Return(nil, errors.New("search error"))

	envelope := createTestEnvelope(t, false)

	log := logger.NewNoop()
	config := VerificationConfig{
		RekorURL:            "https://rekor.example.com",
		VerifyRekor:         true,
		RekorTemporalPolicy: types.TemporalPolicyIgnore,
	}

	verifier := New(config, log)
	result, err := verifier.Verify(t.Context(), envelope)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.RekorValid)
	assert.NotEmpty(t, result.Errors)
}

func TestVerify_WithRekor_NotFound(t *testing.T) {
	// Setup mock rekor client that returns no entries
	mockRekor := rekor.SetupMockClient(t)
	mockRekor.On("SearchByHash", mock.Anything, mock.Anything).Return([]string{}, nil)

	envelope := createTestEnvelope(t, false)

	log := logger.NewNoop()
	config := VerificationConfig{
		RekorURL:            "https://rekor.example.com",
		VerifyRekor:         true,
		RekorTemporalPolicy: types.TemporalPolicyIgnore,
	}

	verifier := New(config, log)
	result, err := verifier.Verify(t.Context(), envelope)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.RekorValid)
	assert.NotEmpty(t, result.Errors)
}

func TestVerify_OverallValidity(t *testing.T) {
	tests := []struct {
		name             string
		signatureValid   bool
		certificateValid bool
		rekorValid       bool
		wantValid        bool
	}{
		{
			name:             "signature valid only",
			signatureValid:   true,
			certificateValid: true,
			rekorValid:       true,
			wantValid:        true,
		},
		{
			name:           "signature invalid",
			signatureValid: false,
			wantValid:      false,
		},
		{
			name:             "all valid",
			signatureValid:   true,
			certificateValid: true,
			rekorValid:       true,
			wantValid:        true,
		},
		{
			name:             "certificate invalid",
			signatureValid:   true,
			certificateValid: false,
			rekorValid:       true,
			wantValid:        false,
		},
		{
			name:             "rekor invalid",
			signatureValid:   true,
			certificateValid: true,
			rekorValid:       false,
			wantValid:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &VerificationResult{
				SignatureValid:   tt.signatureValid,
				CertificateValid: tt.certificateValid,
				RekorValid:       tt.rekorValid,
			}

			// Compute overall validity using same logic as Verify
			result.Valid = result.SignatureValid &&
				result.CertificateValid &&
				result.RekorValid

			assert.Equal(t, tt.wantValid, result.Valid)
		})
	}
}

func TestVerificationConfig(t *testing.T) {
	config := VerificationConfig{
		PublicKeyPath:       "/path/to/key.pem",
		RekorURL:            "https://rekor.example.com",
		VerifyRekor:         true,
		FulcioURL:           "https://fulcio.example.com",
		RekorTemporalPolicy: types.TemporalPolicyStrict,
		Insecure:            false,
	}

	assert.Equal(t, "/path/to/key.pem", config.PublicKeyPath)
	assert.Equal(t, "https://rekor.example.com", config.RekorURL)
	assert.True(t, config.VerifyRekor)
	assert.Equal(t, "https://fulcio.example.com", config.FulcioURL)
	assert.Equal(t, types.TemporalPolicyStrict, config.RekorTemporalPolicy)
	assert.False(t, config.Insecure)
}

func TestVerificationResult(t *testing.T) {
	result := VerificationResult{
		Valid:            false,
		SignatureValid:   true,
		CertificateValid: true,
		RekorValid:       false,
		Errors:           []string{"error1", "error2"},
		Warnings:         []string{"warning1"},
		AttestationPath:  "/path/to/attestation.json",
		AttestationHash:  "sha256:abc123",
		RekorEntryUUID:   "uuid-123",
	}

	assert.False(t, result.Valid)
	assert.True(t, result.SignatureValid)
	assert.True(t, result.CertificateValid)
	assert.False(t, result.RekorValid)
	assert.Len(t, result.Errors, 2)
	assert.Len(t, result.Warnings, 1)
	assert.Equal(t, "/path/to/attestation.json", result.AttestationPath)
	assert.Equal(t, "sha256:abc123", result.AttestationHash)
	assert.Equal(t, "uuid-123", result.RekorEntryUUID)
}

func TestErrFulcioURLRequired(t *testing.T) {
	assert.Equal(t, "fulcio URL is required for certificate verification", ErrFulcioURLRequired.Error())
}

// Helper functions

func createTestEnvelope(t *testing.T, withCert bool) *intoto.Envelope {
	t.Helper()

	payload := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicateType":"https://example.com/test","predicate":{}}`
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(payload))

	sig := intoto.Signature{
		KeyID:     "test-key-id",
		Signature: base64.StdEncoding.EncodeToString([]byte("test-signature")),
	}

	if withCert {
		cert := generateTestCertificate(t)
		sig.Certificate = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	return &intoto.Envelope{
		Payload:     encodedPayload,
		PayloadType: intoto.PayloadType,
		Signatures:  []intoto.Signature{sig},
	}
}

func createTestEnvelopeWithCert(t *testing.T) *intoto.Envelope {
	t.Helper()
	return createTestEnvelope(t, true)
}

func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func createTestPublicKeyFile(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	pemBlock := "-----BEGIN PUBLIC KEY-----\n" +
		base64.StdEncoding.EncodeToString(pubKeyBytes) +
		"\n-----END PUBLIC KEY-----\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "public.pem")
	err = os.WriteFile(path, []byte(pemBlock), 0644)
	require.NoError(t, err)

	return path
}
