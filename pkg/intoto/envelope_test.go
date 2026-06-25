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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	stderrors "errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/signing"
)

// mockSigner implements signing.Signer for testing.
type mockSigner struct {
	keyID       string
	signature   []byte
	signErr     error
	keyIDErr    error
	certificate []byte
	certErr     error
}

func (m *mockSigner) ID() string                                              { return "mock-signer" }
func (m *mockSigner) Validate(_ signing.SignerConfig) error                   { return nil }
func (m *mockSigner) PreSign(_ context.Context, _ signing.SignerConfig) error { return nil }
func (m *mockSigner) PostSign(_ context.Context) error                        { return nil }

func (m *mockSigner) PublicKey() (crypto.PublicKey, error) { return nil, nil } //nolint:nilnil // Test mock: simplified implementation
func (m *mockSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return m.signature, m.signErr
}
func (m *mockSigner) KeyID() (string, error) {
	return m.keyID, m.keyIDErr
}
func (m *mockSigner) Certificate() ([]byte, error) {
	return m.certificate, m.certErr
}

// mockVerifier implements Verifier for testing.
type mockVerifier struct {
	verifyErr error
}

func (m *mockVerifier) Verify(_, _ []byte, _ string) error {
	return m.verifyErr
}

func validStatement(t *testing.T) *Statement {
	t.Helper()
	stmt, err := NewStatement(
		"https://example.com/predicate/v1",
		map[string]string{"key": "value"},
		[]Subject{{Name: "artifact.tar.gz", Digest: map[string]string{"sha256": "abc123"}}},
	)
	require.NoError(t, err)
	return stmt
}

func TestNewEnvelope(t *testing.T) {
	stmt := validStatement(t)

	env, err := NewEnvelope(stmt)

	require.NoError(t, err)
	assert.Equal(t, PayloadType, env.PayloadType)
	assert.NotEmpty(t, env.Payload)
	assert.Empty(t, env.Signatures)
}

func TestNewEnvelope_NilStatement(t *testing.T) {
	_, err := NewEnvelope(nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilStatement)
}

func TestNewEnvelope_InvalidStatement(t *testing.T) {
	stmt := &Statement{
		Type:          "invalid",
		Subject:       []Subject{},
		PredicateType: "",
		Predicate:     nil,
	}

	_, err := NewEnvelope(stmt)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidStatementType)
}

func TestEnvelope_Sign(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	signer := &mockSigner{
		keyID:     "test-key-id",
		signature: []byte("test-signature"),
	}

	err := env.Sign(t.Context(), signer)

	require.NoError(t, err)
	assert.Len(t, env.Signatures, 1)
	assert.Equal(t, "test-key-id", env.Signatures[0].KeyID)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("test-signature")), env.Signatures[0].Signature)
	assert.Empty(t, env.Signatures[0].Certificate)
}

func TestEnvelope_Sign_WithCertificate(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	signer := &mockSigner{
		keyID:       "cert-key-id",
		signature:   []byte("cert-signature"),
		certificate: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
	}

	err := env.Sign(t.Context(), signer)

	require.NoError(t, err)
	assert.Len(t, env.Signatures, 1)
	assert.NotEmpty(t, env.Signatures[0].Certificate)
}

func TestEnvelope_Sign_NilSigner(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)

	err := env.Sign(t.Context(), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilSigner)
}

func TestEnvelope_Sign_SignError(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	signErr := stderrors.New("signing failed")
	signer := &mockSigner{
		signErr: signErr,
	}

	err := env.Sign(t.Context(), signer)

	require.Error(t, err)
	require.ErrorIs(t, err, signErr)
	assert.Contains(t, err.Error(), "failed to sign payload")
}

func TestEnvelope_Sign_KeyIDError(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	keyIDErr := stderrors.New("key ID failed")
	signer := &mockSigner{
		signature: []byte("sig"),
		keyIDErr:  keyIDErr,
	}

	err := env.Sign(t.Context(), signer)

	require.Error(t, err)
	require.ErrorIs(t, err, keyIDErr)
	assert.Contains(t, err.Error(), "failed to get key ID")
}

func TestEnvelope_Sign_CertificateError(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	certErr := stderrors.New("cert failed")
	signer := &mockSigner{
		keyID:     "key-id",
		signature: []byte("sig"),
		certErr:   certErr,
	}

	err := env.Sign(t.Context(), signer)

	require.Error(t, err)
	require.ErrorIs(t, err, certErr)
	assert.Contains(t, err.Error(), "failed to get certificate")
}

func TestEnvelope_Sign_MultipleSignatures(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	signer1 := &mockSigner{keyID: "key-1", signature: []byte("sig-1")}
	signer2 := &mockSigner{keyID: "key-2", signature: []byte("sig-2")}

	require.NoError(t, env.Sign(t.Context(), signer1))
	require.NoError(t, env.Sign(t.Context(), signer2))

	assert.Len(t, env.Signatures, 2)
	assert.Equal(t, "key-1", env.Signatures[0].KeyID)
	assert.Equal(t, "key-2", env.Signatures[1].KeyID)
}

func TestEnvelope_ToJSON(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)

	data, err := env.ToJSON()

	require.NoError(t, err)
	assert.Contains(t, string(data), `"payloadType":"application/vnd.in-toto+json"`)
	assert.Contains(t, string(data), `"payload":`)
}

func TestEnvelope_ToJSONIndent(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)

	data, err := env.ToJSONIndent()

	require.NoError(t, err)
	assert.Contains(t, string(data), "\n")
	assert.Contains(t, string(data), "  ")
}

func TestEnvelope_GetStatement(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)

	extracted, err := env.GetStatement()

	require.NoError(t, err)
	assert.Equal(t, stmt.Type, extracted.Type)
	assert.Equal(t, stmt.PredicateType, extracted.PredicateType)
	assert.Len(t, extracted.Subject, 1)
}

func TestEnvelope_GetStatement_InvalidBase64(t *testing.T) {
	env := &Envelope{
		Payload:     "not-valid-base64!!!",
		PayloadType: PayloadType,
	}

	_, err := env.GetStatement()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode payload")
}

func TestEnvelope_GetStatement_InvalidJSON(t *testing.T) {
	env := &Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("not json")),
		PayloadType: PayloadType,
	}

	_, err := env.GetStatement()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal statement")
}

func TestEnvelope_Verify(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)
	env.Signatures = []Signature{
		{KeyID: "key-1", Signature: base64.StdEncoding.EncodeToString([]byte("sig-1"))},
	}
	verifier := &mockVerifier{}

	err := env.Verify(verifier)

	assert.NoError(t, err)
}

func TestEnvelope_Verify_NilVerifier(t *testing.T) {
	env := &Envelope{Signatures: []Signature{{KeyID: "k", Signature: "c2ln"}}}

	err := env.Verify(nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilVerifier)
}

func TestEnvelope_Verify_NoSignatures(t *testing.T) {
	env := &Envelope{Signatures: []Signature{}}
	verifier := &mockVerifier{}

	err := env.Verify(verifier)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSignatures)
}

func TestEnvelope_Verify_InvalidSignatureBase64(t *testing.T) {
	env := &Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("{}")),
		PayloadType: PayloadType,
		Signatures:  []Signature{{KeyID: "key", Signature: "invalid-base64!!!"}},
	}
	verifier := &mockVerifier{}

	err := env.Verify(verifier)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode signature")
}

func TestEnvelope_Verify_VerificationFailed(t *testing.T) {
	env := &Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("{}")),
		PayloadType: PayloadType,
		Signatures:  []Signature{{KeyID: "key", Signature: base64.StdEncoding.EncodeToString([]byte("sig"))}},
	}
	verifyErr := stderrors.New("verification failed")
	verifier := &mockVerifier{verifyErr: verifyErr}

	err := env.Verify(verifier)

	require.Error(t, err)
	assert.ErrorIs(t, err, verifyErr)
}

func TestEnvelope_Verify_MultipleSignatures(t *testing.T) {
	env := &Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("{}")),
		PayloadType: PayloadType,
		Signatures: []Signature{
			{KeyID: "key-1", Signature: base64.StdEncoding.EncodeToString([]byte("sig-1"))},
			{KeyID: "key-2", Signature: base64.StdEncoding.EncodeToString([]byte("sig-2"))},
		},
	}
	verifier := &mockVerifier{}

	err := env.Verify(verifier)

	assert.NoError(t, err)
}

func TestEnvelope_HasSignatures(t *testing.T) {
	env := &Envelope{}
	assert.False(t, env.HasSignatures())

	env.Signatures = []Signature{{KeyID: "k", Signature: "s"}}
	assert.True(t, env.HasSignatures())
}

func TestEnvelope_SignatureCount(t *testing.T) {
	env := &Envelope{}
	assert.Equal(t, 0, env.SignatureCount())

	env.Signatures = []Signature{{}, {}, {}}
	assert.Equal(t, 3, env.SignatureCount())
}

func TestEnvelope_HasCertificate(t *testing.T) {
	tests := []struct {
		name       string
		signatures []Signature
		want       bool
	}{
		{
			name:       "no signatures",
			signatures: nil,
			want:       false,
		},
		{
			name:       "empty signatures",
			signatures: []Signature{},
			want:       false,
		},
		{
			name: "signature without certificate",
			signatures: []Signature{
				{Signature: "sig1"},
			},
			want: false,
		},
		{
			name: "signature with certificate",
			signatures: []Signature{
				{Signature: "sig1", Certificate: "cert1"},
			},
			want: true,
		},
		{
			name: "multiple signatures, none with certificate",
			signatures: []Signature{
				{Signature: "sig1"},
				{Signature: "sig2"},
			},
			want: false,
		},
		{
			name: "multiple signatures, first has certificate",
			signatures: []Signature{
				{Signature: "sig1", Certificate: "cert1"},
				{Signature: "sig2"},
			},
			want: true,
		},
		{
			name: "multiple signatures, second has certificate",
			signatures: []Signature{
				{Signature: "sig1"},
				{Signature: "sig2", Certificate: "cert2"},
			},
			want: true,
		},
		{
			name: "multiple signatures, all have certificates",
			signatures: []Signature{
				{Signature: "sig1", Certificate: "cert1"},
				{Signature: "sig2", Certificate: "cert2"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &Envelope{Signatures: tt.signatures}
			assert.Equal(t, tt.want, env.HasCertificate())
		})
	}
}

func TestEnvelope_preauthEncode(t *testing.T) {
	env := &Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("test payload")),
		PayloadType: PayloadType,
	}

	pae := env.preauthEncode()

	// PAE format: "DSSEv1 <len(type)> <type> <len(body)> <body>"
	assert.Contains(t, string(pae), "DSSEv1")
	assert.Contains(t, string(pae), PayloadType)
	assert.Contains(t, string(pae), "test payload")
}

func TestEnvelope_JSONRoundTrip(t *testing.T) {
	stmt := validStatement(t)
	original, _ := NewEnvelope(stmt)
	original.Signatures = []Signature{
		{KeyID: "key-1", Signature: "sig-1", Certificate: "cert-1"},
	}

	data, err := original.ToJSON()
	require.NoError(t, err)

	var parsed Envelope
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Payload, parsed.Payload)
	assert.Equal(t, original.PayloadType, parsed.PayloadType)
	assert.Len(t, parsed.Signatures, 1)
	assert.Equal(t, "key-1", parsed.Signatures[0].KeyID)
	assert.Equal(t, "cert-1", parsed.Signatures[0].Certificate)
}

func TestEnvelope_SHA256(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)

	hash, err := env.SHA256()

	require.NoError(t, err)
	assert.Len(t, hash, 64) // SHA256 hex is 64 characters
	assert.Regexp(t, "^[a-f0-9]+$", hash)
}

func TestEnvelope_SHA256_Consistent(t *testing.T) {
	stmt := validStatement(t)
	env, _ := NewEnvelope(stmt)

	hash1, _ := env.SHA256()
	hash2, _ := env.SHA256()

	assert.Equal(t, hash1, hash2)
}

func TestEnvelope_SHA256_DifferentEnvelopes(t *testing.T) {
	stmt1, _ := NewStatement(
		"https://example.com/v1",
		map[string]string{"a": "1"},
		[]Subject{{Name: "file1", Digest: map[string]string{"sha256": "abc"}}},
	)
	stmt2, _ := NewStatement(
		"https://example.com/v1",
		map[string]string{"a": "2"},
		[]Subject{{Name: "file2", Digest: map[string]string{"sha256": "def"}}},
	)

	env1, _ := NewEnvelope(stmt1)
	env2, _ := NewEnvelope(stmt2)

	hash1, _ := env1.SHA256()
	hash2, _ := env2.SHA256()

	assert.NotEqual(t, hash1, hash2)
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "application/vnd.in-toto+json", PayloadType)
	assert.Equal(t, "DSSEv1", DSSEVersion)
}

func TestEnvelope_ExtractCertificate_DER(t *testing.T) {
	// Create a self-signed certificate for testing
	cert := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{
				KeyID:       "test-key",
				Signature:   "sig",
				Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
			},
		},
	}

	extracted, err := env.ExtractCertificate()

	require.NoError(t, err)
	assert.NotNil(t, extracted)
	assert.Equal(t, cert.Subject.CommonName, extracted.Subject.CommonName)
}

func TestEnvelope_ExtractCertificate_PEM(t *testing.T) {
	cert := generateTestCertificate(t)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	env := &Envelope{
		Signatures: []Signature{
			{
				KeyID:       "test-key",
				Signature:   "sig",
				Certificate: base64.StdEncoding.EncodeToString(pemBlock),
			},
		},
	}

	extracted, err := env.ExtractCertificate()

	require.NoError(t, err)
	assert.NotNil(t, extracted)
	assert.Equal(t, cert.Subject.CommonName, extracted.Subject.CommonName)
}

func TestEnvelope_ExtractCertificate_NoCertificate(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: ""},
			{KeyID: "key-2", Signature: "sig-2", Certificate: ""},
		},
	}

	_, err := env.ExtractCertificate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificate_NoSignatures(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{},
	}

	_, err := env.ExtractCertificate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificate_InvalidBase64(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key", Signature: "sig", Certificate: "not-valid-base64!!!"},
		},
	}

	_, err := env.ExtractCertificate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificate_InvalidCertData(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key", Signature: "sig", Certificate: base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
		},
	}

	_, err := env.ExtractCertificate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificate_MultipleSignatures_FirstHasCert(t *testing.T) {
	cert := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: base64.StdEncoding.EncodeToString(cert.Raw)},
			{KeyID: "key-2", Signature: "sig-2", Certificate: ""},
		},
	}

	extracted, err := env.ExtractCertificate()

	require.NoError(t, err)
	assert.NotNil(t, extracted)
}

func TestEnvelope_ExtractCertificate_MultipleSignatures_SecondHasCert(t *testing.T) {
	cert := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: ""},
			{KeyID: "key-2", Signature: "sig-2", Certificate: base64.StdEncoding.EncodeToString(cert.Raw)},
		},
	}

	extracted, err := env.ExtractCertificate()

	require.NoError(t, err)
	assert.NotNil(t, extracted)
}

func TestEnvelope_ExtractCertificates_SingleSignature(t *testing.T) {
	cert := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: base64.StdEncoding.EncodeToString(cert.Raw)},
		},
	}

	certs, err := env.ExtractCertificates()

	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
}

func TestEnvelope_ExtractCertificates_MultipleSignatures(t *testing.T) {
	cert1 := generateTestCertificate(t)
	cert2 := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: base64.StdEncoding.EncodeToString(cert1.Raw)},
			{KeyID: "key-2", Signature: "sig-2", Certificate: base64.StdEncoding.EncodeToString(cert2.Raw)},
		},
	}

	certs, err := env.ExtractCertificates()

	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestEnvelope_ExtractCertificates_MixedSignatures(t *testing.T) {
	cert := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: ""},
			{KeyID: "key-2", Signature: "sig-2", Certificate: base64.StdEncoding.EncodeToString(cert.Raw)},
			{KeyID: "key-3", Signature: "sig-3", Certificate: ""},
		},
	}

	certs, err := env.ExtractCertificates()

	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestEnvelope_ExtractCertificates_NoCertificates(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: ""},
			{KeyID: "key-2", Signature: "sig-2", Certificate: ""},
		},
	}

	_, err := env.ExtractCertificates()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificates_NoSignatures(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{},
	}

	_, err := env.ExtractCertificates()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificates_InvalidBase64(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key", Signature: "sig", Certificate: "not-valid-base64!!!"},
		},
	}

	_, err := env.ExtractCertificates()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificates_InvalidCertData(t *testing.T) {
	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key", Signature: "sig", Certificate: base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
		},
	}

	_, err := env.ExtractCertificates()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCertificate)
}

func TestEnvelope_ExtractCertificates_SkipsInvalidCerts(t *testing.T) {
	cert := generateTestCertificate(t)

	env := &Envelope{
		Signatures: []Signature{
			{KeyID: "key-1", Signature: "sig-1", Certificate: "invalid-base64!!!"},
			{KeyID: "key-2", Signature: "sig-2", Certificate: base64.StdEncoding.EncodeToString([]byte("invalid cert data"))},
			{KeyID: "key-3", Signature: "sig-3", Certificate: base64.StdEncoding.EncodeToString(cert.Raw)},
		},
	}

	certs, err := env.ExtractCertificates()

	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
}

// generateTestCertificate creates a self-signed certificate for testing.
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
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
