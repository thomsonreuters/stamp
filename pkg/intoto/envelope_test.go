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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &Envelope{Signatures: tt.signatures}
			assert.Equal(t, tt.want, env.HasCertificate())
		})
	}
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

func TestConstants(t *testing.T) {
	assert.Equal(t, "application/vnd.in-toto+json", PayloadType)
	assert.Equal(t, "DSSEv1", DSSEVersion)
}

func TestEnvelope_ExtractCertificate_DER(t *testing.T) {
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
