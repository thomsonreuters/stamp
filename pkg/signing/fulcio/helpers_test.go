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

package fulcio

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate creates a test X.509 certificate.
func createTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestGenerateKeyIDFromCert(t *testing.T) {
	cert := createTestCertificate(t)

	keyID, err := generateKeyIDFromCert(cert)

	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	assert.Len(t, keyID, 64) // SHA256 hex = 64 chars
}

func TestGenerateKeyIDFromCert_Consistent(t *testing.T) {
	cert := createTestCertificate(t)

	keyID1, err := generateKeyIDFromCert(cert)
	require.NoError(t, err)

	keyID2, err := generateKeyIDFromCert(cert)
	require.NoError(t, err)

	assert.Equal(t, keyID1, keyID2)
}

func TestGenerateKeyIDFromCert_DifferentCerts(t *testing.T) {
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)

	keyID1, err := generateKeyIDFromCert(cert1)
	require.NoError(t, err)

	keyID2, err := generateKeyIDFromCert(cert2)
	require.NoError(t, err)

	// Different certificates should have different key IDs
	assert.NotEqual(t, keyID1, keyID2)
}

func TestDeriveAudienceFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "HTTPS URL with path",
			url:      "https://fulcio.sigstore.dev/api/v2",
			expected: "fulcio.sigstore.dev",
		},
		{
			name:     "HTTPS URL without path",
			url:      "https://fulcio.sigstore.dev",
			expected: "fulcio.sigstore.dev",
		},
		{
			name:     "HTTPS URL with port",
			url:      "https://fulcio.example.com:8443/api",
			expected: "fulcio.example.com:8443",
		},
		{
			name:     "HTTP URL",
			url:      "http://localhost:5555",
			expected: "localhost:5555",
		},
		{
			name:     "URL with trailing slash",
			url:      "https://fulcio.example.com/",
			expected: "fulcio.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audience, err := deriveAudienceFromURL(tt.url)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, audience)
		})
	}
}

func TestDeriveAudienceFromURL_EmptyURL(t *testing.T) {
	audience, err := deriveAudienceFromURL("")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "Fulcio URL is required")
}

func TestDeriveAudienceFromURL_InvalidURL(t *testing.T) {
	audience, err := deriveAudienceFromURL("://invalid-url")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "failed to parse Fulcio URL")
}

func TestDeriveAudienceFromURL_NoHost(t *testing.T) {
	audience, err := deriveAudienceFromURL("file:///path/to/file")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "Fulcio URL has no host")
}
