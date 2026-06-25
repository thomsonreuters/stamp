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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fp, err := Fingerprint(rsaKey)
	require.NoError(t, err)

	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA256 hex = 64 chars
}

func TestFingerprint_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fp, err := Fingerprint(ecKey)
	require.NoError(t, err)

	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

func TestFingerprint_Deterministic(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fp1, err := Fingerprint(ecKey)
	require.NoError(t, err)

	fp2, err := Fingerprint(ecKey)
	require.NoError(t, err)

	assert.Equal(t, fp1, fp2)
}

func TestFingerprint_DifferentKeys(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fp1, err := Fingerprint(key1)
	require.NoError(t, err)

	fp2, err := Fingerprint(key2)
	require.NoError(t, err)

	assert.NotEqual(t, fp1, fp2)
}

func TestFingerprint_UnsupportedKeyType(t *testing.T) {
	_, err := Fingerprint("not a private key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestFingerprintPublicKey_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fp, err := FingerprintPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

func TestFingerprintPublicKey_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fp, err := FingerprintPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

func TestFingerprintPublicKey_MatchesFingerprint(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fpPrivate, err := Fingerprint(rsaKey)
	require.NoError(t, err)

	fpPublic, err := FingerprintPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, fpPrivate, fpPublic)
}

func TestFingerprintPublicKey_DifferentCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			fp, err := FingerprintPublicKey(&ecKey.PublicKey)
			require.NoError(t, err)

			assert.NotEmpty(t, fp)
			assert.Len(t, fp, 64)
		})
	}
}

func TestFingerprintPublicKey_UnsupportedType(t *testing.T) {
	_, err := FingerprintPublicKey("not a public key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal public key")
}

func TestExtractPublicKey_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKey, err := ExtractPublicKey(rsaKey)
	require.NoError(t, err)

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	assert.True(t, ok)
	assert.Equal(t, &rsaKey.PublicKey, rsaPubKey)
}

func TestExtractPublicKey_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey, err := ExtractPublicKey(ecKey)
	require.NoError(t, err)

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	assert.True(t, ok)
	assert.Equal(t, &ecKey.PublicKey, ecPubKey)
}

func TestExtractPublicKey_UnsupportedType(t *testing.T) {
	_, err := ExtractPublicKey("not a key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestExtractPublicKey_NilKey(t *testing.T) {
	_, err := ExtractPublicKey(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestFingerprint_HexFormat(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	fp, err := Fingerprint(ecKey)
	require.NoError(t, err)

	// Verify lowercase hex format
	for _, c := range fp {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
	}
}

func TestFingerprint_DifferentRSAKeySizes(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"RSA-2048", 2048},
		{"RSA-4096", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rsaKey, err := rsa.GenerateKey(rand.Reader, tt.size)
			require.NoError(t, err)

			fp, err := Fingerprint(rsaKey)
			require.NoError(t, err)

			assert.NotEmpty(t, fp)
			assert.Len(t, fp, 64)
		})
	}
}
