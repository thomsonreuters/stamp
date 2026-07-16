// Copyright 2025 Thomson Reuters
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

package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectAlgorithms(t *testing.T) {
	ecdsaKey := func(t *testing.T, curve elliptic.Curve) *ecdsa.PublicKey {
		t.Helper()
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		return &priv.PublicKey
	}
	rsaKey := func(t *testing.T, bits int) *rsa.PublicKey {
		t.Helper()
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		return &priv.PublicKey
	}

	tests := []struct {
		name        string
		pub         any
		wantHash    crypto.Hash
		wantHashPb  protocommon.HashAlgorithm
		wantSignAlg protocommon.PublicKeyDetails
		wantKeyAlgo string
		wantErr     string
	}{
		{"ECDSA P-256", ecdsaKey(t, elliptic.P256()),
			crypto.SHA256, protocommon.HashAlgorithm_SHA2_256,
			protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, "ECDSA", ""},
		{"ECDSA P-384", ecdsaKey(t, elliptic.P384()),
			crypto.SHA384, protocommon.HashAlgorithm_SHA2_384,
			protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, "ECDSA", ""},
		{"ECDSA P-521", ecdsaKey(t, elliptic.P521()),
			crypto.SHA512, protocommon.HashAlgorithm_SHA2_512,
			protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512, "ECDSA", ""},
		{"RSA 2048", rsaKey(t, 2048),
			crypto.SHA256, protocommon.HashAlgorithm_SHA2_256,
			protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, "RSA", ""},
		{"unsupported Ed25519", func() ed25519.PublicKey {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			return pub
		}(), 0, 0, 0, "", "unsupported public key type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, hashPb, signAlgo, keyAlgo, err := detectAlgorithms(tt.pub)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantHash, hash)
			assert.Equal(t, tt.wantHashPb, hashPb)
			assert.Equal(t, tt.wantSignAlg, signAlgo)
			assert.Equal(t, tt.wantKeyAlgo, keyAlgo)
		})
	}
}

func TestPublicKeyToPEM_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemStr, err := publicKeyToPEM(&priv.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")

	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	decoded, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	// PublicKey.X / .Y direct access is deprecated in Go 1.26; use the
	// Equal method (compares coordinates + curve without touching them).
	assert.True(t, priv.PublicKey.Equal(decoded), "decoded public key must equal the original")
}

func TestNewKeypairAdapter_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kp, err := newKeypairAdapter(priv, []byte("adapter-key-id"))
	require.NoError(t, err)

	assert.Equal(t, protocommon.HashAlgorithm_SHA2_256, kp.GetHashAlgorithm())
	assert.Equal(t, protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
	assert.Equal(t, []byte("adapter-key-id"), kp.GetHint())
	assert.Equal(t, "ECDSA", kp.GetKeyAlgorithm())
	assert.Equal(t, &priv.PublicKey, kp.GetPublicKey())
	pemStr, err := kp.GetPublicKeyPem()
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
}

func TestNewKeypairAdapter_UnsupportedCurveErrors(t *testing.T) {
	// P-224 isn't in detectAlgorithms; adapter construction must reject.
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	_, err = newKeypairAdapter(priv, []byte("id"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECDSA curve")
}

func TestKeypairAdapter_SignData_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kp, err := newKeypairAdapter(priv, []byte("id"))
	require.NoError(t, err)

	payload := []byte("payload to sign")
	sig, digest, err := kp.SignData(context.Background(), payload)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// digest must be sha256(payload) for P-256
	want := sha256.Sum256(payload)
	assert.Equal(t, want[:], digest)

	// signature must verify against the same digest
	assert.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest, sig),
		"ECDSA verify must succeed against the returned digest")
}

func TestKeypairAdapter_SignData_P521_UsesSHA512(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	kp, err := newKeypairAdapter(priv, []byte("id"))
	require.NoError(t, err)

	payload := []byte("payload")
	sig, digest, err := kp.SignData(context.Background(), payload)
	require.NoError(t, err)

	// P-521 must hash with SHA-512, not SHA-256
	want := sha512.Sum512(payload)
	assert.Equal(t, want[:], digest, "P-521 must use SHA-512")
	assert.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest, sig))
}
