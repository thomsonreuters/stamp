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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureHashAlgo_ECDSACurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  crypto.Hash
	}{
		{"P-256", elliptic.P256(), crypto.SHA256},
		{"P-384", elliptic.P384(), crypto.SHA384},
		{"P-521", elliptic.P521(), crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			assert.Equal(t, tt.want, SignatureHashAlgo(&ecKey.PublicKey))
		})
	}
}

func TestSignatureHashAlgo_ECDSAUnsupportedCurveDefaultsToSHA256(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, crypto.SHA256, SignatureHashAlgo(&ecKey.PublicKey))
}

func TestSignatureHashAlgo_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, crypto.SHA512, SignatureHashAlgo(pub))
}

func TestSignatureHashAlgo_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	assert.Equal(t, crypto.SHA256, SignatureHashAlgo(&rsaKey.PublicKey))
}

func TestSignatureHashAlgo_UnsupportedTypeDefaultsToSHA256(t *testing.T) {
	assert.Equal(t, crypto.SHA256, SignatureHashAlgo("not a public key"))
}

func TestSignatureHashAlgo_NilDefaultsToSHA256(t *testing.T) {
	assert.Equal(t, crypto.SHA256, SignatureHashAlgo(nil))
}
