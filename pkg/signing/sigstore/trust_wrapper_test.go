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

package sigstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubBase satisfies root.TrustedMaterial. PublicKeyVerifier always errors so
// that any test hitting it (indicating the wrapper failed to delegate) shows
// up as a clear failure.
type stubBase struct {
	root.BaseTrustedMaterial
	pkvCalled bool
}

func (s *stubBase) PublicKeyVerifier(_ string) (root.TimeConstrainedVerifier, error) {
	s.pkvCalled = true
	return nil, errors.New("stubBase.PublicKeyVerifier must not be called when keyMaterial is set")
}

func genECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return priv
}

func TestNewSignerKeyTrustedMaterial_NilPubKeyReturnsBaseUnchanged(t *testing.T) {
	base := &stubBase{}
	got, err := newSignerKeyTrustedMaterial(base, nil)
	require.NoError(t, err)
	// Same instance — no wrapping.
	assert.Same(t, root.TrustedMaterial(base), got)
}

func TestNewSignerKeyTrustedMaterial_UnsupportedPubKeyErrors(t *testing.T) {
	// A plain string is not a crypto.PublicKey and LoadDefaultVerifier will reject it.
	_, err := newSignerKeyTrustedMaterial(&stubBase{}, "not a key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load verifier for user key")
}

// The whole point of the wrapper: PublicKeyVerifier(hint) returns the injected
// key regardless of hint, so sigstore-go's CompareKey succeeds during
// sign.Bundle's post-verify.
func TestSignerKeyTrustedMaterial_PublicKeyVerifierReturnsInjectedKey(t *testing.T) {
	base := &stubBase{}
	priv := genECDSAKey(t)

	wrapped, err := newSignerKeyTrustedMaterial(base, priv.Public())
	require.NoError(t, err)

	for _, hint := range []string{"", "any-hint", "another-hint", "sha256:abc"} {
		verifier, err := wrapped.PublicKeyVerifier(hint)
		require.NoError(t, err, "hint=%q", hint)
		require.NotNil(t, verifier, "hint=%q", hint)

		got, err := verifier.PublicKey()
		require.NoError(t, err)
		equaler, ok := got.(interface{ Equal(x crypto.PublicKey) bool })
		require.True(t, ok, "public key must implement Equal(crypto.PublicKey)")
		assert.True(t, equaler.Equal(priv.Public()), "returned key must equal signer's public key")
	}
	assert.False(t, base.pkvCalled, "base.PublicKeyVerifier must not be reached when keyMaterial is set")
}

// Non-PublicKeyVerifier methods must fall through to the embedded base so the
// wrapped material still exposes Fulcio CAs, Rekor logs, and TSA chains.
func TestSignerKeyTrustedMaterial_DelegatesOtherMethods(t *testing.T) {
	base := &stubBase{}
	priv := genECDSAKey(t)

	wrapped, err := newSignerKeyTrustedMaterial(base, priv.Public())
	require.NoError(t, err)

	// BaseTrustedMaterial provides zero-value slices/maps for each of these.
	// The important assertion is that calling them does not panic and does
	// not route through our override.
	assert.NotNil(t, wrapped.FulcioCertificateAuthorities())
	assert.NotNil(t, wrapped.TimestampingAuthorities())
	assert.NotNil(t, wrapped.RekorLogs())
	assert.NotNil(t, wrapped.CTLogs())
	assert.False(t, base.pkvCalled, "delegate methods must not call PublicKeyVerifier")
}

// When keyMaterial is nil (constructed by field literal, not the constructor),
// the wrapper must fall back to the embedded base's PublicKeyVerifier.
func TestSignerKeyTrustedMaterial_NilKeyMaterialFallsBackToBase(t *testing.T) {
	base := &stubBase{}
	w := &signerKeyTrustedMaterial{TrustedMaterial: base, keyMaterial: nil}

	_, err := w.PublicKeyVerifier("hint")
	require.Error(t, err)
	assert.True(t, base.pkvCalled, "base.PublicKeyVerifier must be invoked when keyMaterial is nil")
}
