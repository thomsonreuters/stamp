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

package container

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestECDSAKey returns a fresh P-256 crypto.Signer for tests.
func newTestECDSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return priv
}

func TestOptions_validate(t *testing.T) {
	signer := newTestECDSAKey(t)
	registry := &RegistryOptions{Username: "user", Password: "pass"}
	validKey := &KeyOptions{Signer: signer, Hint: []byte("id")}

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "missing key and fulcio",
			opts:    Options{Registry: registry},
			wantErr: "one of Key or Fulcio is required",
		},
		{
			name: "key and fulcio both set",
			opts: Options{
				Key:      validKey,
				Fulcio:   &FulcioOptions{URL: "https://fulcio.example.com", IDToken: "tok"},
				Registry: registry,
			},
			wantErr: "Key and Fulcio are mutually exclusive",
		},
		{
			name: "key without signer",
			opts: Options{
				Key:      &KeyOptions{Hint: []byte("id")},
				Registry: registry,
			},
			wantErr: "Key.Signer is required",
		},
		{
			name: "key without hint",
			opts: Options{
				Key:      &KeyOptions{Signer: signer},
				Registry: registry,
			},
			wantErr: "Key.Hint is required",
		},
		{
			name: "fulcio without URL",
			opts: Options{
				Fulcio:   &FulcioOptions{IDToken: "tok"},
				Registry: registry,
			},
			wantErr: "Fulcio.URL is required",
		},
		{
			name: "fulcio without token",
			opts: Options{
				Fulcio:   &FulcioOptions{URL: "https://fulcio.example.com"},
				Registry: registry,
			},
			wantErr: "Fulcio.IDToken is required",
		},
		{
			name: "rekor without URL",
			opts: Options{
				Key:      validKey,
				Rekor:    &RekorOptions{},
				Registry: registry,
			},
			wantErr: "Rekor.URL is required",
		},
		{
			// Signer.Sign uses the keychain when Registry is nil.
			name: "nil registry passes validation",
			opts: Options{Key: validKey},
		},
		{
			// Empty struct also routes to the keychain (see
			// hasExplicitRegistryCreds in signer.go); validate accepts it.
			name: "empty registry struct passes validation",
			opts: Options{
				Key:      validKey,
				Registry: &RegistryOptions{},
			},
		},
		{
			name: "registry with only username is rejected",
			opts: Options{
				Key:      validKey,
				Registry: &RegistryOptions{Username: "user"},
			},
			wantErr: "must be set together",
		},
		{
			name: "registry with only password is rejected",
			opts: Options{
				Key:      validKey,
				Registry: &RegistryOptions{Password: "pass"},
			},
			wantErr: "must be set together",
		},
		{
			name: "valid key-mode options",
			opts: Options{
				Key:      validKey,
				Registry: registry,
			},
		},
		{
			name: "valid keyless options with rekor",
			opts: Options{
				Fulcio:   &FulcioOptions{URL: "https://fulcio.example.com", IDToken: "tok"},
				Rekor:    &RekorOptions{URL: "https://rekor.example.com"},
				Registry: registry,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOptions_buildSigningMaterial_KeyMode(t *testing.T) {
	opts := &Options{Key: &KeyOptions{Signer: newTestECDSAKey(t), Hint: []byte("id")}}
	kp, provider, certOpts, err := opts.buildSigningMaterial()
	require.NoError(t, err)
	require.NotNil(t, kp)
	assert.Nil(t, provider)
	assert.Nil(t, certOpts)
}

func TestOptions_buildSigningMaterial_FulcioMode(t *testing.T) {
	opts := &Options{Fulcio: &FulcioOptions{URL: "https://fulcio.example.com", IDToken: "tok"}}
	kp, provider, certOpts, err := opts.buildSigningMaterial()
	require.NoError(t, err)
	require.NotNil(t, kp)
	require.NotNil(t, provider)
	require.NotNil(t, certOpts)
	assert.Equal(t, "tok", certOpts.IDToken)
}

func TestOptions_buildSigningMaterial_KeyModeUnsupportedCurve(t *testing.T) {
	// P-224 not in detectAlgorithms → keypair adapter must reject.
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	opts := &Options{Key: &KeyOptions{Signer: priv, Hint: []byte("id")}}
	_, _, _, err = opts.buildSigningMaterial()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keypair adapter")
}
