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

func TestOptions_Validate(t *testing.T) {
	signer := newTestECDSAKey(t)
	validKey := &KeyOptions{Signer: signer, Hint: []byte("id")}

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "missing key and fulcio",
			opts:    Options{},
			wantErr: "one of Key or Fulcio is required",
		},
		{
			name: "key and fulcio both set",
			opts: Options{
				Key:    validKey,
				Fulcio: &FulcioOptions{URL: "https://fulcio.example.com", IDToken: "tok"},
			},
			wantErr: "Key and Fulcio are mutually exclusive",
		},
		{
			name: "key without signer",
			opts: Options{
				Key: &KeyOptions{Hint: []byte("id")},
			},
			wantErr: "Key.Signer is required",
		},
		{
			name: "key without hint",
			opts: Options{
				Key: &KeyOptions{Signer: signer},
			},
			wantErr: "Key.Hint is required",
		},
		{
			name: "fulcio without URL",
			opts: Options{
				Fulcio: &FulcioOptions{IDToken: "tok"},
			},
			wantErr: "Fulcio.URL is required",
		},
		{
			name: "fulcio without token",
			opts: Options{
				Fulcio: &FulcioOptions{URL: "https://fulcio.example.com"},
			},
			wantErr: "Fulcio.IDToken is required",
		},
		{
			name: "rekor without URL",
			opts: Options{
				Key:   validKey,
				Rekor: &RekorOptions{},
			},
			wantErr: "Rekor.URL is required",
		},
		{
			name: "valid key-mode options",
			opts: Options{Key: validKey},
		},
		{
			name: "valid keyless options with rekor",
			opts: Options{
				Fulcio: &FulcioOptions{URL: "https://fulcio.example.com", IDToken: "tok"},
				Rekor:  &RekorOptions{URL: "https://rekor.example.com"},
			},
		},
		// --- TSA validation ---
		{
			name: "TSA set with empty URL, no Rekor",
			opts: Options{
				Key: validKey,
				TSA: &TSAOptions{URL: ""},
			},
			wantErr: "TSA.URL is required when TSA is set",
		},
		{
			name: "valid TSA-only, no Rekor",
			opts: Options{
				Key: validKey,
				TSA: &TSAOptions{URL: "https://timestamp.example.com"},
			},
		},
		{
			name: "rekor v1 with empty TSA URL",
			opts: Options{
				Key:   validKey,
				Rekor: &RekorOptions{URL: "https://rekor.example.com", Version: 1},
				TSA:   &TSAOptions{URL: ""},
			},
			wantErr: "TSA.URL is required when TSA is set",
		},
		{
			name: "rekor v1 with valid TSA",
			opts: Options{
				Key:   validKey,
				Rekor: &RekorOptions{URL: "https://rekor.example.com", Version: 1},
				TSA:   &TSAOptions{URL: "https://timestamp.example.com"},
			},
		},
		{
			name: "rekor v2 without TSA",
			opts: Options{
				Key:   validKey,
				Rekor: &RekorOptions{URL: "https://rekor.example.com", Version: 2},
			},
			wantErr: "Rekor v2 requires TSA.URL to be set",
		},
		{
			name: "rekor v2 with empty TSA URL (v2 rule takes precedence)",
			opts: Options{
				Key:   validKey,
				Rekor: &RekorOptions{URL: "https://rekor.example.com", Version: 2},
				TSA:   &TSAOptions{URL: ""},
			},
			wantErr: "Rekor v2 requires TSA.URL to be set",
		},
		{
			name: "valid rekor v2 with TSA",
			opts: Options{
				Key:   validKey,
				Rekor: &RekorOptions{URL: "https://rekor.example.com", Version: 2},
				TSA:   &TSAOptions{URL: "https://timestamp.example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOptions_BuildSigningMaterial_KeyMode(t *testing.T) {
	opts := &Options{Key: &KeyOptions{Signer: newTestECDSAKey(t), Hint: []byte("id")}}
	kp, provider, certOpts, err := opts.BuildSigningMaterial()
	require.NoError(t, err)
	require.NotNil(t, kp)
	assert.Nil(t, provider)
	assert.Nil(t, certOpts)
}

func TestOptions_BuildSigningMaterial_FulcioMode(t *testing.T) {
	opts := &Options{Fulcio: &FulcioOptions{URL: "https://fulcio.example.com", IDToken: "tok"}}
	kp, provider, certOpts, err := opts.BuildSigningMaterial()
	require.NoError(t, err)
	require.NotNil(t, kp)
	require.NotNil(t, provider)
	require.NotNil(t, certOpts)
	assert.Equal(t, "tok", certOpts.IDToken)
}

func TestOptions_BuildSigningMaterial_KeyModeUnsupportedCurve(t *testing.T) {
	// P-224 not in detectAlgorithms → keypair adapter must reject.
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	opts := &Options{Key: &KeyOptions{Signer: priv, Hint: []byte("id")}}
	_, _, _, err = opts.BuildSigningMaterial()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keypair adapter")
}
