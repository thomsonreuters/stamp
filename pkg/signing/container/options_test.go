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
	"github.com/thomsonreuters/stamp/pkg/signing/sigstore"
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
	validKey := &sigstore.KeyOptions{Signer: signer, Hint: []byte("id")}
	validSigstore := sigstore.Options{Key: validKey}
	registry := &RegistryOptions{Username: "user", Password: "pass"}

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			// Verifies the sigstore delegation path: a missing Key/Fulcio must
			// still surface through container.Options.validate.
			name:    "delegates to sigstore: missing key and fulcio",
			opts:    Options{Registry: registry},
			wantErr: "one of Key or Fulcio is required",
		},
		{
			name: "nil registry passes validation",
			opts: Options{Options: validSigstore},
		},
		{
			// Empty struct routes to the keychain (see hasExplicitRegistryCreds
			// in signer.go); validate accepts it.
			name: "empty registry struct passes validation",
			opts: Options{
				Options:  validSigstore,
				Registry: &RegistryOptions{},
			},
		},
		{
			name: "registry with only username is rejected",
			opts: Options{
				Options:  validSigstore,
				Registry: &RegistryOptions{Username: "user"},
			},
			wantErr: "must be set together",
		},
		{
			name: "registry with only password is rejected",
			opts: Options{
				Options:  validSigstore,
				Registry: &RegistryOptions{Password: "pass"},
			},
			wantErr: "must be set together",
		},
		{
			name: "valid key-mode with creds",
			opts: Options{
				Options:  validSigstore,
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
