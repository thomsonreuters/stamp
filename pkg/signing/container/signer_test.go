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
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNewSigner(t *testing.T) {
	s := NewSigner(logger.NewNoop())
	require.NotNil(t, s)
	assert.NotNil(t, s.logger)
}

func TestSigner_Sign_InvalidOptions(t *testing.T) {
	s := NewSigner(logger.NewNoop())
	_, err := s.Sign(context.Background(), "alpine:latest", Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "container sign")
}

func TestSigner_Sign_InvalidImageReference(t *testing.T) {
	s := NewSigner(logger.NewNoop())
	opts := Options{
		Key:      &KeyOptions{Signer: newTestECDSAKey(t), Hint: []byte("id")},
		Registry: &RegistryOptions{Username: "user", Password: "pass"},
	}
	_, err := s.Sign(context.Background(), "://not a ref", opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse reference")
}

func TestHasExplicitRegistryCreds(t *testing.T) {
	tests := []struct {
		name string
		in   *RegistryOptions
		want bool
	}{
		{"nil is keychain", nil, false},
		{"empty struct is keychain (not empty Basic Auth)", &RegistryOptions{}, false},
		{"username only is keychain (validate rejects this at a higher layer)", &RegistryOptions{Username: "u"}, false},
		{"password only is keychain", &RegistryOptions{Password: "p"}, false},
		{"both set is explicit creds", &RegistryOptions{Username: "u", Password: "p"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasExplicitRegistryCreds(tt.in))
		})
	}
}

func TestWrapSignBundleError(t *testing.T) {
	tests := []struct {
		name        string
		underlying  error
		rekor       bool
		wantContain string
	}{
		{
			name: "rekor TextConsumer failure gets a policy hint",
			underlying: errors.New(
				`&{0 } (*models.Error) is not supported by the TextConsumer, can be resolved by supporting TextUnmarshaler interface`,
			),
			rekor:       true,
			wantContain: "Rekor rejected the upload with a non-JSON response",
		},
		{
			name:        "rekor generic failure passes through",
			underlying:  errors.New("connection refused"),
			rekor:       true,
			wantContain: "container sign: sign.Bundle",
		},
		{
			name:        "TextConsumer without rekor enabled is generic",
			underlying:  errors.New(`(*models.Error) is not supported by the TextConsumer`),
			rekor:       false,
			wantContain: "container sign: sign.Bundle",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapSignBundleError(tt.underlying, tt.rekor)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantContain)
			assert.ErrorIs(t, err, tt.underlying, "wrapped error must expose the underlying via errors.Is/Unwrap")
		})
	}
}

func TestBuildStatementPayload(t *testing.T) {
	ref, err := name.ParseReference("registry.example.com/app:v1")
	require.NoError(t, err)

	payload, err := buildStatementPayload(ref, "sha256", "abc123")
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(payload, &stmt))

	assert.Equal(t, intoto.StatementType, stmt.Type)
	assert.Equal(t, CosignPredicateType, stmt.PredicateType)
	require.Len(t, stmt.Subject, 1)
	assert.Equal(t, "registry.example.com/app", stmt.Subject[0].Name)
	assert.Equal(t, map[string]string{"sha256": "abc123"}, stmt.Subject[0].Digest)
	predicateBytes, err := json.Marshal(stmt.Predicate)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(predicateBytes))
}
