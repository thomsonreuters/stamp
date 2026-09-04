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

package verification

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityConfigured(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "empty config",
			cfg:  Config{},
			want: false,
		},
		{
			name: "SAN exact",
			cfg:  Config{ExpectedSAN: "user@example.com"},
			want: true,
		},
		{
			name: "SAN regex",
			cfg:  Config{ExpectedSANRegex: `.+@example\.com`},
			want: true,
		},
		{
			name: "issuer exact",
			cfg:  Config{ExpectedIssuer: "https://accounts.google.com"},
			want: true,
		},
		{
			name: "issuer regex",
			cfg:  Config{ExpectedIssuerRegex: `^https://.*google\.com$`},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, identityConfigured(tt.cfg))
		})
	}
}

// TestVerify_NoTrustedMaterial asserts Verify returns an error when it is
// called without any trust root. The full bundle-verification path is
// exercised end-to-end by docs/testing/c3-e2e/run-verify.sh; unit tests
// here cover only the local guards.
func TestVerify_NoTrustedMaterial(t *testing.T) {
	result, err := Verify(t.Context(), nil, nil, Config{})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no trusted material")
}
