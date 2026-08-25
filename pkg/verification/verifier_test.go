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
)

func TestIdentityConfigured(t *testing.T) {
	tests := []struct {
		name string
		cfg  VerificationConfig
		want bool
	}{
		{
			name: "empty config",
			cfg:  VerificationConfig{},
			want: false,
		},
		{
			name: "SAN exact",
			cfg:  VerificationConfig{ExpectedSAN: "user@example.com"},
			want: true,
		},
		{
			name: "SAN regex",
			cfg:  VerificationConfig{ExpectedSANRegex: `.+@example\.com`},
			want: true,
		},
		{
			name: "issuer exact",
			cfg:  VerificationConfig{ExpectedIssuer: "https://accounts.google.com"},
			want: true,
		},
		{
			name: "issuer regex",
			cfg:  VerificationConfig{ExpectedIssuerRegex: `^https://.*google\.com$`},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, identityConfigured(tt.cfg))
		})
	}
}

// TestVerifier_NoTrustedMaterial asserts the verifier fails cleanly when it is
// constructed without any trust root.
func TestVerifier_NoTrustedMaterial(t *testing.T) {
	// Fixtures pending regeneration — see testdata/README.md for the
	// planned public-sigstore bundle fixtures. Once those exist this test
	// can load a bundle and exercise the full Verify path.
	v := &Verifier{}
	result, err := v.Verify(t.Context(), nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
}
