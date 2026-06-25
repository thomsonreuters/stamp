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

package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPredicateURI(t *testing.T) {
	assert.Equal(t, "https://witness.dev/attestations/jwt/v0.1", PredicateURI)
}

func TestPredicate_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := Predicate{
		Source: "file:/path/to/token.jwt",
		Digest: "sha256:abc123",
		Header: JWTHeader{
			Algorithm: "RS256",
			Type:      "JWT",
			KeyID:     "key-123",
		},
		Claims: JWTClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user@example.com",
			Audience:  "api.example.com",
			ExpiresAt: 1700000000,
			IssuedAt:  1699990000,
		},
		Verification: "verified",
		Key: &Key{
			Method:     "jwks",
			Source:     "https://issuer.example.com/.well-known/jwks.json",
			VerifiedAt: now,
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.Contains(t, string(data), "source")
	assert.Contains(t, string(data), "digest")
	assert.Contains(t, string(data), "header")
	assert.Contains(t, string(data), "claims")
	assert.Contains(t, string(data), "verification")
	assert.Contains(t, string(data), "key")
}

func TestPredicate_JSONUnmarshal(t *testing.T) {
	jsonData := `{
		"source": "env:TOKEN",
		"digest": "sha256:def456",
		"header": {
			"alg": "ES256",
			"typ": "JWT",
			"kid": "key-456"
		},
		"claims": {
			"iss": "https://issuer.example.com",
			"sub": "service@example.com",
			"exp": 1700000000
		},
		"verification": "verified",
		"key": {
			"method": "oidc-discovery",
			"source": "https://issuer.example.com/.well-known/jwks.json",
			"discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
			"verified_at": "2025-11-12T10:00:00Z"
		}
	}`

	var predicate Predicate
	err := json.Unmarshal([]byte(jsonData), &predicate)
	require.NoError(t, err)

	assert.Equal(t, "env:TOKEN", predicate.Source)
	assert.Equal(t, "sha256:def456", predicate.Digest)
	assert.Equal(t, "ES256", predicate.Header.Algorithm)
	assert.Equal(t, "https://issuer.example.com", predicate.Claims.Issuer)
	assert.Equal(t, "verified", predicate.Verification)
	require.NotNil(t, predicate.Key)
	assert.Equal(t, "oidc-discovery", predicate.Key.Method)
}

func TestPredicate_OmitEmptyKey(t *testing.T) {
	predicate := Predicate{
		Source:       "stdin",
		Digest:       "sha256:xyz789",
		Verification: "skipped",
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "key")
}

func TestKey_JSONMarshal(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 30, 0, 0, time.UTC)

	key := Key{
		Method:       "static-key",
		Source:       "/path/to/public.pem",
		VerifiedAt:   now,
		DiscoveryURL: "",
	}

	data, err := json.Marshal(key)
	require.NoError(t, err)

	assert.Contains(t, string(data), "method")
	assert.Contains(t, string(data), "source")
	assert.Contains(t, string(data), "verified_at")
}

func TestKey_OmitEmptyDiscoveryURL(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	key := Key{
		Method:     "jwks",
		Source:     "https://example.com/jwks.json",
		VerifiedAt: now,
	}

	data, err := json.Marshal(key)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "discovery_url")
}

func TestJWTHeader_JSONMarshal(t *testing.T) {
	header := JWTHeader{
		Algorithm: "RS256",
		Type:      "JWT",
		KeyID:     "key-789",
		X5T:       "thumbprint-sha1",
		X5TS256:   "thumbprint-sha256",
		X5C:       []string{"cert1", "cert2"},
	}

	data, err := json.Marshal(header)
	require.NoError(t, err)

	assert.Contains(t, string(data), "alg")
	assert.Contains(t, string(data), "typ")
	assert.Contains(t, string(data), "kid")
	assert.Contains(t, string(data), "x5t")
	assert.Contains(t, string(data), "x5t#S256")
	assert.Contains(t, string(data), "x5c")
}

func TestJWTHeader_OmitEmptyFields(t *testing.T) {
	header := JWTHeader{
		Algorithm: "ES256",
		Type:      "JWT",
	}

	data, err := json.Marshal(header)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "kid")
	assert.NotContains(t, string(data), "x5t")
	assert.NotContains(t, string(data), "x5c")
}

func TestJWTClaims_JSONMarshal(t *testing.T) {
	claims := JWTClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  "api.example.com",
		ExpiresAt: 1700000000,
		NotBefore: 1699990000,
		IssuedAt:  1699990000,
		JWTID:     "jwt-id-123",
		CustomClaims: map[string]any{
			"role":  "admin",
			"scope": []string{"read", "write"},
		},
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	assert.Contains(t, string(data), "iss")
	assert.Contains(t, string(data), "sub")
	assert.Contains(t, string(data), "aud")
	assert.Contains(t, string(data), "exp")
	assert.Contains(t, string(data), "nbf")
	assert.Contains(t, string(data), "iat")
	assert.Contains(t, string(data), "jti")
	assert.Contains(t, string(data), "custom_claims")
}

func TestJWTClaims_OmitEmptyFields(t *testing.T) {
	claims := JWTClaims{
		Issuer:   "https://issuer.example.com",
		Subject:  "user@example.com",
		IssuedAt: 1699990000,
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "aud")
	assert.NotContains(t, string(data), "exp")
	assert.NotContains(t, string(data), "nbf")
	assert.NotContains(t, string(data), "jti")
	assert.NotContains(t, string(data), "custom_claims")
}

func TestJWTClaims_AudienceString(t *testing.T) {
	claims := JWTClaims{
		Issuer:   "https://issuer.example.com",
		Audience: "api.example.com",
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var result JWTClaims
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "api.example.com", result.Audience)
}

func TestJWTClaims_AudienceArray(t *testing.T) {
	claims := JWTClaims{
		Issuer:   "https://issuer.example.com",
		Audience: []string{"api1.example.com", "api2.example.com"},
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var result JWTClaims
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	audArray, ok := result.Audience.([]any)
	require.True(t, ok)
	assert.Len(t, audArray, 2)
}

func TestPredicate_Complete(t *testing.T) {
	now := time.Date(2025, 11, 12, 10, 0, 0, 0, time.UTC)

	predicate := Predicate{
		Source: "file:/tmp/token.jwt",
		Digest: "sha256:complete123",
		Header: JWTHeader{
			Algorithm: "RS256",
			Type:      "JWT",
			KeyID:     "rsa-key-1",
			X5C:       []string{"cert1", "cert2", "cert3"},
			X5T:       "sha1thumb",
			X5TS256:   "sha256thumb",
		},
		Claims: JWTClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "service-account@example.com",
			Audience:  []string{"service1", "service2"},
			ExpiresAt: 1700000000,
			NotBefore: 1699990000,
			IssuedAt:  1699990000,
			JWTID:     "unique-jwt-id",
			CustomClaims: map[string]any{
				"department": "engineering",
				"level":      5,
				"admin":      true,
			},
		},
		Verification: "verified",
		Key: &Key{
			Method:       "oidc-discovery",
			Source:       "https://auth.example.com/.well-known/jwks.json",
			DiscoveryURL: "https://auth.example.com/.well-known/openid-configuration",
			VerifiedAt:   now,
		},
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, predicate.Source, result.Source)
	assert.Equal(t, predicate.Digest, result.Digest)
	assert.Equal(t, predicate.Header.Algorithm, result.Header.Algorithm)
	assert.Equal(t, predicate.Claims.Issuer, result.Claims.Issuer)
	assert.Equal(t, predicate.Verification, result.Verification)
	assert.Equal(t, predicate.Key.Method, result.Key.Method)
	assert.Equal(t, predicate.Key.DiscoveryURL, result.Key.DiscoveryURL)
}

func TestPredicate_VerificationStates(t *testing.T) {
	tests := []struct {
		name         string
		verification string
		hasKey       bool
	}{
		{
			name:         "Verified",
			verification: "verified",
			hasKey:       true,
		},
		{
			name:         "Unverified",
			verification: "unverified",
			hasKey:       true,
		},
		{
			name:         "Skipped",
			verification: "skipped",
			hasKey:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := Predicate{
				Source:       "test-source",
				Digest:       "sha256:test",
				Verification: tt.verification,
			}

			if tt.hasKey {
				predicate.Key = &Key{
					Method:     "jwks",
					Source:     "https://example.com/jwks.json",
					VerifiedAt: time.Now(),
				}
			}

			data, err := json.Marshal(predicate)
			require.NoError(t, err)

			var result Predicate
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.verification, result.Verification)
			if tt.hasKey {
				assert.NotNil(t, result.Key)
			}
		})
	}
}

func TestKey_Methods(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		discoveryURL string
	}{
		{
			name:   "Static Key",
			method: "static-key",
		},
		{
			name:   "JWKS",
			method: "jwks",
		},
		{
			name:         "OIDC Discovery",
			method:       "oidc-discovery",
			discoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := Key{
				Method:       tt.method,
				Source:       "https://example.com/keys",
				DiscoveryURL: tt.discoveryURL,
				VerifiedAt:   time.Now(),
			}

			data, err := json.Marshal(key)
			require.NoError(t, err)

			var result Key
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.method, result.Method)
			assert.Equal(t, tt.discoveryURL, result.DiscoveryURL)
		})
	}
}

func TestJWTHeader_Algorithms(t *testing.T) {
	algorithms := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			header := JWTHeader{
				Algorithm: alg,
				Type:      "JWT",
			}

			data, err := json.Marshal(header)
			require.NoError(t, err)

			var result JWTHeader
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, alg, result.Algorithm)
		})
	}
}

func TestJWTClaims_CustomClaims(t *testing.T) {
	claims := JWTClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user@example.com",
		CustomClaims: map[string]any{
			"string_claim": "value",
			"number_claim": 42,
			"bool_claim":   true,
			"array_claim":  []string{"a", "b", "c"},
			"nested_claim": map[string]any{
				"sub_field": "sub_value",
			},
		},
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var result JWTClaims
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "value", result.CustomClaims["string_claim"])
	assert.InDelta(t, 42.0, result.CustomClaims["number_claim"], 0.001)
	assert.Equal(t, true, result.CustomClaims["bool_claim"])
}

func TestJWTHeader_X5CChain(t *testing.T) {
	certs := []string{
		"MIIC...cert1",
		"MIIC...cert2",
		"MIIC...cert3",
	}

	header := JWTHeader{
		Algorithm: "RS256",
		Type:      "JWT",
		X5C:       certs,
	}

	data, err := json.Marshal(header)
	require.NoError(t, err)

	var result JWTHeader
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Len(t, result.X5C, 3)
	assert.Equal(t, certs, result.X5C)
}

func TestPredicate_SourceFormats(t *testing.T) {
	sources := []string{
		"file:/path/to/token.jwt",
		"env:JWT_TOKEN",
		"stdin",
		"https://example.com/token",
	}

	for _, source := range sources {
		t.Run(source, func(t *testing.T) {
			predicate := Predicate{
				Source:       source,
				Digest:       "sha256:test",
				Verification: "skipped",
			}

			data, err := json.Marshal(predicate)
			require.NoError(t, err)

			var result Predicate
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, source, result.Source)
		})
	}
}

func TestJWTClaims_EmptyCustomClaims(t *testing.T) {
	claims := JWTClaims{
		Issuer:       "https://issuer.example.com",
		Subject:      "user@example.com",
		CustomClaims: make(map[string]any),
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var result JWTClaims
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, claims.Issuer, result.Issuer)
}

func TestKey_TimeFormats(t *testing.T) {
	tests := []struct {
		name     string
		jsonTime string
		valid    bool
	}{
		{
			name:     "RFC3339 format",
			jsonTime: `{"method":"jwks","source":"test","verified_at":"2025-11-12T10:00:00Z"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with timezone",
			jsonTime: `{"method":"jwks","source":"test","verified_at":"2025-11-12T10:00:00+05:30"}`,
			valid:    true,
		},
		{
			name:     "RFC3339 with nanoseconds",
			jsonTime: `{"method":"jwks","source":"test","verified_at":"2025-11-12T10:00:00.123456Z"}`,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var k Key
			err := json.Unmarshal([]byte(tt.jsonTime), &k)

			if tt.valid {
				require.NoError(t, err)
				assert.False(t, k.VerifiedAt.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestPredicate_MinimalValid(t *testing.T) {
	predicate := Predicate{
		Source:       "stdin",
		Digest:       "sha256:minimal",
		Verification: "skipped",
	}

	data, err := json.Marshal(predicate)
	require.NoError(t, err)

	var result Predicate
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "stdin", result.Source)
	assert.Equal(t, "sha256:minimal", result.Digest)
	assert.Equal(t, "skipped", result.Verification)
}
