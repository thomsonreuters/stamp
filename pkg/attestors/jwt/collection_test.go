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

package jwt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestCollectData_SkipVerification(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	tokenPath := createTokenFile(t, validToken)

	mockClient := jwtclient.SetupMockClient(t)
	mockClient.On("HashToken", mock.Anything).Return("sha256:abc123")
	mockClient.On("ParseToken", mock.Anything).Return(&jwtclient.TokenInfo{
		Header: jwtclient.Header{
			Algorithm: "RS256",
			Type:      "JWT",
		},
		Claims: jwtclient.Claims{
			Subject: "test-subject",
			Issuer:  "test-issuer",
		},
	}, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			TokenFile:        tokenPath,
			SkipVerification: true,
		},
	}

	predicate, err := attestor.collectData(t.Context(), core.Config{})

	require.NoError(t, err)
	assert.NotNil(t, predicate)
	assert.Equal(t, VerificationSkipped, predicate.Verification)
	assert.Equal(t, "RS256", predicate.Header.Algorithm)
	assert.Equal(t, "test-subject", predicate.Claims.Subject)
}

func TestCollectData_WithVerification(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	tokenPath := createTokenFile(t, validToken)

	mockClient := jwtclient.SetupMockClient(t)
	mockClient.On("HashToken", mock.Anything).Return("sha256:abc123")
	mockClient.On("ParseToken", mock.Anything).Return(&jwtclient.TokenInfo{
		Header: jwtclient.Header{
			Algorithm: "RS256",
			Type:      "JWT",
		},
		Claims: jwtclient.Claims{
			Subject: "test-subject",
			Issuer:  "test-issuer",
		},
	}, nil)
	mockClient.On("ValidateAlgorithm", "RS256").Return(nil)
	mockClient.On("VerifySignature", mock.Anything, mock.Anything).Return(&jwtclient.VerificationResult{
		Verified: true,
		Method:   "jwks",
		Source:   "https://example.com/jwks",
	}, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			TokenFile:        tokenPath,
			SkipVerification: false,
		},
	}

	predicate, err := attestor.collectData(t.Context(), core.Config{})

	require.NoError(t, err)
	assert.NotNil(t, predicate)
	assert.Equal(t, VerificationVerified, predicate.Verification)
	assert.NotNil(t, predicate.Key)
	assert.Equal(t, "jwks", predicate.Key.Method)
}

func TestCollectData_VerificationFailed(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	tokenPath := createTokenFile(t, validToken)

	mockClient := jwtclient.SetupMockClient(t)
	mockClient.On("HashToken", mock.Anything).Return("sha256:abc123")
	mockClient.On("ParseToken", mock.Anything).Return(&jwtclient.TokenInfo{
		Header: jwtclient.Header{
			Algorithm: "RS256",
			Type:      "JWT",
		},
		Claims: jwtclient.Claims{
			Subject: "test-subject",
		},
	}, nil)
	mockClient.On("ValidateAlgorithm", "RS256").Return(nil)
	mockClient.On("VerifySignature", mock.Anything, mock.Anything).Return(&jwtclient.VerificationResult{
		Verified: false,
		Method:   "jwks",
	}, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			TokenFile:        tokenPath,
			SkipVerification: false,
		},
	}

	predicate, err := attestor.collectData(t.Context(), core.Config{})

	require.NoError(t, err)
	assert.NotNil(t, predicate)
	assert.Equal(t, VerificationUnverified, predicate.Verification)
}

func TestFilterClaims_IncludeAll(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: true,
		},
	}

	claims := map[string]any{
		"custom1": "value1",
		"custom2": "value2",
	}

	result := attestor.filterClaims(claims)
	assert.Equal(t, claims, result)
}

func TestFilterClaims_Allowlist(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: false,
			ClaimsAllowlist:  []string{"custom1"},
		},
	}

	claims := map[string]any{
		"custom1": "value1",
		"custom2": "value2",
	}

	result := attestor.filterClaims(claims)
	assert.Len(t, result, 1)
	assert.Equal(t, "value1", result["custom1"])
	assert.NotContains(t, result, "custom2")
}

func TestFilterClaims_Denylist(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: true,
			ClaimsDenylist:   []string{"internal"},
		},
	}

	claims := map[string]any{
		"custom1":  "value1",
		"internal": "secret",
	}

	result := attestor.filterClaims(claims)
	assert.Len(t, result, 1)
	assert.Equal(t, "value1", result["custom1"])
	assert.NotContains(t, result, "internal")
}

func TestFilterClaims_Redaction(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: true,
			RedactClaims:     []string{"email"},
		},
	}

	claims := map[string]any{
		"custom1": "value1",
		"email":   "user@example.com",
	}

	result := attestor.filterClaims(claims)
	assert.Len(t, result, 2)
	assert.Equal(t, "value1", result["custom1"])
	assert.Equal(t, "[REDACTED]", result["email"])
}

func TestFilterClaims_CombinedFilters(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: false,
			ClaimsAllowlist:  []string{"custom1", "email"},
			RedactClaims:     []string{"email"},
		},
	}

	claims := map[string]any{
		"custom1":  "value1",
		"custom2":  "value2",
		"email":    "user@example.com",
		"internal": "secret",
	}

	result := attestor.filterClaims(claims)
	assert.Len(t, result, 2)
	assert.Equal(t, "value1", result["custom1"])
	assert.Equal(t, "[REDACTED]", result["email"])
	assert.NotContains(t, result, "custom2")
	assert.NotContains(t, result, "internal")
}

func TestFilterClaims_ExcludeAllNoDenylistNoAllowlist(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: false,
		},
	}

	claims := map[string]any{
		"custom1": "value1",
		"custom2": "value2",
	}

	result := attestor.filterClaims(claims)
	assert.Empty(t, result)
}

func TestFilterClaims_ExcludeAllWithDenylistOnly(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: false,
			ClaimsDenylist:   []string{"internal"},
		},
	}

	claims := map[string]any{
		"custom1":  "value1",
		"internal": "secret",
	}

	result := attestor.filterClaims(claims)
	assert.Len(t, result, 1)
	assert.Equal(t, "value1", result["custom1"])
	assert.NotContains(t, result, "internal")
}

func TestFilterClaims_ExcludeAllWithRedactOnly(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{
			IncludeAllClaims: false,
			RedactClaims:     []string{"email"},
		},
	}

	claims := map[string]any{
		"custom1": "value1",
		"email":   "user@example.com",
	}

	result := attestor.filterClaims(claims)
	assert.Len(t, result, 2)
	assert.Equal(t, "value1", result["custom1"])
	assert.Equal(t, "[REDACTED]", result["email"])
}

func TestConvertHeader(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}

	header := jwtclient.Header{
		Algorithm: "RS256",
		Type:      "JWT",
		KeyID:     "key123",
		X5C:       []string{"cert1", "cert2"},
		X5T:       "thumbprint",
		X5TS256:   "thumbprint256",
	}

	result := attestor.convertHeader(header)

	assert.Equal(t, "RS256", result.Algorithm)
	assert.Equal(t, "JWT", result.Type)
	assert.Equal(t, "key123", result.KeyID)
	assert.Equal(t, []string{"cert1", "cert2"}, result.X5C)
	assert.Equal(t, "thumbprint", result.X5T)
	assert.Equal(t, "thumbprint256", result.X5TS256)
}

func TestConvertClaims(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}

	claims := jwtclient.Claims{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  []string{"aud1", "aud2"},
		ExpiresAt: 1767225599,
		NotBefore: 1704067200,
		IssuedAt:  1704067200,
		JWTID:     "jwt-123",
		CustomClaims: map[string]any{
			"custom": "value",
		},
	}

	result := attestor.convertClaims(claims)

	assert.Equal(t, "test-issuer", result.Issuer)
	assert.Equal(t, "test-subject", result.Subject)
	assert.Equal(t, []string{"aud1", "aud2"}, result.Audience)
	assert.Equal(t, int64(1767225599), result.ExpiresAt)
	assert.Equal(t, "jwt-123", result.JWTID)
	assert.Equal(t, "value", result.CustomClaims["custom"])
}

func TestConvertKeyInfo(t *testing.T) {
	attestor := &Attestor{logger: logger.NewNoop()}

	result := &jwtclient.VerificationResult{
		Verified:     true,
		Method:       "jwks",
		Source:       "https://example.com/jwks",
		DiscoveryURL: "https://example.com/.well-known/openid-configuration",
	}

	keyInfo := attestor.convertKeyInfo(result)

	assert.Equal(t, "jwks", keyInfo.Method)
	assert.Equal(t, "https://example.com/jwks", keyInfo.Source)
	assert.Equal(t, "https://example.com/.well-known/openid-configuration", keyInfo.DiscoveryURL)
	assert.NotZero(t, keyInfo.VerifiedAt)
}

func createTokenFile(t *testing.T, token string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "token")
	err := os.WriteFile(path, []byte(token), 0600)
	require.NoError(t, err)
	return path
}
