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

package githubworkflow

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/logger"
	ghworkflowpredicate "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

func TestFetchAndVerifyOIDCToken_OIDCEnvNotAvailable(t *testing.T) {
	// Clear OIDC env vars so IsOIDCEnvAvailable returns false
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")

	github.SetupMockClient(t)
	jwtclient.SetupMockClient(t)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	assert.Nil(t, oidcInfo)
	assert.Nil(t, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC environment not detected")
}

func TestFetchAndVerifyOIDCToken_FetchIDTokenError(t *testing.T) {
	setupRequiredOIDCEnv(t)

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return("", errors.New("network timeout"))
	jwtclient.SetupMockClient(t)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	assert.Nil(t, oidcInfo)
	assert.Nil(t, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch OIDC token")
}

func TestFetchAndVerifyOIDCToken_ParseTokenError(t *testing.T) {
	setupRequiredOIDCEnv(t)

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return("bad-token", nil)

	mockJWT := jwtclient.SetupMockClient(t)
	mockJWT.On("HashToken", "bad-token").Return("hash-of-bad")
	mockJWT.On("ParseToken", "bad-token").
		Return(nil, errors.New("invalid JWT format"))

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	assert.Nil(t, oidcInfo)
	assert.Nil(t, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse OIDC token")
}

func TestFetchAndVerifyOIDCToken_VerifySignatureError(t *testing.T) {
	setupRequiredOIDCEnv(t)

	mockToken := "header.payload.signature"

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return(mockToken, nil)

	tokenInfo := &jwtclient.TokenInfo{
		Claims: jwtclient.Claims{
			Issuer:       DefaultOIDCIssuer,
			Subject:      "repo:owner/repo:ref:refs/heads/main",
			CustomClaims: map[string]any{"workflow": "test"},
		},
	}

	mockJWT := jwtclient.SetupMockClient(t)
	mockJWT.On("HashToken", mockToken).Return("hash")
	mockJWT.On("ParseToken", mockToken).Return(tokenInfo, nil)
	mockJWT.On("VerifySignature", mock.Anything, mockToken).
		Return(nil, errors.New("JWKS fetch failed"))

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	assert.Nil(t, oidcInfo)
	assert.Nil(t, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token verification failed")
}

func TestFetchAndVerifyOIDCToken_AudienceMismatch(t *testing.T) {
	setupRequiredOIDCEnv(t)

	mockToken := "header.payload.signature"

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return(mockToken, nil)

	tokenInfo := &jwtclient.TokenInfo{
		Claims: jwtclient.Claims{
			Issuer:       DefaultOIDCIssuer,
			Audience:     "https://evil.example.com",
			Subject:      "repo:owner/repo:ref:refs/heads/main",
			CustomClaims: map[string]any{"workflow": "test"},
		},
	}

	verifyResult := &jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
		KeyID:      "key-1",
	}

	mockJWT := jwtclient.SetupMockClient(t)
	mockJWT.On("HashToken", mockToken).Return("hash")
	mockJWT.On("ParseToken", mockToken).Return(tokenInfo, nil)
	mockJWT.On("VerifySignature", mock.Anything, mockToken).Return(verifyResult, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	assert.Nil(t, oidcInfo)
	assert.Nil(t, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestFetchAndVerifyOIDCToken_AudienceMismatch_StringSlice(t *testing.T) {
	setupRequiredOIDCEnv(t)

	mockToken := "header.payload.signature"

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return(mockToken, nil)

	tokenInfo := &jwtclient.TokenInfo{
		Claims: jwtclient.Claims{
			Issuer:       DefaultOIDCIssuer,
			Audience:     []string{"https://other.example.com", "https://evil.example.com"},
			Subject:      "repo:owner/repo:ref:refs/heads/main",
			CustomClaims: map[string]any{"workflow": "test"},
		},
	}

	verifyResult := &jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
		KeyID:      "key-1",
	}

	mockJWT := jwtclient.SetupMockClient(t)
	mockJWT.On("HashToken", mockToken).Return("hash")
	mockJWT.On("ParseToken", mockToken).Return(tokenInfo, nil)
	mockJWT.On("VerifySignature", mock.Anything, mockToken).Return(verifyResult, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	assert.Nil(t, oidcInfo)
	assert.Nil(t, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestAudienceContains(t *testing.T) {
	tests := []struct {
		name     string
		aud      any
		expected string
		want     bool
	}{
		{"string match", "https://github.com", "https://github.com", true},
		{"string mismatch", "https://evil.com", "https://github.com", false},
		{"slice contains", []string{"https://a.com", "https://github.com"}, "https://github.com", true},
		{"slice missing", []string{"https://a.com", "https://b.com"}, "https://github.com", false},
		{"empty slice", []string{}, "https://github.com", false},
		{"nil", nil, "https://github.com", false},
		{"unexpected type", 42, "https://github.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, utils.AudienceContains(tt.aud, tt.expected))
		})
	}
}

func TestVerifyOIDCToken_UntrustedIssuer(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: "https://evil-issuer.com"},
	}, nil)

	result, err := utils.VerifyOIDCToken(t.Context(), mockJWT, "token", utils.OIDCVerifyOptions{
		TrustedIssuers: []string{DefaultOIDCIssuer},
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted OIDC issuer")
}

func TestVerifyOIDCToken_SignatureVerificationFails(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: DefaultOIDCIssuer},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").
		Return(nil, errors.New("key not found in JWKS"))

	result, err := utils.VerifyOIDCToken(t.Context(), mockJWT, "token", utils.OIDCVerifyOptions{
		TrustedIssuers: []string{DefaultOIDCIssuer},
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyOIDCToken_SignatureInvalid(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: DefaultOIDCIssuer},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").
		Return(&jwtclient.VerificationResult{Verified: false}, nil)

	result, err := utils.VerifyOIDCToken(t.Context(), mockJWT, "token", utils.OIDCVerifyOptions{
		TrustedIssuers: []string{DefaultOIDCIssuer},
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token signature is invalid")
}

func TestVerifyOIDCToken_Success(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: DefaultOIDCIssuer},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").Return(&jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
		KeyID:      "key-1",
		Algorithm:  "RS256",
		Method:     "jwks",
		Source:     DefaultOIDCIssuer,
	}, nil)

	result, err := utils.VerifyOIDCToken(t.Context(), mockJWT, "token", utils.OIDCVerifyOptions{
		TrustedIssuers: []string{DefaultOIDCIssuer},
	})
	require.NoError(t, err)
	assert.True(t, result.Verification.Verified)
	assert.Equal(t, "RS256", result.Verification.Algorithm)
}

func TestVerifyOIDCToken_NoIssuerList_SkipsValidation(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: "https://any-issuer.example.com"},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").Return(&jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
	}, nil)

	// Empty TrustedIssuers skips issuer validation
	result, err := utils.VerifyOIDCToken(t.Context(), mockJWT, "token", utils.OIDCVerifyOptions{})
	require.NoError(t, err)
	assert.True(t, result.Verification.Verified)
}

func TestFetchAndVerifyOIDCToken_Success(t *testing.T) {
	setupRequiredOIDCEnv(t)
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")

	mockToken := "header.payload.signature"

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return(mockToken, nil)

	tokenInfo := &jwtclient.TokenInfo{
		Header: jwtclient.Header{KeyID: "key-123"},
		Claims: jwtclient.Claims{
			Issuer:    DefaultOIDCIssuer,
			Audience:  "https://github.com",
			Subject:   "repo:owner/repo:ref:refs/heads/main",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			JWTID:     "jwt-id-abc",
			CustomClaims: map[string]any{
				"workflow":   "CI",
				"run_id":     "999",
				"repository": "owner/repo",
			},
		},
	}

	verifyResult := &jwtclient.VerificationResult{
		Verified:     true,
		VerifiedAt:   time.Now(),
		KeyID:        "key-123",
		Algorithm:    "RS256",
		Method:       "oidc-discovery",
		Source:       "https://token.actions.githubusercontent.com/.well-known/jwks",
		DiscoveryURL: "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
	}

	mockJWT := jwtclient.SetupMockClient(t)
	mockJWT.On("HashToken", mockToken).Return("sha256-hash")
	mockJWT.On("ParseToken", mockToken).Return(tokenInfo, nil)
	mockJWT.On("VerifySignature", mock.Anything, mockToken).Return(verifyResult, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	require.NoError(t, err)
	require.NotNil(t, oidcInfo)
	require.NotNil(t, claims)

	// Verify OIDCInfo fields
	assert.Equal(t, "sha256-hash", oidcInfo.TokenHash)
	assert.Equal(t, DefaultOIDCIssuer, oidcInfo.Issuer)
	assert.Equal(t, "repo:owner/repo:ref:refs/heads/main", oidcInfo.Subject)
	assert.Equal(t, "https://github.com", oidcInfo.Audience)
	assert.Equal(t, "jwt-id-abc", oidcInfo.JWTID)
	assert.Equal(t, "key-123", oidcInfo.KeyID)
	assert.True(t, oidcInfo.Verified)
	assert.Equal(t, "oidc-discovery", oidcInfo.VerifyMethod)
	assert.Equal(t, "RS256", oidcInfo.KeyAlgorithm)
	assert.NotZero(t, oidcInfo.FetchedAt)
	assert.NotZero(t, oidcInfo.VerifiedAt)

	// Verify custom claims returned
	assert.Equal(t, "CI", claims["workflow"])
	assert.Equal(t, "999", claims["run_id"])
	assert.Equal(t, "owner/repo", claims["repository"])
}

func TestFetchAndVerifyOIDCToken_AudienceSliceMatch(t *testing.T) {
	setupRequiredOIDCEnv(t)
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")

	mockToken := "header.payload.signature"

	mockGH := github.SetupMockClient(t)
	mockGH.On("FetchIDToken", mock.Anything, "https://github.com").
		Return(mockToken, nil)

	tokenInfo := &jwtclient.TokenInfo{
		Claims: jwtclient.Claims{
			Issuer:       DefaultOIDCIssuer,
			Audience:     []string{"https://other.example.com", "https://github.com"},
			Subject:      "repo:owner/repo:ref:refs/heads/main",
			CustomClaims: map[string]any{"workflow": "test"},
		},
	}

	verifyResult := &jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
		KeyID:      "key-1",
	}

	mockJWT := jwtclient.SetupMockClient(t)
	mockJWT.On("HashToken", mockToken).Return("hash")
	mockJWT.On("ParseToken", mockToken).Return(tokenInfo, nil)
	mockJWT.On("VerifySignature", mock.Anything, mockToken).Return(verifyResult, nil)

	attestor := &Attestor{
		logger: logger.NewNoop(),
	}
	err := attestor.PreAttest(t.Context(), nil)
	require.NoError(t, err)

	oidcInfo, claims, err := attestor.fetchAndVerifyOIDCToken(t.Context())
	require.NoError(t, err)
	require.NotNil(t, oidcInfo)
	require.NotNil(t, claims)

	// Audience is []string and contains the expected value
	assert.Equal(t, []string{"https://other.example.com", "https://github.com"}, oidcInfo.Audience)
	assert.True(t, oidcInfo.Verified)
}

func TestOIDCInfo_OmitEmptyFields(t *testing.T) {
	// OIDCInfo with only required fields set; optional fields should be omitted from JSON
	info := &ghworkflowpredicate.OIDCInfo{
		TokenHash: "abc123",
		Issuer:    DefaultOIDCIssuer,
		Subject:   "repo:owner/repo:ref:refs/heads/main",
		Audience:  "https://github.com",
		Verified:  true,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var m map[string]any
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	// Required fields present
	assert.Contains(t, m, "token_hash")
	assert.Contains(t, m, "issuer")
	assert.Contains(t, m, "subject")
	assert.Contains(t, m, "audience")
	assert.Contains(t, m, "verified")

	// omitempty fields absent when zero
	assert.NotContains(t, m, "expires_at")
	assert.NotContains(t, m, "issued_at")
	assert.NotContains(t, m, "not_before")
	assert.NotContains(t, m, "jwt_id")
	assert.NotContains(t, m, "verified_at")
	assert.NotContains(t, m, "verify_method")
	assert.NotContains(t, m, "verify_source")
	assert.NotContains(t, m, "key_algorithm")
	assert.NotContains(t, m, "key_id")
	assert.NotContains(t, m, "discovery_url")
	assert.NotContains(t, m, "fetched_at")
}

func TestResolveOIDCIssuers(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      []string
	}{
		{
			name:      "empty env returns default issuer",
			serverURL: "",
			want:      []string{DefaultOIDCIssuer},
		},
		{
			name:      "github.com returns default issuer",
			serverURL: "https://github.com",
			want:      []string{DefaultOIDCIssuer},
		},
		{
			name:      "GHES URL returns default plus derived",
			serverURL: "https://github.enterprise.com",
			want:      []string{DefaultOIDCIssuer, "https://github.enterprise.com/_services/token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_SERVER_URL", tt.serverURL)
			a := &Attestor{
				logger: logger.NewNoop(),
			}
			assert.Equal(t, tt.want, a.resolveOIDCIssuers())
		})
	}
}
