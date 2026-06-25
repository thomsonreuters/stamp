// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
)

func TestValidateIssuer(t *testing.T) {
	tests := []struct {
		name           string
		issuer         string
		allowedIssuers []string
		wantErr        bool
		errContains    string
	}{
		{
			name:           "nil allowed list skips validation",
			issuer:         "https://any-issuer.com",
			allowedIssuers: nil,
			wantErr:        false,
		},
		{
			name:           "empty allowed list skips validation",
			issuer:         "https://any-issuer.com",
			allowedIssuers: []string{},
			wantErr:        false,
		},
		{
			name:           "issuer in allowed list",
			issuer:         "https://token.actions.githubusercontent.com",
			allowedIssuers: []string{"https://token.actions.githubusercontent.com"},
			wantErr:        false,
		},
		{
			name:           "issuer in multi-item allowed list",
			issuer:         "https://ghes.corp.com/_services/token",
			allowedIssuers: []string{"https://token.actions.githubusercontent.com", "https://ghes.corp.com/_services/token"},
			wantErr:        false,
		},
		{
			name:           "issuer not in allowed list",
			issuer:         "https://evil.com",
			allowedIssuers: []string{"https://token.actions.githubusercontent.com"},
			wantErr:        true,
			errContains:    "untrusted OIDC issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIssuer(tt.issuer, tt.allowedIssuers)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
			assert.Equal(t, tt.want, AudienceContains(tt.aud, tt.expected))
		})
	}
}

func TestVerifyOIDCToken_Success(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("sha256-hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Header: jwtclient.Header{KeyID: "key-1", Algorithm: "RS256"},
		Claims: jwtclient.Claims{
			Issuer:   "https://token.actions.githubusercontent.com",
			Subject:  "repo:org/repo:ref:refs/heads/main",
			Audience: "https://github.com",
		},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").Return(&jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
		Algorithm:  "RS256",
		Method:     "oidc-discovery",
	}, nil)

	result, err := VerifyOIDCToken(context.Background(), mockJWT, "token", OIDCVerifyOptions{
		TrustedIssuers:   []string{"https://token.actions.githubusercontent.com"},
		ExpectedAudience: "https://github.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "sha256-hash", result.TokenHash)
	assert.True(t, result.Verification.Verified)
	assert.Equal(t, "RS256", result.Verification.Algorithm)
}

func TestVerifyOIDCToken_UntrustedIssuer(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: "https://evil.com"},
	}, nil)

	result, err := VerifyOIDCToken(context.Background(), mockJWT, "token", OIDCVerifyOptions{
		TrustedIssuers: []string{"https://token.actions.githubusercontent.com"},
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted OIDC issuer")
}

func TestVerifyOIDCToken_SignatureFails(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{Issuer: "https://issuer.example.com"},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").
		Return(nil, errors.New("key not found"))

	result, err := VerifyOIDCToken(context.Background(), mockJWT, "token", OIDCVerifyOptions{
		TrustedIssuers: []string{"https://issuer.example.com"},
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyOIDCToken_AudienceMismatch(t *testing.T) {
	mockJWT := &jwtclient.MockClient{}
	mockJWT.On("HashToken", "token").Return("hash")
	mockJWT.On("ParseToken", "token").Return(&jwtclient.TokenInfo{
		Claims: jwtclient.Claims{
			Issuer:   "https://issuer.example.com",
			Audience: "https://wrong.com",
		},
	}, nil)
	mockJWT.On("VerifySignature", mock.Anything, "token").Return(&jwtclient.VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now(),
	}, nil)

	result, err := VerifyOIDCToken(context.Background(), mockJWT, "token", OIDCVerifyOptions{
		ExpectedAudience: "https://expected.com",
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
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

	result, err := VerifyOIDCToken(context.Background(), mockJWT, "token", OIDCVerifyOptions{})
	require.NoError(t, err)
	assert.True(t, result.Verification.Verified)
}
