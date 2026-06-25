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

package fulcio

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestToken creates a JWT token string with the given claims.
// Note: This creates an unsigned token for testing purposes.
func createTestToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

func TestExtractTokenSubject_Success(t *testing.T) {
	expectedSubject := "user@example.com"
	tokenString := createTestToken(t, jwt.MapClaims{
		"sub": expectedSubject,
		"iss": "https://issuer.example.com",
		"aud": "fulcio",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	subject, err := extractTokenSubject(tokenString)

	require.NoError(t, err)
	assert.Equal(t, expectedSubject, subject)
}

func TestExtractTokenSubject_WithSPIFFEID(t *testing.T) {
	expectedSubject := "spiffe://example.org/workload"
	tokenString := createTestToken(t, jwt.MapClaims{
		"sub": expectedSubject,
		"iss": "https://spire.example.org",
	})

	subject, err := extractTokenSubject(tokenString)

	require.NoError(t, err)
	assert.Equal(t, expectedSubject, subject)
}

func TestExtractTokenSubject_WithGitHubSubject(t *testing.T) {
	expectedSubject := "repo:owner/repo:ref:refs/heads/main"
	tokenString := createTestToken(t, jwt.MapClaims{
		"sub": expectedSubject,
		"iss": "https://token.actions.githubusercontent.com",
		"aud": "sigstore",
	})

	subject, err := extractTokenSubject(tokenString)

	require.NoError(t, err)
	assert.Equal(t, expectedSubject, subject)
}

func TestExtractTokenSubject_EmptySubject(t *testing.T) {
	tokenString := createTestToken(t, jwt.MapClaims{
		"sub": "",
		"iss": "https://issuer.example.com",
	})

	subject, err := extractTokenSubject(tokenString)

	require.Error(t, err)
	assert.Empty(t, subject)
	assert.Contains(t, err.Error(), "no subject claim found")
}

func TestExtractTokenSubject_MissingSubject(t *testing.T) {
	tokenString := createTestToken(t, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": "fulcio",
	})

	subject, err := extractTokenSubject(tokenString)

	require.Error(t, err)
	assert.Empty(t, subject)
	assert.Contains(t, err.Error(), "no subject claim found")
}

func TestExtractTokenSubject_InvalidToken(t *testing.T) {
	subject, err := extractTokenSubject("not-a-valid-jwt")

	require.Error(t, err)
	assert.Empty(t, subject)
}

func TestExtractTokenSubject_EmptyToken(t *testing.T) {
	subject, err := extractTokenSubject("")

	require.Error(t, err)
	assert.Empty(t, subject)
}

func TestExtractTokenSubject_MalformedToken(t *testing.T) {
	// Token with only two parts instead of three
	subject, err := extractTokenSubject("header.payload")

	require.Error(t, err)
	assert.Empty(t, subject)
}

func TestExtractTokenSubject_InvalidBase64Payload(t *testing.T) {
	// Token with invalid base64 in payload
	subject, err := extractTokenSubject("eyJhbGciOiJub25lIn0.!!!invalid-base64!!!.signature")

	require.Error(t, err)
	assert.Empty(t, subject)
}

func TestExtractTokenSubject_InvalidJSONPayload(t *testing.T) {
	// Token with valid base64 but invalid JSON
	// "not json" in base64 is "bm90IGpzb24"
	subject, err := extractTokenSubject("eyJhbGciOiJub25lIn0.bm90IGpzb24.signature")

	require.Error(t, err)
	assert.Empty(t, subject)
}

func TestExtractTokenSubject_WithAdditionalClaims(t *testing.T) {
	expectedSubject := "test@example.com"
	tokenString := createTestToken(t, jwt.MapClaims{
		"sub":   expectedSubject,
		"iss":   "https://issuer.example.com",
		"aud":   []string{"fulcio", "other-audience"},
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nbf":   time.Now().Unix(),
		"email": "test@example.com",
		"custom_claim": map[string]any{
			"nested": "value",
		},
	})

	subject, err := extractTokenSubject(tokenString)

	require.NoError(t, err)
	assert.Equal(t, expectedSubject, subject)
}
