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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNew(t *testing.T) {
	client, err := New(t.Context())
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNewWithOptions(t *testing.T) {
	client, err := New(t.Context(),
		WithLogger(logger.NewNoop()),
		WithJWKSURL("https://example.com/.well-known/jwks.json"),
		WithHTTPTimeout(10*time.Second),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestParseToken_ValidRS256(t *testing.T) {
	// Create a valid RS256 token
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := createTestToken(t, privateKey, "RS256", map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "user123",
		"aud": "client123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	info, err := client.ParseToken(token)
	require.NoError(t, err)
	assert.Equal(t, "RS256", info.Header.Algorithm)
	assert.Equal(t, "https://issuer.example.com", info.Claims.Issuer)
	assert.Equal(t, "user123", info.Claims.Subject)
}

func TestParseToken_ValidES256(t *testing.T) {
	// Create a valid ES256 token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := createTestToken(t, privateKey, "ES256", map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "user456",
	})

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	info, err := client.ParseToken(token)
	require.NoError(t, err)
	assert.Equal(t, "ES256", info.Header.Algorithm)
	assert.Equal(t, "https://issuer.example.com", info.Claims.Issuer)
	assert.Equal(t, "user456", info.Claims.Subject)
}

func TestParseToken_CustomClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := createTestToken(t, privateKey, "RS256", map[string]any{
		"iss":    "https://issuer.example.com",
		"sub":    "user123",
		"roles":  []string{"admin", "user"},
		"tenant": "acme-corp",
	})

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	info, err := client.ParseToken(token)
	require.NoError(t, err)
	assert.Contains(t, info.Claims.CustomClaims, "roles")
	assert.Contains(t, info.Claims.CustomClaims, "tenant")
}

func TestParseToken_EmptyToken(t *testing.T) {
	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	_, err = client.ParseToken("")
	assert.ErrorIs(t, err, ErrEmptyToken)
}

func TestParseToken_InvalidFormat(t *testing.T) {
	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	_, err = client.ParseToken("not.a.valid.token")
	assert.Error(t, err)
}

func TestHashToken(t *testing.T) {
	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	hash := client.HashToken("test-token")
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA256 produces 64 hex characters

	// Same token should produce same hash
	hash2 := client.HashToken("test-token")
	assert.Equal(t, hash, hash2)

	// Different token should produce different hash
	hash3 := client.HashToken("different-token")
	assert.NotEqual(t, hash, hash3)
}

func TestValidateAlgorithm_AllowedAlgorithm(t *testing.T) {
	client, err := New(t.Context(),
		WithLogger(logger.NewNoop()),
		WithAllowedAlgorithms([]string{"RS256", "ES256"}),
		WithDeniedAlgorithms([]string{"none"}),
	)
	require.NoError(t, err)

	err = client.ValidateAlgorithm("RS256")
	require.NoError(t, err)

	err = client.ValidateAlgorithm("ES256")
	require.NoError(t, err)
}

func TestValidateAlgorithm_DeniedAlgorithm(t *testing.T) {
	client, err := New(t.Context(),
		WithLogger(logger.NewNoop()),
		WithDeniedAlgorithms([]string{"none", "HS256"}),
	)
	require.NoError(t, err)

	err = client.ValidateAlgorithm("none")
	require.ErrorIs(t, err, ErrAlgorithmDenied)

	err = client.ValidateAlgorithm("HS256")
	assert.ErrorIs(t, err, ErrAlgorithmDenied)
}

func TestValidateAlgorithm_NotInAllowedList(t *testing.T) {
	client, err := New(t.Context(),
		WithLogger(logger.NewNoop()),
		WithAllowedAlgorithms([]string{"RS256", "ES256"}),
	)
	require.NoError(t, err)

	err = client.ValidateAlgorithm("PS256")
	assert.ErrorIs(t, err, ErrAlgorithmNotAllowed)
}

func TestFetchJWKS_Success(t *testing.T) {
	// Create a test JWKS server
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key, err := jwk.FromRaw(privateKey.Public())
	require.NoError(t, err)
	_ = key.Set(jwk.KeyIDKey, "test-key-id")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)

	keySet := jwk.NewSet()
	_ = keySet.AddKey(key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keySet)
	}))
	defer server.Close()

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	fetchedSet, err := client.FetchJWKS(t.Context(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, 1, fetchedSet.Len())
}

func TestFetchJWKS_EmptySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	_, err = client.FetchJWKS(t.Context(), server.URL)
	assert.ErrorIs(t, err, ErrNoKeysInJWKS)
}

func TestLoadPublicKey_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyFile := createTempPublicKeyFile(t, privateKey.Public())
	defer func() { _ = os.Remove(keyFile) }()

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	publicKey, err := client.LoadPublicKey(keyFile)
	require.NoError(t, err)
	assert.NotNil(t, publicKey)
}

func TestLoadPublicKey_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyFile := createTempPublicKeyFile(t, privateKey.Public())
	defer func() { _ = os.Remove(keyFile) }()

	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	publicKey, err := client.LoadPublicKey(keyFile)
	require.NoError(t, err)
	assert.NotNil(t, publicKey)
}

func TestLoadPublicKey_NotFound(t *testing.T) {
	client, err := New(t.Context(), WithLogger(logger.NewNoop()))
	require.NoError(t, err)

	_, err = client.LoadPublicKey("/nonexistent/path/key.pem")
	assert.Error(t, err)
}

func TestMockClient(t *testing.T) {
	mockClient := NewMockClient()

	expectedInfo := &TokenInfo{
		Header: Header{Algorithm: "RS256"},
		Claims: Claims{Issuer: "test-issuer"},
	}

	mockClient.On("ParseToken", "test-token").Return(expectedInfo, nil)
	mockClient.On("HashToken", "test-token").Return("abc123")
	mockClient.On("ValidateAlgorithm", "RS256").Return(nil)

	info, err := mockClient.ParseToken("test-token")
	require.NoError(t, err)
	assert.Equal(t, "RS256", info.Header.Algorithm)

	hash := mockClient.HashToken("test-token")
	assert.Equal(t, "abc123", hash)

	err = mockClient.ValidateAlgorithm("RS256")
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestMockClientWithAnyArgs(t *testing.T) {
	mockClient := NewMockClient()

	expectedInfo := &TokenInfo{
		Header: Header{Algorithm: "ES256"},
		Claims: Claims{Subject: "user123"},
	}

	mockClient.On("ParseToken", mock.Anything).Return(expectedInfo, nil)
	mockClient.On("FindKey", mock.Anything, mock.Anything).Return(&KeyInfo{Method: "jwks"}, nil)

	info, _ := mockClient.ParseToken("any-token")
	assert.Equal(t, "ES256", info.Header.Algorithm)

	keyInfo, _ := mockClient.FindKey(t.Context(), "any-token")
	assert.Equal(t, "jwks", keyInfo.Method)

	mockClient.AssertExpectations(t)
}

// Helper functions for tests

func createTestToken(t *testing.T, privateKey any, algorithm string, claims map[string]any) string {
	t.Helper()

	alg := jwa.SignatureAlgorithm(algorithm)
	builder := jwt.NewBuilder()

	for key, value := range claims {
		switch key {
		case "iss":
			v, _ := value.(string)
			builder = builder.Issuer(v)
		case "sub":
			v, _ := value.(string)
			builder = builder.Subject(v)
		case "aud":
			v, _ := value.(string)
			builder = builder.Audience([]string{v})
		case "exp":
			v, _ := value.(int64)
			builder = builder.Expiration(time.Unix(v, 0))
		case "iat":
			v, _ := value.(int64)
			builder = builder.IssuedAt(time.Unix(v, 0))
		default:
			builder = builder.Claim(key, value)
		}
	}

	token, err := builder.Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(token, jwt.WithKey(alg, privateKey))
	require.NoError(t, err)

	return string(signed)
}

func createTempPublicKeyFile(t *testing.T, publicKey any) string {
	t.Helper()

	key, err := jwk.FromRaw(publicKey)
	require.NoError(t, err)

	pem, err := jwk.Pem(key)
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp(t.TempDir(), "public-key-*.pem")
	require.NoError(t, err)

	_, err = tmpFile.Write(pem)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}
