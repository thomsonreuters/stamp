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

package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client, err := New(t.Context(), Options{})

	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNew_WithOptions(t *testing.T) {
	opts := Options{
		RequestToken:    "test-token",
		TokenRequestURL: "https://example.com/token",
		Timeout:         60 * time.Second,
	}

	client, err := New(t.Context(), opts)

	require.NoError(t, err)
	assert.NotNil(t, client)

	c, _ := client.(*Client)
	assert.Equal(t, "test-token", c.opts.RequestToken)
	assert.Equal(t, "https://example.com/token", c.opts.TokenRequestURL)
	assert.Equal(t, 60*time.Second, c.opts.Timeout)
}

func TestNew_DefaultTimeout(t *testing.T) {
	client, err := New(t.Context(), Options{
		RequestToken:    "token",
		TokenRequestURL: "url",
	})

	require.NoError(t, err)
	c, _ := client.(*Client)
	assert.Equal(t, DefaultTimeout, c.opts.Timeout)
}

func TestNew_FromEnvironment(t *testing.T) {
	t.Setenv(EnvActionsIDTokenRequestToken, "env-token")
	t.Setenv(EnvActionsIDTokenRequestURL, "https://env-url.com/token")

	client, err := New(t.Context(), Options{})

	require.NoError(t, err)
	c, _ := client.(*Client)
	assert.Equal(t, "env-token", c.opts.RequestToken)
	assert.Equal(t, "https://env-url.com/token", c.opts.TokenRequestURL)
}

func TestClient_FetchIDToken_Success(t *testing.T) {
	expectedToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-payload.signature"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer test-request-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "sigstore", r.URL.Query().Get("audience"))

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(tokenResponse{Value: expectedToken})
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "test-request-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	token, err := client.FetchIDToken(t.Context(), "sigstore")

	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestClient_FetchIDToken_CustomAudience(t *testing.T) {
	expectedToken := "custom-audience-token"
	customAudience := "example-custom-audience"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, customAudience, r.URL.Query().Get("audience"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(tokenResponse{Value: expectedToken})
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "test-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	token, err := client.FetchIDToken(t.Context(), customAudience)

	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestClient_FetchIDToken_DefaultAudience(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Empty audience should default to "sigstore"
		assert.Equal(t, DefaultAudience, r.URL.Query().Get("audience"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(tokenResponse{Value: "token"})
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "test-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	// Pass empty string to test default audience
	_, err = client.FetchIDToken(t.Context(), "")

	require.NoError(t, err)
}

func TestClient_FetchIDToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "test-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "500")
}

func TestClient_FetchIDToken_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid token"}`))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "invalid-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "401")
}

func TestClient_FetchIDToken_EmptyTokenResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(tokenResponse{Value: ""})
		assert.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "test-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "empty token")
}

func TestClient_FetchIDToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		RequestToken:    "test-token",
		TokenRequestURL: server.URL,
	})
	require.NoError(t, err)

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
}

func TestClient_FetchIDToken_MissingConfig(t *testing.T) {
	client := &Client{opts: Options{}}

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "GitHub Actions environment not properly configured")
}

func TestClient_FetchIDToken_MissingRequestToken(t *testing.T) {
	client := &Client{opts: Options{
		TokenRequestURL: "https://example.com/token",
	}}

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "GitHub Actions environment not properly configured")
}

func TestClient_FetchIDToken_MissingRequestURL(t *testing.T) {
	client := &Client{opts: Options{
		RequestToken: "token",
	}}

	token, err := client.FetchIDToken(t.Context(), "audience")

	require.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "GitHub Actions environment not properly configured")
}

func TestClient_IsGitHubActions_True(t *testing.T) {
	t.Setenv(EnvGitHubActions, "true")

	client := &Client{}

	assert.True(t, client.IsGitHubActions())
}

func TestClient_IsGitHubActions_False(t *testing.T) {
	_ = os.Unsetenv(EnvGitHubActions)

	client := &Client{}

	assert.False(t, client.IsGitHubActions())
}

func TestClient_IsGitHubActions_OtherValue(t *testing.T) {
	t.Setenv(EnvGitHubActions, "false")

	client := &Client{}

	assert.False(t, client.IsGitHubActions())
}

func TestIsGitHubActionsEnv_True(t *testing.T) {
	t.Setenv(EnvGitHubActions, "true")

	assert.True(t, IsGitHubActionsEnv())
}

func TestIsGitHubActionsEnv_False(t *testing.T) {
	_ = os.Unsetenv(EnvGitHubActions)

	assert.False(t, IsGitHubActionsEnv())
}

func TestIsGitHubActionsEnv_OtherValue(t *testing.T) {
	t.Setenv(EnvGitHubActions, "false")

	assert.False(t, IsGitHubActionsEnv())
}

func TestDefaultAudience(t *testing.T) {
	assert.Equal(t, "sigstore", DefaultAudience)
}

func TestDefaultTimeout(t *testing.T) {
	assert.Equal(t, 30*time.Second, DefaultTimeout)
}

func TestClient_IsOIDCAvailable_True(t *testing.T) {
	client := &Client{opts: Options{
		RequestToken:    "token",
		TokenRequestURL: "https://example.com/token",
	}}

	assert.True(t, client.IsOIDCAvailable())
}

func TestClient_IsOIDCAvailable_MissingToken(t *testing.T) {
	client := &Client{opts: Options{
		TokenRequestURL: "https://example.com/token",
	}}

	assert.False(t, client.IsOIDCAvailable())
}

func TestClient_IsOIDCAvailable_MissingURL(t *testing.T) {
	client := &Client{opts: Options{
		RequestToken: "token",
	}}

	assert.False(t, client.IsOIDCAvailable())
}

func TestClient_IsOIDCAvailable_Empty(t *testing.T) {
	client := &Client{opts: Options{}}

	assert.False(t, client.IsOIDCAvailable())
}

func TestIsOIDCEnvAvailable_True(t *testing.T) {
	t.Setenv(EnvActionsIDTokenRequestToken, "token")
	t.Setenv(EnvActionsIDTokenRequestURL, "https://example.com/token")

	assert.True(t, IsOIDCEnvAvailable())
}

func TestIsOIDCEnvAvailable_MissingToken(t *testing.T) {
	_ = os.Unsetenv(EnvActionsIDTokenRequestToken)
	t.Setenv(EnvActionsIDTokenRequestURL, "https://example.com/token")

	assert.False(t, IsOIDCEnvAvailable())
}

func TestIsOIDCEnvAvailable_MissingURL(t *testing.T) {
	t.Setenv(EnvActionsIDTokenRequestToken, "token")
	_ = os.Unsetenv(EnvActionsIDTokenRequestURL)

	assert.False(t, IsOIDCEnvAvailable())
}

func TestIsOIDCEnvAvailable_BothMissing(t *testing.T) {
	_ = os.Unsetenv(EnvActionsIDTokenRequestToken)
	_ = os.Unsetenv(EnvActionsIDTokenRequestURL)

	assert.False(t, IsOIDCEnvAvailable())
}

func TestDeriveOIDCIssuers(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      []string
	}{
		{
			name:      "empty server URL returns default only",
			serverURL: "",
			want:      []string{DefaultOIDCIssuer},
		},
		{
			name:      "github.com returns default only",
			serverURL: "https://github.com",
			want:      []string{DefaultOIDCIssuer},
		},
		{
			name:      "GHES URL returns default plus derived",
			serverURL: "https://github.enterprise.com",
			want:      []string{DefaultOIDCIssuer, "https://github.enterprise.com/_services/token"},
		},
		{
			name:      "GHES with port",
			serverURL: "https://ghes.internal:8443",
			want:      []string{DefaultOIDCIssuer, "https://ghes.internal:8443/_services/token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvGitHubServerURL, tt.serverURL)
			got := DeriveOIDCIssuers()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDeriveIssuerFromServerURL(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"valid GHES URL", "https://github.enterprise.com", "https://github.enterprise.com/_services/token"},
		{"with port", "https://ghes.internal:8443", "https://ghes.internal:8443/_services/token"},
		{"http scheme", "http://ghes.local", "http://ghes.local/_services/token"},
		{"with trailing path", "https://ghes.corp/path", "https://ghes.corp/_services/token"},
		{"empty string", "", ""},
		{"invalid URL", "://bad", ""},
		{"no host", "file:///local", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, DeriveIssuerFromServerURL(tt.serverURL))
		})
	}
}
