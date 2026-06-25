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

package eks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client, err := New(t.Context(), Options{})

	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNew_WithCustomTokenPath(t *testing.T) {
	customPath := "/custom/path/token"
	client, err := New(t.Context(), Options{TokenPath: customPath})

	require.NoError(t, err)
	assert.Equal(t, customPath, client.GetTokenPath())
}

func TestClient_FetchToken_Success(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	expectedToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"

	err := os.WriteFile(tokenPath, []byte(expectedToken), 0600)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{TokenPath: tokenPath})
	require.NoError(t, err)

	token, err := client.FetchToken(t.Context())

	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestClient_FetchToken_WithWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	expectedToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"

	err := os.WriteFile(tokenPath, []byte("  "+expectedToken+"\n\t"), 0600)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{TokenPath: tokenPath})
	require.NoError(t, err)

	token, err := client.FetchToken(t.Context())

	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestClient_FetchToken_FileNotFound(t *testing.T) {
	client, err := New(t.Context(), Options{TokenPath: "/nonexistent/path/token"})
	require.NoError(t, err)

	token, err := client.FetchToken(t.Context())

	require.ErrorIs(t, err, ErrTokenFileNotFound)
	assert.Empty(t, token)
}

func TestClient_FetchToken_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")

	err := os.WriteFile(tokenPath, []byte(""), 0600)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{TokenPath: tokenPath})
	require.NoError(t, err)

	token, err := client.FetchToken(t.Context())

	require.ErrorIs(t, err, ErrTokenFileEmpty)
	assert.Empty(t, token)
}

func TestClient_FetchToken_WhitespaceOnly(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")

	err := os.WriteFile(tokenPath, []byte("   \n\t  "), 0600)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{TokenPath: tokenPath})
	require.NoError(t, err)

	token, err := client.FetchToken(t.Context())

	require.ErrorIs(t, err, ErrTokenFileEmpty)
	assert.Empty(t, token)
}

func TestIsIRSAEnvAvailable_WithEnvVar(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenPath, []byte("token"), 0600)
	require.NoError(t, err)

	t.Setenv(EnvWebIdentityTokenFile, tokenPath)

	assert.True(t, IsIRSAEnvAvailable())
}

func TestIsIRSAEnvAvailable_EnvVarFileNotFound(t *testing.T) {
	t.Setenv(EnvWebIdentityTokenFile, "/nonexistent/token")

	assert.False(t, IsIRSAEnvAvailable())
}

func TestIsIRSAEnvAvailable_NoEnvVar(t *testing.T) {
	_ = os.Unsetenv(EnvWebIdentityTokenFile)

	// Default path doesn't exist in test environment
	assert.False(t, IsIRSAEnvAvailable())
}

func TestGetTokenFilePath_FromEnv(t *testing.T) {
	customPath := "/custom/token/path"
	t.Setenv(EnvWebIdentityTokenFile, customPath)

	assert.Equal(t, customPath, GetTokenFilePath())
}

func TestGetTokenFilePath_Default(t *testing.T) {
	_ = os.Unsetenv(EnvWebIdentityTokenFile)

	assert.Equal(t, DefaultTokenPath, GetTokenFilePath())
}

func TestClient_GetTokenPath(t *testing.T) {
	customPath := "/custom/path"
	client, err := New(t.Context(), Options{TokenPath: customPath})
	require.NoError(t, err)

	assert.Equal(t, customPath, client.GetTokenPath())
}

func TestClient_IsIRSAAvailable(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenPath, []byte("token"), 0600)
	require.NoError(t, err)

	t.Setenv(EnvWebIdentityTokenFile, tokenPath)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	assert.True(t, client.IsIRSAAvailable())
}
