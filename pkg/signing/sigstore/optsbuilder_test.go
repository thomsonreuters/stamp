// Copyright 2025 Thomson Reuters
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

package sigstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"go.step.sm/crypto/pemutil"
)

// writeTempECDSAKeyFile writes an unencrypted PKCS#8 P-256 private key to
// a temp file and returns its path.
func writeTempECDSAKeyFile(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

// writeTempEncryptedECDSAKeyFile writes a PKCS#8-encrypted P-256 private
// key (AES-256-CBC + PBKDF2) to a temp file and returns its path.
func writeTempEncryptedECDSAKeyFile(t *testing.T, password string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	block, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, der, []byte(password), x509.PEMCipherAES256)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "encrypted.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

func TestBuildKeyOptions_FileNotFound(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.PrivateKey).Return("/nonexistent/key.pem")
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false)

	_, err := BuildKeyOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load private key")
	cfg.AssertExpectations(t)
}

func TestBuildKeyOptions_Success(t *testing.T) {
	keyPath := writeTempECDSAKeyFile(t)

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.PrivateKey).Return(keyPath)
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false)

	got, err := BuildKeyOptions(cfg)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.Signer)
	require.NotEmpty(t, got.Hint, "fingerprint hint must be populated")
	cfg.AssertExpectations(t)
}

func TestBuildKeyOptions_EncryptedKey_WithPassword(t *testing.T) {
	const password = "correct-horse-battery-staple"
	keyPath := writeTempEncryptedECDSAKeyFile(t, password)

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.PrivateKey).Return(keyPath)
	cfg.On("GetString", flags.CryptographyKeyPassword).Return(password)
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("").Maybe()
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false).Maybe()

	got, err := BuildKeyOptions(cfg)
	require.NoError(t, err)
	require.NotNil(t, got.Signer)
	require.NotEmpty(t, got.Hint)
	cfg.AssertExpectations(t)
}

func TestBuildKeyOptions_EncryptedKey_WithPasswordFile(t *testing.T) {
	const password = "file-supplied-secret"
	keyPath := writeTempEncryptedECDSAKeyFile(t, password)
	pwFile := filepath.Join(t.TempDir(), "pw.txt")
	// Trailing whitespace is expected to be trimmed by ReadPasswordFromFile.
	require.NoError(t, os.WriteFile(pwFile, []byte(password+"\n"), 0o600))

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.PrivateKey).Return(keyPath)
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return(pwFile)
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false).Maybe()

	got, err := BuildKeyOptions(cfg)
	require.NoError(t, err)
	require.NotNil(t, got.Signer)
	cfg.AssertExpectations(t)
}

func TestBuildKeyOptions_EncryptedKey_WrongPassword(t *testing.T) {
	keyPath := writeTempEncryptedECDSAKeyFile(t, "real-password")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.PrivateKey).Return(keyPath)
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("wrong-password")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("").Maybe()
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false).Maybe()

	_, err := BuildKeyOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load private key",
		"decrypt failure must surface as a load error, not e.g. a fingerprint error")
	cfg.AssertExpectations(t)
}

func TestBuildKeyOptions_EncryptedKey_NoPassword(t *testing.T) {
	keyPath := writeTempEncryptedECDSAKeyFile(t, "some-password")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.PrivateKey).Return(keyPath)
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false)

	_, err := BuildKeyOptions(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load private key")
	cfg.AssertExpectations(t)
}

func TestBuildFulcioOptions_NoTokenSource(t *testing.T) {
	// Clear ambient GitHub Actions env vars so ResolveToken's
	// best-effort auto-detect step reaches the "no source" error.
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.OIDCToken).Return("")
	cfg.On("GetString", flags.OIDCTokenFile).Return("")
	cfg.On("GetBool", flags.UseSpire).Return(false)
	cfg.On("GetString", flags.SPIRESocket).Return("")
	cfg.On("GetBool", flags.UseGitHub).Return(false)
	cfg.On("GetBool", flags.Insecure).Return(false)

	_, err := BuildFulcioOptions(context.Background(), cfg, "https://fulcio.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC token")
	cfg.AssertExpectations(t)
}

func TestBuildFulcioOptions_DirectToken(t *testing.T) {
	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.OIDCToken).Return("my-oidc-token")
	cfg.On("GetString", flags.OIDCTokenFile).Return("")
	cfg.On("GetBool", flags.UseSpire).Return(false)
	cfg.On("GetString", flags.SPIRESocket).Return("")
	cfg.On("GetBool", flags.UseGitHub).Return(false)
	cfg.On("GetBool", flags.Insecure).Return(false)

	got, err := BuildFulcioOptions(context.Background(), cfg, "https://fulcio.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "https://fulcio.example.com", got.URL)
	assert.Equal(t, "my-oidc-token", got.IDToken)
	cfg.AssertExpectations(t)
}
