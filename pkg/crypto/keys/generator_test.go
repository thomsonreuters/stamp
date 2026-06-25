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

package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_RSA(t *testing.T) {
	key, err := Generate(AlgorithmRSA)
	require.NoError(t, err)

	rsaKey, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok)
	assert.Equal(t, DefaultRSAKeySize, rsaKey.N.BitLen())
}

func TestGenerate_ECDSA(t *testing.T) {
	key, err := Generate(AlgorithmECDSA)
	require.NoError(t, err)

	ecKey, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok)
	assert.Equal(t, "P-256", ecKey.Curve.Params().Name)
}

func TestGenerate_CaseInsensitive(t *testing.T) {
	tests := []string{"RSA", "Rsa", "rsa", "ECDSA", "Ecdsa", "ecdsa"}

	for _, alg := range tests {
		t.Run(alg, func(t *testing.T) {
			key, err := Generate(alg)
			require.NoError(t, err)
			assert.NotNil(t, key)
		})
	}
}

func TestGenerate_UnsupportedAlgorithm(t *testing.T) {
	_, err := Generate("unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestGenerateRSA_ValidSizes(t *testing.T) {
	tests := []int{2048, 3072, 4096}

	for _, bits := range tests {
		t.Run(string(rune(bits)), func(t *testing.T) {
			key, err := GenerateRSA(bits)
			require.NoError(t, err)
			assert.Equal(t, bits, key.N.BitLen())
		})
	}
}

func TestGenerateRSA_TooSmall(t *testing.T) {
	_, err := GenerateRSA(1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2048 bits")
}

func TestGenerateECDSA(t *testing.T) {
	key, err := GenerateECDSA()
	require.NoError(t, err)
	assert.Equal(t, "P-256", key.Curve.Params().Name)
}

func TestGenerateToFile_ECDSA(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	result, err := GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmECDSA,
	})
	require.NoError(t, err)

	assert.Equal(t, fmt.Sprintf("%s.key", basePath), result.PrivateKeyPath)
	assert.Equal(t, fmt.Sprintf("%s.pub", basePath), result.PublicKeyPath)

	assert.FileExists(t, result.PrivateKeyPath)
	assert.FileExists(t, result.PublicKeyPath)

	// Verify private key can be loaded
	loaded, err := LoadPrivateKeyFromFile(result.PrivateKeyPath, "")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)

	// Verify public key can be loaded and matches private key
	pubKey, err := LoadPublicKeyFromFile(result.PublicKeyPath)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, pubKey)

	// Verify public key matches private key's public component
	privateKey, _ := loaded.PrivateKey.(*ecdsa.PrivateKey)
	loadedPubKey, _ := pubKey.(*ecdsa.PublicKey)
	assert.True(t, privateKey.PublicKey.Equal(loadedPubKey), "public key should match private key's public component")
}

func TestGenerateToFile_RSA(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	result, err := GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmRSA,
	})
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(result.PrivateKeyPath, "")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, loaded.PrivateKey)
}

func TestGenerateToFile_DefaultAlgorithm(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	result, err := GenerateToFile(basePath, GenerateOptions{})
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(result.PrivateKeyPath, "")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, loaded.PrivateKey)
}

func TestGenerateToFile_Encrypted(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")
	password := "testpassword123"

	result, err := GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmECDSA,
		Password:  password,
	})
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(result.PrivateKeyPath, password)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, loaded.PrivateKey)
	assert.True(t, loaded.IsEncrypted)
}

func TestGenerateToFile_EncryptedWrongPassword(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	_, err := GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmECDSA,
		Password:  "correctpassword",
	})
	require.NoError(t, err)

	_, err = LoadPrivateKeyFromFile(fmt.Sprintf("%s.key", basePath), "wrongpassword")
	assert.Error(t, err)
}

func TestGenerateToFile_Overwrite(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	// Generate first key pair
	result1, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.NoError(t, err)

	// Get fingerprint of first key
	loaded1, err := LoadPrivateKeyFromFile(result1.PrivateKeyPath, "")
	require.NoError(t, err)
	fp1, err := Fingerprint(loaded1.PrivateKey)
	require.NoError(t, err)

	// Generate second key pair with overwrite
	result2, err := GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmECDSA,
		Overwrite: true,
	})
	require.NoError(t, err)

	// Get fingerprint of second key
	loaded2, err := LoadPrivateKeyFromFile(result2.PrivateKeyPath, "")
	require.NoError(t, err)
	fp2, err := Fingerprint(loaded2.PrivateKey)
	require.NoError(t, err)

	// Keys should be different
	assert.NotEqual(t, fp1, fp2)
}

func TestGenerateToFile_NoOverwrite(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	_, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.NoError(t, err)

	_, err = GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmECDSA,
		Overwrite: false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestGenerateToFile_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "subdir", "nested", "testkey")

	result, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.NoError(t, err)

	assert.FileExists(t, result.PrivateKeyPath)
	assert.FileExists(t, result.PublicKeyPath)
}

func TestGenerateToFile_PrivateKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions work differently on Windows")
	}

	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	result, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.NoError(t, err)

	info, err := os.Stat(result.PrivateKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestGenerateToFile_PublicKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions work differently on Windows")
	}

	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	result, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.NoError(t, err)

	info, err := os.Stat(result.PublicKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func TestGenerateToFile_StripExtension(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey.pem")

	result, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(dir, "testkey.key"), result.PrivateKeyPath)
	assert.Equal(t, filepath.Join(dir, "testkey.pub"), result.PublicKeyPath)
}

func TestGenerateToFile_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	_, err := GenerateToFile(basePath, GenerateOptions{Algorithm: "unknown"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestGenerateToFile_CleanupOnPublicKeyFailure(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	// Create the public key path as a directory to cause write failure
	pubKeyPath := fmt.Sprintf("%s.pub", basePath)
	err := os.MkdirAll(pubKeyPath, 0755)
	require.NoError(t, err)

	_, err = GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.Error(t, err)

	// Private key should be cleaned up
	_, err = os.Stat(fmt.Sprintf("%s.key", basePath))
	assert.True(t, os.IsNotExist(err))
}

func TestGenerateToFile_InvalidDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/dev/null path does not exist on Windows")
	}

	// Try to create in a path that can't be created
	basePath := "/dev/null/invalid/path/testkey"

	_, err := GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}

func TestGenerateToFile_PrivateKeyPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	err := os.MkdirAll(fmt.Sprintf("%s.key", basePath), 0755)
	require.NoError(t, err)

	_, err = GenerateToFile(basePath, GenerateOptions{Algorithm: AlgorithmECDSA})
	require.Error(t, err)
}

func TestGenerateToFile_PublicKeyExistsNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "testkey")

	// Create only public key file
	err := os.WriteFile(fmt.Sprintf("%s.pub", basePath), []byte("dummy"), 0644)
	require.NoError(t, err)

	_, err = GenerateToFile(basePath, GenerateOptions{
		Algorithm: AlgorithmECDSA,
		Overwrite: false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}
