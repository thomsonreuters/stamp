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

package key

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/signing"
	"go.step.sm/crypto/pemutil"
)

// Helper to create RSA key file.
func createRSAKeyFile(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(path, pemData, 0600))

	return key
}

// Helper to create ECDSA key file.
func createECDSAKeyFile(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(path, pemData, 0600))

	return key
}

// Helper to create encrypted key file.
func createEncryptedKeyFile(t *testing.T, path, password string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemBlock, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, keyBytes, []byte(password), x509.PEMCipherAES256)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600))

	return key
}

// Helper to create and initialize a signer.
func createSigner(t *testing.T, config signing.SignerConfig) signing.Signer {
	t.Helper()
	ctx := context.Background()

	signer, err := New(ctx, config)
	require.NoError(t, err)

	err = signer.PreSign(ctx, config)
	require.NoError(t, err)

	return signer
}

func TestSigner_ID(t *testing.T) {
	signer := &Signer{}
	assert.Equal(t, "key", signer.ID())
}

func TestSigner_Validate(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("dummy"), 0600))

	tests := []struct {
		name    string
		config  signing.SignerConfig
		wantErr string
	}{
		{
			name:    "nil key config",
			config:  signing.SignerConfig{Provider: "key", Key: nil},
			wantErr: "key configuration is required",
		},
		{
			name:    "empty key path",
			config:  signing.SignerConfig{Provider: "key", Key: &signing.KeySignerConfig{}},
			wantErr: "key-path is required",
		},
		{
			name: "both password and password file set",
			config: signing.SignerConfig{
				Provider: "key",
				Key: &signing.KeySignerConfig{
					KeyPath:         keyPath,
					KeyPassword:     "pass",
					KeyPasswordFile: "/some/file",
				},
			},
			wantErr: "only one of key-password or key-password-file should be set",
		},
		{
			name: "wrong provider name",
			config: signing.SignerConfig{
				Provider: "wrong",
				Key:      &signing.KeySignerConfig{KeyPath: keyPath},
			},
			wantErr: "invalid provider",
		},
		{
			name: "key file not found",
			config: signing.SignerConfig{
				Provider: "key",
				Key:      &signing.KeySignerConfig{KeyPath: "/nonexistent/path"},
			},
			wantErr: "key file not found",
		},
		{
			name: "valid config",
			config: signing.SignerConfig{
				Provider: "key",
				Key:      &signing.KeySignerConfig{KeyPath: keyPath},
			},
			wantErr: "",
		},
	}

	signer := &Signer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := signer.Validate(tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// End-to-end test: RSA key file → load → sign → verify.
func TestEndToEnd_RSA_SignAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa.key")
	originalKey := createRSAKeyFile(t, keyPath)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	signer := createSigner(t, config)

	// Sign payload
	payload := []byte(`{"subject":"test-artifact","predicate":{"type":"attestation"}}`)
	signature, err := signer.Sign(ctx, payload)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// PostSign
	err = signer.PostSign(ctx)
	require.NoError(t, err)

	// Verify with original key
	hash := sha256.Sum256(payload)
	err = rsa.VerifyPKCS1v15(&originalKey.PublicKey, crypto.SHA256, hash[:], signature)
	require.NoError(t, err, "signature verification should succeed")

	// Verify public key matches
	pubKey, err := signer.PublicKey()
	require.NoError(t, err)
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, originalKey.PublicKey.N, rsaPub.N)
	assert.Equal(t, originalKey.PublicKey.E, rsaPub.E)
}

// End-to-end test: ECDSA key file → load → sign → verify.
func TestEndToEnd_ECDSA_SignAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa.key")
	originalKey := createECDSAKeyFile(t, keyPath)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	signer := createSigner(t, config)

	// Sign payload
	payload := []byte(`{"subject":"test-artifact","predicate":{"type":"attestation"}}`)
	signature, err := signer.Sign(ctx, payload)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify with original key
	hash := sha256.Sum256(payload)
	valid := ecdsa.VerifyASN1(&originalKey.PublicKey, hash[:], signature)
	require.True(t, valid, "signature verification should succeed")

	// Verify public key matches
	pubKey, err := signer.PublicKey()
	require.NoError(t, err)
	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, originalKey.PublicKey.Equal(ecPub), "public keys should match")
}

// End-to-end test: Encrypted key with password.
func TestEndToEnd_EncryptedKey_SignAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "encrypted.key")
	password := "secure-password-123"
	originalKey := createEncryptedKeyFile(t, keyPath, password)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath, KeyPassword: password},
	}

	signer := createSigner(t, config)

	// Sign and verify
	payload := []byte("encrypted key signing test")
	signature, err := signer.Sign(ctx, payload)
	require.NoError(t, err)

	hash := sha256.Sum256(payload)
	valid := ecdsa.VerifyASN1(&originalKey.PublicKey, hash[:], signature)
	require.True(t, valid)
}

// End-to-end test: Password from file.
func TestEndToEnd_PasswordFile_SignAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "encrypted.key")
	passwordFile := filepath.Join(tmpDir, "password.txt")
	password := "password-from-file"
	ctx := context.Background()

	// Write password file with trailing newline (common scenario)
	require.NoError(t, os.WriteFile(passwordFile, []byte(password+"\n  \n"), 0600))

	originalKey := createEncryptedKeyFile(t, keyPath, password)

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath, KeyPasswordFile: passwordFile},
	}

	signer := createSigner(t, config)

	// Sign and verify
	payload := []byte("password file test")
	signature, err := signer.Sign(ctx, payload)
	require.NoError(t, err)

	hash := sha256.Sum256(payload)
	valid := ecdsa.VerifyASN1(&originalKey.PublicKey, hash[:], signature)
	require.True(t, valid)
}

// Test that modified payload fails verification.
func TestSignature_ModifiedPayloadFails(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa.key")
	originalKey := createECDSAKeyFile(t, keyPath)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	signer := createSigner(t, config)

	// Sign original payload
	original := []byte("original payload")
	signature, err := signer.Sign(ctx, original)
	require.NoError(t, err)

	// Verify original succeeds
	hash := sha256.Sum256(original)
	valid := ecdsa.VerifyASN1(&originalKey.PublicKey, hash[:], signature)
	require.True(t, valid)

	// Verify modified payload fails
	modified := []byte("modified payload")
	modifiedHash := sha256.Sum256(modified)
	valid = ecdsa.VerifyASN1(&originalKey.PublicKey, modifiedHash[:], signature)
	assert.False(t, valid, "signature should fail for modified payload")
}

// Test that wrong key fails verification.
func TestSignature_WrongKeyFails(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create two different keys
	signingKeyPath := filepath.Join(tmpDir, "signing.key")
	wrongKeyPath := filepath.Join(tmpDir, "wrong.key")
	_ = createECDSAKeyFile(t, signingKeyPath) // Only need the file for signer to load
	wrongKey := createECDSAKeyFile(t, wrongKeyPath)

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: signingKeyPath},
	}

	signer := createSigner(t, config)

	// Sign with signing key
	payload := []byte("test payload")
	signature, err := signer.Sign(ctx, payload)
	require.NoError(t, err)

	// Verify with wrong key should fail
	hash := sha256.Sum256(payload)
	valid := ecdsa.VerifyASN1(&wrongKey.PublicKey, hash[:], signature)
	assert.False(t, valid, "signature should fail with wrong key")
}

// Test multiple signatures with same signer.
func TestSigner_MultipleSignatures(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa.key")
	originalKey := createECDSAKeyFile(t, keyPath)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	signer := createSigner(t, config)

	payloads := [][]byte{
		[]byte("payload 1"),
		[]byte("payload 2"),
		[]byte("payload 3"),
		[]byte(""),
		[]byte("payload with special chars: !@#$%^&*()"),
	}

	for i, payload := range payloads {
		signature, err := signer.Sign(ctx, payload)
		require.NoError(t, err, "signing payload %d should succeed", i)

		hash := sha256.Sum256(payload)
		valid := ecdsa.VerifyASN1(&originalKey.PublicKey, hash[:], signature)
		require.True(t, valid, "verifying payload %d should succeed", i)
	}
}

// Test key ID is consistent.
func TestSigner_KeyIDConsistency(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa.key")
	createECDSAKeyFile(t, keyPath)

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	// Create signer twice
	signer1 := createSigner(t, config)
	signer2 := createSigner(t, config)

	// Key IDs should be identical
	keyID1, err := signer1.KeyID()
	require.NoError(t, err)

	keyID2, err := signer2.KeyID()
	require.NoError(t, err)

	assert.Equal(t, keyID1, keyID2, "key IDs should be consistent for same key")
	assert.Len(t, keyID1, 64, "key ID should be SHA256 hex (64 chars)")
}

// Test large payload signing.
func TestSigner_LargePayload(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa.key")
	originalKey := createECDSAKeyFile(t, keyPath)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	signer := createSigner(t, config)

	// 10MB payload
	largePayload := make([]byte, 10*1024*1024)
	_, err := rand.Read(largePayload)
	require.NoError(t, err)

	signature, err := signer.Sign(ctx, largePayload)
	require.NoError(t, err)

	hash := sha256.Sum256(largePayload)
	valid := ecdsa.VerifyASN1(&originalKey.PublicKey, hash[:], signature)
	require.True(t, valid)
}

// Test provider registration.
func TestProviderRegistration(t *testing.T) {
	assert.True(t, signing.Has("key"))
}

// Error cases.
func TestPreSign_InvalidKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("not a valid PEM"), 0600))
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath},
	}

	signer, err := New(ctx, config)
	require.NoError(t, err)

	err = signer.PreSign(ctx, config)
	require.Error(t, err)
}

func TestPreSign_WrongPassword(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "encrypted.key")
	createEncryptedKeyFile(t, keyPath, "correct-password")
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath, KeyPassword: "wrong-password"},
	}

	signer, err := New(ctx, config)
	require.NoError(t, err)

	err = signer.PreSign(ctx, config)
	require.Error(t, err)
}

func TestPreSign_PasswordFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	createECDSAKeyFile(t, keyPath)
	ctx := context.Background()

	config := signing.SignerConfig{
		Provider: "key",
		Key:      &signing.KeySignerConfig{KeyPath: keyPath, KeyPasswordFile: "/nonexistent/password"},
	}

	signer, err := New(ctx, config)
	require.NoError(t, err)

	err = signer.PreSign(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read password file")
}

func TestSigner_Sign_UnsupportedKeyType(t *testing.T) {
	signer := &Signer{
		privateKey: "unsupported-type",
		keyID:      "test",
	}

	_, err := signer.Sign(context.Background(), []byte("test"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestSigner_PublicKey_UnsupportedType(t *testing.T) {
	signer := &Signer{
		privateKey: "unsupported-type",
	}

	_, err := signer.PublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestSigner_PostSign(t *testing.T) {
	signer := &Signer{}
	err := signer.PostSign(context.Background())
	assert.NoError(t, err)
}
