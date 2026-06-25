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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/pemutil"
)

func TestLoadPrivateKeyFromFile_PKCS8_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "rsa.key")
	pemBlock := &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(keyPath, "")
	require.NoError(t, err)

	assert.NotNil(t, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)
	assert.IsType(t, &rsa.PrivateKey{}, loaded.PrivateKey)
}

func TestLoadPrivateKeyFromFile_PKCS8_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "ec.key")
	pemBlock := &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(keyPath, "")
	require.NoError(t, err)

	assert.NotNil(t, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)
	assert.IsType(t, &ecdsa.PrivateKey{}, loaded.PrivateKey)
}

func TestLoadPrivateKeyFromFile_PKCS1_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	keyPath := filepath.Join(t.TempDir(), "rsa_pkcs1.key")
	pemBlock := &pem.Block{Type: PEMTypePKCS1RSA, Bytes: keyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(keyPath, "")
	require.NoError(t, err)

	assert.NotNil(t, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)
	assert.IsType(t, &rsa.PrivateKey{}, loaded.PrivateKey)
}

func TestLoadPrivateKeyFromFile_SEC1_EC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "ec_sec1.key")
	pemBlock := &pem.Block{Type: PEMTypeSEC1EC, Bytes: keyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(keyPath, "")
	require.NoError(t, err)

	assert.NotNil(t, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)
	assert.IsType(t, &ecdsa.PrivateKey{}, loaded.PrivateKey)
}

func TestLoadPrivateKeyFromFile_Encrypted_PKCS8(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	password := "testpassword123"
	encryptedBlock, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, keyBytes, []byte(password), x509.PEMCipherAES256)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "ec_encrypted.key")
	err = os.WriteFile(keyPath, pem.EncodeToMemory(encryptedBlock), 0600)
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromFile(keyPath, password)
	require.NoError(t, err)

	assert.NotNil(t, loaded.PrivateKey)
	assert.True(t, loaded.IsEncrypted)
	assert.IsType(t, &ecdsa.PrivateKey{}, loaded.PrivateKey)
}

func TestLoadPrivateKeyFromFile_FileNotFound(t *testing.T) {
	_, err := LoadPrivateKeyFromFile("/nonexistent/path/key.pem", "")

	require.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

func TestLoadPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadPrivateKeyFromPEM([]byte("not valid pem data"), "", "test")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestLoadPrivateKeyFromPEM_EncryptedWithoutPassword(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	encryptedBlock, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, keyBytes, []byte("password"), x509.PEMCipherAES256)
	require.NoError(t, err)

	_, err = LoadPrivateKeyFromPEM(pem.EncodeToMemory(encryptedBlock), "", "test")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingPassword)
}

func TestLoadPrivateKeyFromPEM_WrongPassword(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	encryptedBlock, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, keyBytes, []byte("correctpassword"), x509.PEMCipherAES256)
	require.NoError(t, err)

	_, err = LoadPrivateKeyFromPEM(pem.EncodeToMemory(encryptedBlock), "wrongpassword", "test")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestLoadPrivateKeyFromPEM_LegacyPEMEncryption(t *testing.T) {
	pemBlock := &pem.Block{
		Type:  PEMTypePKCS1RSA,
		Bytes: []byte("dummy key data"),
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC,abc123",
		},
	}

	_, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "", "test")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrLegacyEncryption)
}

func TestLoadPrivateKeyFromPEM_UnsupportedKeyType(t *testing.T) {
	pemBlock := &pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("some key data"),
	}

	_, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "", "test")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestLoadPrivateKeyFromPEM_InvalidPKCS8Data(t *testing.T) {
	pemBlock := &pem.Block{
		Type:  PEMTypePKCS8,
		Bytes: []byte("invalid pkcs8 data"),
	}

	_, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "", "test")

	assert.Error(t, err)
}

func TestLoadPrivateKeyFromPEM_InvalidPKCS1Data(t *testing.T) {
	pemBlock := &pem.Block{
		Type:  PEMTypePKCS1RSA,
		Bytes: []byte("invalid pkcs1 data"),
	}

	_, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "", "test")

	assert.Error(t, err)
}

func TestLoadPrivateKeyFromPEM_InvalidSEC1Data(t *testing.T) {
	pemBlock := &pem.Block{
		Type:  PEMTypeSEC1EC,
		Bytes: []byte("invalid sec1 data"),
	}

	_, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "", "test")

	assert.Error(t, err)
}

func TestLoadPrivateKeyFromPEM_NonEncryptedKeyWithPassword(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}

	// Password is ignored for unencrypted keys
	loaded, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "somepassword", "test")

	require.NoError(t, err)
	assert.NotNil(t, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)
}

func TestLoadPrivateKeyFromPEM_HeadersWithoutProcType(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	// Non-encryption headers should be allowed
	pemBlock := &pem.Block{
		Type:  PEMTypePKCS8,
		Bytes: keyBytes,
		Headers: map[string]string{
			"Comment": "This is a test key",
		},
	}

	loaded, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(pemBlock), "", "test")

	require.NoError(t, err)
	assert.NotNil(t, loaded.PrivateKey)
	assert.False(t, loaded.IsEncrypted)
}

func TestLoadPrivateKeyFromFile_DifferentKeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"RSA-2048", 2048},
		{"RSA-4096", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rsaKey, err := rsa.GenerateKey(rand.Reader, tt.keySize)
			require.NoError(t, err)

			keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
			require.NoError(t, err)

			keyPath := filepath.Join(t.TempDir(), "rsa.key")
			pemBlock := &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}
			err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
			require.NoError(t, err)

			loaded, err := LoadPrivateKeyFromFile(keyPath, "")
			require.NoError(t, err)

			rsaLoaded, _ := loaded.PrivateKey.(*rsa.PrivateKey)
			assert.Equal(t, tt.keySize, rsaLoaded.N.BitLen())
		})
	}
}

func TestLoadPrivateKeyFromFile_DifferentECCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
			require.NoError(t, err)

			keyPath := filepath.Join(t.TempDir(), "ec.key")
			pemBlock := &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}
			err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
			require.NoError(t, err)

			loaded, err := LoadPrivateKeyFromFile(keyPath, "")
			require.NoError(t, err)

			ecLoaded, _ := loaded.PrivateKey.(*ecdsa.PrivateKey)
			assert.Equal(t, tt.curve.Params().Name, ecLoaded.Curve.Params().Name)
		})
	}
}

func TestLoadPublicKeyFromFile_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "rsa.pub")
	pemBlock := &pem.Block{Type: PEMTypePublicKey, Bytes: pubKeyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0644)
	require.NoError(t, err)

	pubKey, err := LoadPublicKeyFromFile(keyPath)
	require.NoError(t, err)

	assert.IsType(t, &rsa.PublicKey{}, pubKey)
	loadedRSA, _ := pubKey.(*rsa.PublicKey)
	assert.True(t, rsaKey.PublicKey.Equal(loadedRSA))
}

func TestLoadPublicKeyFromFile_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "ec.pub")
	pemBlock := &pem.Block{Type: PEMTypePublicKey, Bytes: pubKeyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0644)
	require.NoError(t, err)

	pubKey, err := LoadPublicKeyFromFile(keyPath)
	require.NoError(t, err)

	assert.IsType(t, &ecdsa.PublicKey{}, pubKey)
	loadedEC, _ := pubKey.(*ecdsa.PublicKey)
	assert.True(t, ecKey.PublicKey.Equal(loadedEC))
}

func TestLoadPublicKeyFromFile_FileNotFound(t *testing.T) {
	_, err := LoadPublicKeyFromFile("/nonexistent/path/key.pub")

	require.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

func TestLoadPublicKeyFromPEM_Success(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{Type: PEMTypePublicKey, Bytes: pubKeyBytes}
	pemData := pem.EncodeToMemory(pemBlock)

	pubKey, err := LoadPublicKeyFromPEM(pemData, "test")
	require.NoError(t, err)

	assert.IsType(t, &ecdsa.PublicKey{}, pubKey)
	loadedEC, _ := pubKey.(*ecdsa.PublicKey)
	assert.True(t, ecKey.PublicKey.Equal(loadedEC))
}

func TestLoadPublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadPublicKeyFromPEM([]byte("not valid pem data"), "test")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestLoadPublicKeyFromPEM_WrongBlockType(t *testing.T) {
	// Use a private key PEM block type instead of public key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{Type: PEMTypePKCS8, Bytes: keyBytes}
	pemData := pem.EncodeToMemory(pemBlock)

	_, err = LoadPublicKeyFromPEM(pemData, "test")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestLoadPublicKeyFromPEM_InvalidKeyData(t *testing.T) {
	pemBlock := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: []byte("invalid public key data"),
	}

	_, err := LoadPublicKeyFromPEM(pem.EncodeToMemory(pemBlock), "test")

	assert.Error(t, err)
}

func TestLoadPublicKeyFromFile_DifferentECCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
			require.NoError(t, err)

			keyPath := filepath.Join(t.TempDir(), "ec.pub")
			pemBlock := &pem.Block{Type: PEMTypePublicKey, Bytes: pubKeyBytes}
			err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0644)
			require.NoError(t, err)

			pubKey, err := LoadPublicKeyFromFile(keyPath)
			require.NoError(t, err)

			ecLoaded, _ := pubKey.(*ecdsa.PublicKey)
			assert.Equal(t, tt.curve.Params().Name, ecLoaded.Curve.Params().Name)
		})
	}
}

// Certificate parsing tests

func TestParseCertificateFromBytes_DER(t *testing.T) {
	cert := generateTestCertificate(t)

	parsed, err := ParseCertificateFromBytes(cert.Raw)
	require.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
}

func TestParseCertificateFromBytes_PEM(t *testing.T) {
	cert := generateTestCertificate(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificate, Bytes: cert.Raw})

	parsed, err := ParseCertificateFromBytes(pemData)
	require.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
}

func TestParseCertificateFromBytes_PEMChain_ReturnsFirst(t *testing.T) {
	cert1 := generateTestCertificateWithCN(t, "First Certificate")
	cert2 := generateTestCertificateWithCN(t, "Second Certificate")

	// Create PEM chain with two certificates
	var pemChain []byte
	pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificate, Bytes: cert1.Raw})...)
	pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificate, Bytes: cert2.Raw})...)

	parsed, err := ParseCertificateFromBytes(pemChain)
	require.NoError(t, err)
	assert.Equal(t, "First Certificate", parsed.Subject.CommonName)
}

func TestParseCertificateFromBytes_Invalid(t *testing.T) {
	_, err := ParseCertificateFromBytes([]byte("not a certificate"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCertificateParse)
}

func TestParseCertificateFromBytes_Empty(t *testing.T) {
	_, err := ParseCertificateFromBytes([]byte{})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCertificateParse)
}

func TestParseCertificateChainFromBytes_SingleDER(t *testing.T) {
	cert := generateTestCertificate(t)

	certs, err := ParseCertificateChainFromBytes(cert.Raw)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
}

func TestParseCertificateChainFromBytes_PEMChain(t *testing.T) {
	cert1 := generateTestCertificateWithCN(t, "Leaf Certificate")
	cert2 := generateTestCertificateWithCN(t, "Intermediate CA")
	cert3 := generateTestCertificateWithCN(t, "Root CA")

	// Create PEM chain
	var pemChain []byte
	pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificate, Bytes: cert1.Raw})...)
	pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificate, Bytes: cert2.Raw})...)
	pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: PEMTypeCertificate, Bytes: cert3.Raw})...)

	certs, err := ParseCertificateChainFromBytes(pemChain)
	require.NoError(t, err)
	require.Len(t, certs, 3)
	assert.Equal(t, "Leaf Certificate", certs[0].Subject.CommonName)
	assert.Equal(t, "Intermediate CA", certs[1].Subject.CommonName)
	assert.Equal(t, "Root CA", certs[2].Subject.CommonName)
}

func TestParseCertificateChainFromBytes_Invalid(t *testing.T) {
	_, err := ParseCertificateChainFromBytes([]byte("not a certificate"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCertificateParse)
}

// Helper functions for certificate tests

func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	return generateTestCertificateWithCN(t, "Test Certificate")
}

func generateTestCertificateWithCN(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
