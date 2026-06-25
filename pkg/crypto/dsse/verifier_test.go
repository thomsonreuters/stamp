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

package dsse

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

func TestVerifyDSSESignature_NoSignatures(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
		Signatures:  []intoto.Signature{},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSignatures)
}

func TestVerifyDSSESignature_InvalidPayload(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "not-valid-base64!!!",
		Signatures: []intoto.Signature{
			{Signature: "dGVzdA=="},
		},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadDecode)
}

func TestVerifyDSSESignature_InvalidSignatureBase64(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
		Signatures: []intoto.Signature{
			{Signature: "not-valid-base64!!!"},
		},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureDecode)
}

func TestVerifyDSSESignature_NoPublicKey(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
		Signatures: []intoto.Signature{
			{Signature: base64.StdEncoding.EncodeToString([]byte("fake-sig"))},
		},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoPublicKey)
}

func TestVerifyDSSESignature_InvalidCertificateBase64(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
		Signatures: []intoto.Signature{
			{
				Signature:   base64.StdEncoding.EncodeToString([]byte("fake-sig")),
				Certificate: "not-valid-base64!!!",
			},
		},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertificateDecode)
}

func TestVerifyDSSESignature_InvalidCertificateData(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
		Signatures: []intoto.Signature{
			{
				Signature:   base64.StdEncoding.EncodeToString([]byte("fake-sig")),
				Certificate: base64.StdEncoding.EncodeToString([]byte("not-a-certificate")),
			},
		},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertificateDecode)
}

func TestVerifyDSSESignature_ECDSA_Success(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create payload
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create PAE and sign
	pae := createTestPAE("application/vnd.in-toto+json", payload)
	hash := sha256.Sum256(pae)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	// Create certificate
	cert := createTestCertificate(t, &privateKey.PublicKey, privateKey)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payloadB64,
		Signatures: []intoto.Signature{
			{
				Signature:   base64.StdEncoding.EncodeToString(signature),
				Certificate: certB64,
			},
		},
	}

	valid, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyDSSESignature_ECDSA_InvalidSignature(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create payload
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create a different key to sign (wrong signature)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pae := createTestPAE("application/vnd.in-toto+json", payload)
	hash := sha256.Sum256(pae)
	signature, err := ecdsa.SignASN1(rand.Reader, wrongKey, hash[:])
	require.NoError(t, err)

	// Create certificate with original key
	cert := createTestCertificate(t, &privateKey.PublicKey, privateKey)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payloadB64,
		Signatures: []intoto.Signature{
			{
				Signature:   base64.StdEncoding.EncodeToString(signature),
				Certificate: certB64,
			},
		},
	}

	_, err = VerifyDSSESignature(context.Background(), envelope, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifyDSSESignature_RSA_Success(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create payload
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create PAE and sign with PKCS#1 v1.5
	pae := createTestPAE("application/vnd.in-toto+json", payload)
	hash := sha256.Sum256(pae)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	// Create certificate
	cert := createTestCertificateRSA(t, &privateKey.PublicKey, privateKey)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payloadB64,
		Signatures: []intoto.Signature{
			{
				Signature:   base64.StdEncoding.EncodeToString(signature),
				Certificate: certB64,
			},
		},
	}

	valid, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyDSSESignature_FromKeyFile(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Save public key to file
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "test.pub")
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0644)
	require.NoError(t, err)

	// Create payload
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create PAE and sign
	pae := createTestPAE("application/vnd.in-toto+json", payload)
	hash := sha256.Sum256(pae)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payloadB64,
		Signatures: []intoto.Signature{
			{Signature: base64.StdEncoding.EncodeToString(signature)},
		},
	}

	valid, err := VerifyDSSESignature(context.Background(), envelope, keyPath)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyDSSESignature_KeyFileNotFound(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
		Signatures: []intoto.Signature{
			{Signature: base64.StdEncoding.EncodeToString([]byte("fake-sig"))},
		},
	}

	_, err := VerifyDSSESignature(context.Background(), envelope, "/nonexistent/key.pub")
	assert.Error(t, err)
}

func TestVerifyDSSESignature_MultipleSignatures(t *testing.T) {
	// Generate two ECDSA key pairs
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create payload
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create PAE and sign with both keys
	pae := createTestPAE("application/vnd.in-toto+json", payload)
	hash := sha256.Sum256(pae)

	sig1, err := ecdsa.SignASN1(rand.Reader, privateKey1, hash[:])
	require.NoError(t, err)
	sig2, err := ecdsa.SignASN1(rand.Reader, privateKey2, hash[:])
	require.NoError(t, err)

	cert1 := createTestCertificate(t, &privateKey1.PublicKey, privateKey1)
	cert2 := createTestCertificate(t, &privateKey2.PublicKey, privateKey2)

	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payloadB64,
		Signatures: []intoto.Signature{
			{
				Signature:   base64.StdEncoding.EncodeToString(sig1),
				Certificate: base64.StdEncoding.EncodeToString(cert1.Raw),
			},
			{
				Signature:   base64.StdEncoding.EncodeToString(sig2),
				Certificate: base64.StdEncoding.EncodeToString(cert2.Raw),
			},
		},
	}

	valid, err := VerifyDSSESignature(context.Background(), envelope, "")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestCreateDSSEPAE(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte("test payload")),
	}

	pae, err := createDSSEPAE(envelope)
	require.NoError(t, err)

	// Verify PAE format
	expected := "DSSEv1 28 application/vnd.in-toto+json 12 test payload"
	assert.Equal(t, expected, string(pae))
}

func TestCreateDSSEPAE_InvalidPayload(t *testing.T) {
	envelope := &intoto.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "not-valid-base64!!!",
	}

	_, err := createDSSEPAE(envelope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadDecode)
}

func TestVerifyECDSASignature_Success(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test message"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	err = verifyECDSASignature(&privateKey.PublicKey, hash[:], signature)
	assert.NoError(t, err)
}

func TestVerifyECDSASignature_Invalid(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test message"))
	wrongHash := sha256.Sum256([]byte("different message"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	err = verifyECDSASignature(&privateKey.PublicKey, wrongHash[:], signature)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifyRSASignature_PSS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test message"))
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
	require.NoError(t, err)

	err = verifyRSASignature(&privateKey.PublicKey, hash[:], signature)
	assert.NoError(t, err)
}

func TestVerifyRSASignature_PKCS1(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test message"))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	err = verifyRSASignature(&privateKey.PublicKey, hash[:], signature)
	assert.NoError(t, err)
}

func TestVerifyRSASignature_Invalid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("test message"))
	wrongHash := sha256.Sum256([]byte("different message"))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	err = verifyRSASignature(&privateKey.PublicKey, wrongHash[:], signature)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifySignature_UnsupportedKeyType(t *testing.T) {
	// Use an unsupported key type (interface{})
	err := verifySignature("not-a-key", []byte("hash"), []byte("sig"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestExtractPublicKey_FromCertificate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := createTestCertificate(t, &privateKey.PublicKey, privateKey)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	sig := intoto.Signature{Certificate: certB64}
	pubKey, err := extractPublicKey(sig, "")
	require.NoError(t, err)

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, privateKey.PublicKey.Equal(ecdsaPubKey))
}

func TestExtractPublicKey_FromKeyFile(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "test.pub")
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0644)
	require.NoError(t, err)

	sig := intoto.Signature{}
	pubKey, err := extractPublicKey(sig, keyPath)
	require.NoError(t, err)

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, privateKey.PublicKey.Equal(ecdsaPubKey))
}

func TestExtractPublicKey_NoSource(t *testing.T) {
	sig := intoto.Signature{}
	_, err := extractPublicKey(sig, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoPublicKey)
}

// Helper functions

//nolint:unparam // payloadType parameter kept for test helper consistency and future flexibility
func createTestPAE(payloadType string, payload []byte) []byte {
	// Match the exact PAE format from createDSSEPAE
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s",
		len(payloadType),
		payloadType,
		len(payload),
		payload)
}

func createTestCertificate(t *testing.T, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func createTestCertificateRSA(t *testing.T, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test RSA Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
