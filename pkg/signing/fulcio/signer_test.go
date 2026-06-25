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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/signing"
)

func TestSigner_ID(t *testing.T) {
	signer := &Signer{}

	assert.Equal(t, "fulcio", signer.ID())
}

func TestSigner_KeyID_WithKey(t *testing.T) {
	signer := &Signer{
		keyID: "test-key-id-12345",
	}

	keyID, err := signer.KeyID()

	require.NoError(t, err)
	assert.Equal(t, "test-key-id-12345", keyID)
}

func TestSigner_KeyID_Empty(t *testing.T) {
	signer := &Signer{}

	keyID, err := signer.KeyID()

	require.NoError(t, err)
	assert.Empty(t, keyID)
}

func TestSigner_PublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &Signer{
		privateKey: privateKey,
	}

	publicKey, err := signer.PublicKey()

	require.NoError(t, err)
	assert.Equal(t, &privateKey.PublicKey, publicKey)
}

func TestSigner_Sign(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &Signer{
		privateKey: privateKey,
	}

	payload := []byte("test payload to sign")

	signature, err := signer.Sign(t.Context(), payload)

	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSigner_Sign_VerifySignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &Signer{
		privateKey: privateKey,
	}

	payload := []byte("test payload to verify")

	signature, err := signer.Sign(t.Context(), payload)
	require.NoError(t, err)

	// Verify the signature is valid
	hash := sha256.Sum256(payload)
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], signature)
	assert.True(t, valid)
}

func TestSigner_Certificate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{
		privateKey:  privateKey,
		certificate: cert,
	}

	pemBytes, err := signer.Certificate()

	require.NoError(t, err)
	assert.NotEmpty(t, pemBytes)

	// Verify the PEM is valid
	block, _ := pem.Decode(pemBytes)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

func TestSigner_CertificateToPEM(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{
		privateKey:  privateKey,
		certificate: cert,
	}

	pemBytes, err := signer.CertificateToPEM()

	require.NoError(t, err)
	assert.NotEmpty(t, pemBytes)
}

func TestSigner_GetCertificate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{
		privateKey:  privateKey,
		certificate: cert,
	}

	result := signer.GetCertificate()

	assert.Equal(t, cert, result)
}

func TestSigner_GetCertificate_Nil(t *testing.T) {
	signer := &Signer{}

	result := signer.GetCertificate()

	assert.Nil(t, result)
}

func TestSigner_PostSign(t *testing.T) {
	signer := &Signer{}

	err := signer.PostSign(t.Context())

	require.NoError(t, err)
}

func TestNew_ReturnsEmptySigner(t *testing.T) {
	signer, err := New(t.Context(), signing.SignerConfig{})

	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.IsType(t, &Signer{}, signer)
}

func TestSigner_Validate_NoSpire(t *testing.T) {
	signer := &Signer{}

	err := signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			UseSpire: false,
		},
	})

	require.NoError(t, err)
}

func TestSigner_Validate_SpireSocketNotFound(t *testing.T) {
	signer := &Signer{}

	err := signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			UseSpire:         true,
			SpireAgentSocket: "unix:///nonexistent/socket.sock",
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPIRE workload API not accessible")
}

func TestSigner_Validate_SpireSocketExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not supported on Windows")
	}

	// Create a temporary Unix socket
	socketPath := fmt.Sprintf("/tmp/spire-test-%d.sock", time.Now().UnixNano())
	listener, err := net.Listen("unix", socketPath) //nolint:noctx // Test fixture: context not needed for test socket setup
	require.NoError(t, err)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	signer := &Signer{}

	err = signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			UseSpire:         true,
			SpireAgentSocket: "unix://" + socketPath,
		},
	})

	require.NoError(t, err)
}

func TestSigner_Validate_CustomSocketPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not supported on Windows")
	}

	// Create a temporary Unix socket
	socketPath := fmt.Sprintf("/tmp/spire-test-%d.sock", time.Now().UnixNano())
	listener, err := net.Listen("unix", socketPath) //nolint:noctx // Test fixture: context not needed for test socket setup
	require.NoError(t, err)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	signer := &Signer{}

	err = signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			SpireAgentSocket: "unix://" + socketPath, // Custom socket without UseSpire flag
		},
	})

	require.NoError(t, err)
}

func TestSigner_Validate_TokenPathNotFound(t *testing.T) {
	signer := &Signer{}

	err := signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			TokenPath: "/nonexistent/path/to/token.txt",
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "token file not accessible")
}

func TestSigner_Validate_TokenPathExists(t *testing.T) {
	// Create a temporary token file
	tmpFile, err := os.CreateTemp(t.TempDir(), "token-*.txt")
	require.NoError(t, err)
	_, err = tmpFile.WriteString("test-token")
	require.NoError(t, err)
	_ = tmpFile.Close()

	signer := &Signer{}

	err = signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			TokenPath: tmpFile.Name(),
		},
	})

	require.NoError(t, err)
}

func TestSigner_Validate_UseGitHub_NotInGitHubActions(t *testing.T) {
	// Ensure we're not in GitHub Actions environment
	t.Setenv("GITHUB_ACTIONS", "")

	signer := &Signer{}

	err := signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			UseGitHub: true,
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub Actions OIDC requested but not running in GitHub Actions environment")
}

func TestSigner_Validate_UseGitHub_InGitHubActions(t *testing.T) {
	// Simulate GitHub Actions environment
	t.Setenv("GITHUB_ACTIONS", "true")

	signer := &Signer{}

	err := signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			UseGitHub: true,
		},
	})

	require.NoError(t, err)
}

func TestSigner_Validate_UseGitHub_OtherValue(t *testing.T) {
	// Set to non-"true" value
	t.Setenv("GITHUB_ACTIONS", "false")

	signer := &Signer{}

	err := signer.Validate(signing.SignerConfig{
		Fulcio: &signing.FulcioSignerConfig{
			UseGitHub: true,
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub Actions OIDC requested but not running in GitHub Actions environment")
}
