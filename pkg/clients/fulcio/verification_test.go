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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions

// createValidCodeSigningCert creates a certificate with valid code signing properties.
func createValidCodeSigningCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-signer",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// Add email for SAN identity
		EmailAddresses: []string{"test@example.com"},
		// Add Fulcio OIDC issuer extension
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDIssuerV2,
				Value: []byte("https://issuer.example.com"),
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, leafKey
}

// createCAForChainValidation creates a CA certificate and key for testing chain validation.
func createCAForChainValidation(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	return caCert, caKey, string(caCertPEM)
}

// createCertWithKeyUsage creates a certificate with specified key usage flags.
func createCertWithKeyUsage(t *testing.T, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		EmailAddresses: []string{"test@example.com"},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDIssuerV2, Value: []byte("issuer")},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// createCertWithSAN creates a certificate with specified SAN fields.
func createCertWithSAN(t *testing.T, emails []string, uris []*url.URL) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: emails,
		URIs:           uris,
		ExtraExtensions: []pkix.Extension{
			{Id: OIDIssuerV2, Value: []byte("issuer")},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// createCertWithExtensions creates a certificate with specified extensions.
func createCertWithExtensions(t *testing.T, extensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses:  []string{"test@example.com"},
		ExtraExtensions: extensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// createCertWithValidity creates a certificate with specified validity period.
func createCertWithValidity(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: []string{"test@example.com"},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDIssuerV2, Value: []byte("issuer")},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestValidateTemporalValidity_Success tests valid temporal constraints.
func TestValidateTemporalValidity_Success(t *testing.T) {
	now := time.Now()
	cert := createCertWithValidity(t, now, now.Add(10*time.Minute))

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateTemporalValidity(cert, 15*time.Minute)
	assert.NoError(t, err)
}

// TestValidateTemporalValidity_NotAfterBeforeNotBefore tests invalid validity period.
func TestValidateTemporalValidity_NotAfterBeforeNotBefore(t *testing.T) {
	now := time.Now()
	cert := createCertWithValidity(t, now, now.Add(-time.Hour))

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateTemporalValidity(cert, time.Hour)
	assert.ErrorIs(t, err, ErrInvalidValidityPeriod)
}

// TestValidateTemporalValidity_TooLong tests validity period exceeding max duration.
func TestValidateTemporalValidity_TooLong(t *testing.T) {
	now := time.Now()
	cert := createCertWithValidity(t, now, now.Add(2*time.Hour))

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateTemporalValidity(cert, time.Hour)
	assert.ErrorIs(t, err, ErrValidityPeriodTooLong)
}

// TestValidateTemporalValidity_ExactlyMaxDuration tests validity period exactly at max.
func TestValidateTemporalValidity_ExactlyMaxDuration(t *testing.T) {
	now := time.Now()
	cert := createCertWithValidity(t, now, now.Add(time.Hour))

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateTemporalValidity(cert, time.Hour)
	assert.NoError(t, err)
}

// TestValidateCodeSigningUsage_Success tests valid code signing certificate.
func TestValidateCodeSigningUsage_Success(t *testing.T) {
	cert := createCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateCodeSigningUsage(cert)
	assert.NoError(t, err)
}

// TestValidateCodeSigningUsage_MissingDigitalSignature tests missing digital signature key usage.
func TestValidateCodeSigningUsage_MissingDigitalSignature(t *testing.T) {
	cert := createCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateCodeSigningUsage(cert)
	assert.ErrorIs(t, err, ErrMissingDigitalSignature)
}

// TestValidateCodeSigningUsage_InappropriateKeyUsage tests problematic key usages.
func TestValidateCodeSigningUsage_InappropriateKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		keyUsage x509.KeyUsage
	}{
		{"KeyEncipherment", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		{"DataEncipherment", x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment},
		{"KeyAgreement", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement},
		{"CertSign", x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
		{"CRLSign", x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createCertWithKeyUsage(t, tt.keyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

			client, err := New(t.Context(), Options{})
			require.NoError(t, err)

			err = client.ValidateCodeSigningUsage(cert)
			assert.ErrorIs(t, err, ErrInappropriateKeyUsage)
		})
	}
}

// TestValidateCodeSigningUsage_MissingCodeSigningExtKeyUsage tests missing code signing EKU.
func TestValidateCodeSigningUsage_MissingCodeSigningExtKeyUsage(t *testing.T) {
	cert := createCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateCodeSigningUsage(cert)
	assert.ErrorIs(t, err, ErrMissingCodeSigningUsage)
}

// TestValidateCodeSigningUsage_InappropriateExtKeyUsage tests problematic extended key usages.
func TestValidateCodeSigningUsage_InappropriateExtKeyUsage(t *testing.T) {
	tests := []struct {
		name        string
		extKeyUsage []x509.ExtKeyUsage
	}{
		{"ServerAuth", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth}},
		{"ClientAuth", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageClientAuth}},
		{"EmailProtection", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection}},
		{"OCSPSigning", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageOCSPSigning}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, tt.extKeyUsage)

			client, err := New(t.Context(), Options{})
			require.NoError(t, err)

			err = client.ValidateCodeSigningUsage(cert)
			assert.ErrorIs(t, err, ErrInappropriateExtKeyUsage)
		})
	}
}

// TestValidateFulcioSpecificProperties_WithEmail tests certificate with email SAN.
func TestValidateFulcioSpecificProperties_WithEmail(t *testing.T) {
	cert := createCertWithSAN(t, []string{"test@example.com"}, nil)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioSpecificProperties(cert)
	assert.NoError(t, err)
}

// TestValidateFulcioSpecificProperties_WithURI tests certificate with URI SAN.
func TestValidateFulcioSpecificProperties_WithURI(t *testing.T) {
	uri, _ := url.Parse("https://example.com/identity")
	cert := createCertWithSAN(t, nil, []*url.URL{uri})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioSpecificProperties(cert)
	assert.NoError(t, err)
}

// TestValidateFulcioSpecificProperties_MissingSAN tests certificate missing SAN identity.
func TestValidateFulcioSpecificProperties_MissingSAN(t *testing.T) {
	// Create cert without email or URI SAN, but with OIDC issuer extension
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDIssuerV2, Value: []byte("issuer")},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioSpecificProperties(cert)
	assert.ErrorIs(t, err, ErrMissingSANIdentity)
}

// TestValidateFulcioExtensions_WithV2OID tests certificate with v2 OIDC issuer OID.
func TestValidateFulcioExtensions_WithV2OID(t *testing.T) {
	cert := createCertWithExtensions(t, []pkix.Extension{
		{Id: OIDIssuerV2, Value: []byte("https://issuer.example.com")},
	})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioExtensions(cert)
	assert.NoError(t, err)
}

// TestValidateFulcioExtensions_WithLegacyOID tests certificate with legacy OIDC issuer OID.
func TestValidateFulcioExtensions_WithLegacyOID(t *testing.T) {
	cert := createCertWithExtensions(t, []pkix.Extension{
		{Id: OIDIssuerLegacy, Value: []byte("https://issuer.example.com")},
	})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioExtensions(cert)
	assert.NoError(t, err)
}

// TestValidateFulcioExtensions_MissingOIDCIssuer tests certificate missing OIDC issuer extension.
func TestValidateFulcioExtensions_MissingOIDCIssuer(t *testing.T) {
	// Create certificate with a different extension (not OIDC issuer)
	cert := createCertWithExtensions(t, []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("some value")},
	})

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioExtensions(cert)
	assert.ErrorIs(t, err, ErrMissingOIDCIssuer)
}

// TestValidateFulcioExtensions_NoExtensions tests certificate with no extensions.
func TestValidateFulcioExtensions_NoExtensions(t *testing.T) {
	cert := createCertWithExtensions(t, nil)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	err = client.ValidateFulcioExtensions(cert)
	assert.ErrorIs(t, err, ErrMissingOIDCIssuer)
}

// TestValidateCertificateChain_Success tests successful chain validation.
func TestValidateCertificateChain_Success(t *testing.T) {
	caCert, caKey, caCertPEM := createCAForChainValidation(t)
	leafCert, _ := createValidCodeSigningCert(t, caCert, caKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{caCertPEM}},
			},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	err = client.ValidateCertificateChain(t.Context(), leafCert)
	assert.NoError(t, err)
}

// TestValidateCertificateChain_GetTrustRootsError tests chain validation when trust roots fail.
func TestValidateCertificateChain_GetTrustRootsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	cert := createCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	err = client.ValidateCertificateChain(t.Context(), cert)
	assert.Error(t, err)
}

// TestValidateCertificateChain_InvalidChain tests chain validation with untrusted cert.
func TestValidateCertificateChain_InvalidChain(t *testing.T) {
	// Create a different CA that didn't sign the leaf
	_, _, differentCACertPEM := createCAForChainValidation(t)

	// Create a self-signed leaf cert (not signed by the CA in trust bundle)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "untrusted",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	untrustedCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{differentCACertPEM}},
			},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	err = client.ValidateCertificateChain(t.Context(), untrustedCert)
	assert.Error(t, err)
}

// TestVerifyCertificate_Success tests full certificate verification success.
func TestVerifyCertificate_Success(t *testing.T) {
	caCert, caKey, caCertPEM := createCAForChainValidation(t)
	leafCert, _ := createValidCodeSigningCert(t, caCert, caKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{caCertPEM}},
			},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	err = client.VerifyCertificate(t.Context(), leafCert, 15*time.Minute)
	assert.NoError(t, err)
}

// TestVerifyCertificate_ChainValidationFailure tests verification failing on chain validation.
func TestVerifyCertificate_ChainValidationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	cert := createCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	err = client.VerifyCertificate(t.Context(), cert, time.Hour)
	assert.Error(t, err)
}

// TestVerifyCertificate_TemporalValidationFailure tests verification failing on temporal checks.
func TestVerifyCertificate_TemporalValidationFailure(t *testing.T) {
	caCert, caKey, caCertPEM := createCAForChainValidation(t)
	leafCert, _ := createValidCodeSigningCert(t, caCert, caKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{caCertPEM}},
			},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	// Use a very short max validity that the cert exceeds
	err = client.VerifyCertificate(t.Context(), leafCert, 1*time.Second)
	assert.ErrorIs(t, err, ErrValidityPeriodTooLong)
}

// TestVerifyCertificate_CodeSigningUsageFailure tests verification failing on key usage.
func TestVerifyCertificate_CodeSigningUsageFailure(t *testing.T) {
	caCert, caKey, caCertPEM := createCAForChainValidation(t)

	// Create leaf cert with bad key usage
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, // Bad: KeyEncipherment
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: []string{"test@example.com"},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDIssuerV2, Value: []byte("issuer")},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{caCertPEM}},
			},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	err = client.VerifyCertificate(t.Context(), leafCert, 15*time.Minute)
	assert.ErrorIs(t, err, ErrInappropriateKeyUsage)
}

// TestVerifyCertificate_FulcioPropertiesFailure tests verification failing on Fulcio properties.
func TestVerifyCertificate_FulcioPropertiesFailure(t *testing.T) {
	caCert, caKey, caCertPEM := createCAForChainValidation(t)

	// Create leaf cert without SAN identity
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// No EmailAddresses or URIs - will fail SAN check
		ExtraExtensions: []pkix.Extension{
			{Id: OIDIssuerV2, Value: []byte("issuer")},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{caCertPEM}},
			},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	err = client.VerifyCertificate(t.Context(), leafCert, 15*time.Minute)
	assert.ErrorIs(t, err, ErrMissingSANIdentity)
}

// TestOIDConstants tests that OID constants are correctly defined.
func TestOIDConstants(t *testing.T) {
	// OIDIssuerV2: 1.3.6.1.4.1.57264.1.8
	assert.Equal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, OIDIssuerV2)

	// OIDIssuerLegacy: 1.3.6.1.4.1.57264.1.1
	assert.Equal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, OIDIssuerLegacy)
}
