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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestJWT creates a simple test JWT token with a subject claim.
func createTestJWT(subject string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + subject + `","iss":"test"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return header + "." + payload + "." + signature
}

// createTestCertificate creates a test X.509 certificate.
func createTestCertificate(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-subject",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	// Self-sign with random key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM)
}

func TestNew(t *testing.T) {
	client, err := New(t.Context(), Options{})

	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNew_WithOptions(t *testing.T) {
	opts := Options{
		FulcioURL: "https://custom-fulcio.example.com",
		Timeout:   60 * time.Second,
		Insecure:  true,
	}

	client, err := New(t.Context(), opts)

	require.NoError(t, err)
	assert.NotNil(t, client)

	c, _ := client.(*Client)
	assert.Equal(t, "https://custom-fulcio.example.com", c.opts.FulcioURL)
	assert.Equal(t, 60*time.Second, c.opts.Timeout)
	assert.True(t, c.opts.Insecure)
}

func TestNew_DefaultValues(t *testing.T) {
	client, err := New(t.Context(), Options{})

	require.NoError(t, err)
	c, _ := client.(*Client)
	assert.Equal(t, DefaultFulcioURL, c.opts.FulcioURL)
	assert.Equal(t, DefaultTimeout, c.opts.Timeout)
	assert.False(t, c.opts.Insecure)
}

func TestClient_GetCertificate_Success(t *testing.T) {
	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testToken := createTestJWT("test-subject@example.com")
	testCertPEM := createTestCertificate(t, &privateKey.PublicKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v2/signingCert", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := certificateResponse{
			SignedCertificateEmbeddedSct: signedCertificate{
				Chain: certificateChain{
					Certificates: []string{testCertPEM},
				},
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

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      testToken,
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test-subject", cert.Subject.CommonName)
}

func TestClient_GetCertificate_DetachedSCT(t *testing.T) {
	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testToken := createTestJWT("test-subject@example.com")
	testCertPEM := createTestCertificate(t, &privateKey.PublicKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return certificate in detached SCT response
		resp := certificateResponse{
			SignedCertificateDetachedSct: signedCertificate{
				Chain: certificateChain{
					Certificates: []string{testCertPEM},
				},
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

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      testToken,
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestClient_GetCertificate_MissingToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      "",
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "OIDC token is required")
}

func TestClient_GetCertificate_MissingPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  nil,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "public key is required")
}

func TestClient_GetCertificate_MissingPrivateKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, err := New(t.Context(), Options{})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: nil,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "private key is required")
}

//nolint:dupl // Test cases have similar setup but test different error conditions
func TestClient_GetCertificate_ServerError(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "500")
}

//nolint:dupl // Test cases have similar setup but test different error conditions
func TestClient_GetCertificate_Unauthorized(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid token"}`))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "401")
}

func TestClient_GetCertificate_EmptyCertificateResponse(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return empty certificate chains
		resp := certificateResponse{}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "no certificate found")
}

func TestClient_GetCertificate_InvalidJSON(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
}

func TestClient_GetCertificate_InvalidCertificatePEM(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := certificateResponse{
			SignedCertificateEmbeddedSct: signedCertificate{
				Chain: certificateChain{
					Certificates: []string{"not a valid PEM certificate"},
				},
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

	cert, err := client.GetCertificate(t.Context(), CertificateRequest{
		Token:      createTestJWT("test@example.com"),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "invalid PEM")
}

func TestDefaultFulcioURL(t *testing.T) {
	assert.Equal(t, "https://fulcio.sigstore.dev", DefaultFulcioURL)
}

func TestDefaultTimeout(t *testing.T) {
	assert.Equal(t, 30*time.Second, DefaultTimeout)
}

func TestClient_FetchTrustBundle_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v2/trustBundle", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{
					Certificates: []string{
						"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
						"-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
					},
				},
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

	trustBundle, err := client.FetchTrustBundle(t.Context())

	require.NoError(t, err)
	assert.NotNil(t, trustBundle)
	assert.Len(t, trustBundle.Chains, 1)
	assert.Len(t, trustBundle.Chains[0].Certificates, 2)
}

func TestClient_FetchTrustBundle_MultipleChains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{"cert1", "cert2"}},
				{Certificates: []string{"cert3"}},
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

	trustBundle, err := client.FetchTrustBundle(t.Context())

	require.NoError(t, err)
	assert.Len(t, trustBundle.Chains, 2)
	assert.Len(t, trustBundle.Chains[0].Certificates, 2)
	assert.Len(t, trustBundle.Chains[1].Certificates, 1)
}

func TestClient_FetchTrustBundle_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	trustBundle, err := client.FetchTrustBundle(t.Context())

	require.Error(t, err)
	assert.Nil(t, trustBundle)
	assert.Contains(t, err.Error(), "500")
}

func TestClient_FetchTrustBundle_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	trustBundle, err := client.FetchTrustBundle(t.Context())

	require.Error(t, err)
	assert.Nil(t, trustBundle)
}

func TestClient_FetchTrustBundle_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	trustBundle, err := client.FetchTrustBundle(t.Context())

	require.NoError(t, err)
	assert.NotNil(t, trustBundle)
	assert.Empty(t, trustBundle.Chains)
}

func TestClient_FetchTrustBundle_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	trustBundle, err := client.FetchTrustBundle(t.Context())

	require.Error(t, err)
	assert.Nil(t, trustBundle)
	assert.Contains(t, err.Error(), "404")
}

func TestClient_GetTrustRoots_Success(t *testing.T) {
	// Create a test root certificate
	rootCertPEM := createTestRootCertificate(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{rootCertPEM}},
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

	pool, err := client.GetTrustRoots(t.Context())

	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestClient_GetTrustRoots_MultipleChainsAndCerts(t *testing.T) {
	// Create test root certificates
	rootCertPEM1 := createTestRootCertificate(t)
	rootCertPEM2 := createTestRootCertificate(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{rootCertPEM1}},
				{Certificates: []string{rootCertPEM2}},
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

	pool, err := client.GetTrustRoots(t.Context())

	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestClient_GetTrustRoots_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	pool, err := client.GetTrustRoots(t.Context())

	require.Error(t, err)
	assert.Nil(t, pool)
}

func TestClient_GetTrustRoots_EmptyBundle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{},
		}
		encodeErr := json.NewEncoder(w).Encode(resp)
		assert.NoError(t, encodeErr)
	}))
	defer server.Close()

	client, err := New(t.Context(), Options{
		FulcioURL: server.URL,
	})
	require.NoError(t, err)

	pool, err := client.GetTrustRoots(t.Context())

	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "no valid certificates found")
}

func TestClient_GetTrustRoots_InvalidCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TrustBundle{
			Chains: []TrustBundleChain{
				{Certificates: []string{"not a valid cert", "also invalid"}},
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

	pool, err := client.GetTrustRoots(t.Context())

	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "no valid certificates found")
}

// createTestRootCertificate creates a self-signed root certificate for testing.
func createTestRootCertificate(t *testing.T) string {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM)
}
