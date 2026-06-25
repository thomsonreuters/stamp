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

// Package fulcio provides a client for interacting with Fulcio CA to obtain code signing certificates.
package fulcio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	httpclient "github.com/thomsonreuters/stamp/pkg/http/client"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

const (
	// DefaultFulcioURL is the default Fulcio instance URL.
	DefaultFulcioURL = "https://fulcio.sigstore.dev"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// signingCertEndpoint is the Fulcio v2 API endpoint for certificate signing.
	signingCertEndpoint = "/api/v2/signingCert"

	// trustBundleEndpoint is the Fulcio v2 API endpoint for fetching the trust bundle.
	trustBundleEndpoint = "/api/v2/trustBundle"
)

// ClientIface defines the interface for the Fulcio client.
type ClientIface interface {
	// GetCertificate requests a code signing certificate from Fulcio.
	// It requires an OIDC token for authentication and a key pair for proof of possession.
	GetCertificate(ctx context.Context, req CertificateRequest) (*x509.Certificate, error)

	// FetchTrustBundle fetches the trust bundle from Fulcio API.
	FetchTrustBundle(ctx context.Context) (*TrustBundle, error)

	// GetTrustRoots fetches the trust bundle and returns a CertPool containing the root certificates.
	GetTrustRoots(ctx context.Context) (*x509.CertPool, error)

	// VerifyCertificate validates a Fulcio certificate.
	VerifyCertificate(ctx context.Context, cert *x509.Certificate, maxCertValidityDuration time.Duration) error

	// ValidateCertificateChain validates the certificate chain.
	ValidateCertificateChain(ctx context.Context, cert *x509.Certificate) error

	// ValidateTemporalValidity validates the temporal validity of the certificate.
	ValidateTemporalValidity(cert *x509.Certificate, maxCertValidityDuration time.Duration) error

	// ValidateCodeSigningUsage validates the code signing usage of the certificate.
	ValidateCodeSigningUsage(cert *x509.Certificate) error

	// ValidateFulcioSpecificProperties validates the Fulcio specific properties of the certificate.
	ValidateFulcioSpecificProperties(cert *x509.Certificate) error

	// ValidateFulcioExtensions validates the Fulcio extensions of the certificate.
	ValidateFulcioExtensions(cert *x509.Certificate) error
}

// TrustBundle represents the trust bundle returned by the Fulcio API.
type TrustBundle struct {
	Chains []TrustBundleChain `json:"chains"`
}

// TrustBundleChain represents a certificate chain from the Fulcio trust bundle.
type TrustBundleChain struct {
	Certificates []string `json:"certificates"`
}

// Client is the Fulcio client for obtaining code signing certificates.
type Client struct {
	httpClient *httpclient.Client
	opts       Options
}

// Options configures the Fulcio client.
type Options struct {
	// FulcioURL is the Fulcio server URL.
	// If empty, DefaultFulcioURL is used.
	FulcioURL string

	// Timeout is the HTTP request timeout.
	// If zero, DefaultTimeout is used.
	Timeout time.Duration

	// Insecure allows insecure HTTPS connections (skip TLS verification).
	// Should only be used for testing.
	Insecure bool

	// Logger is the logger to use. If nil, a noop logger is used.
	Logger logger.Logger
}

// CertificateRequest contains the parameters for requesting a certificate.
type CertificateRequest struct {
	// Token is the OIDC identity token for authentication.
	Token string

	// PublicKey is the public key to be included in the certificate.
	PublicKey crypto.PublicKey

	// PrivateKey is the private key used to create proof of possession.
	PrivateKey crypto.PrivateKey
}

// certificateRequestBody represents the Fulcio v2 API request body for certificate issuance.
type certificateRequestBody struct {
	PublicKeyRequest publicKeyRequest `json:"publicKeyRequest"`
}

// publicKeyRequest contains the public key information and proof of possession
// for the Fulcio certificate request. The proof demonstrates that the requester
// controls the private key corresponding to the public key.
type publicKeyRequest struct {
	PublicKey         publicKey `json:"publicKey"`
	ProofOfPossession string    `json:"proofOfPossession"`
}

// publicKey represents a public key in the Fulcio API request format.
// Algorithm specifies the key type (e.g., "ecdsa"), and Content contains
// the PEM-encoded public key.
type publicKey struct {
	Algorithm string `json:"algorithm"`
	Content   string `json:"content"`
}

// certificateResponse represents the Fulcio v2 API response containing the issued certificate.
type certificateResponse struct {
	SignedCertificateEmbeddedSct signedCertificate `json:"signedCertificateEmbeddedSct"`
	SignedCertificateDetachedSct signedCertificate `json:"signedCertificateDetachedSct"`
}

// signedCertificate contains the certificate chain returned by Fulcio.
// The chain includes the leaf certificate and any intermediate CA certificates.
type signedCertificate struct {
	Chain certificateChain `json:"chain"`
}

// certificateChain holds PEM-encoded certificates in the chain.
// The first certificate is typically the leaf (signing) certificate,
// followed by intermediate certificates up to (but not including) the root.
type certificateChain struct {
	Certificates []string `json:"certificates"`
}

// GetCertificate requests a code signing certificate from Fulcio.
func (c *Client) GetCertificate(ctx context.Context, req CertificateRequest) (*x509.Certificate, error) {
	if err := c.validateRequest(req); err != nil {
		return nil, err
	}

	proof, err := c.createProofOfPossession(req.Token, req.PrivateKey)
	if err != nil {
		return nil, err
	}

	requestBody, err := c.buildRequestBody(req.PublicKey, proof)
	if err != nil {
		return nil, err
	}

	responseBody, err := c.sendRequest(ctx, req.Token, requestBody)
	if err != nil {
		return nil, err
	}

	return c.parseResponse(responseBody)
}

func (c *Client) validateRequest(req CertificateRequest) error {
	if req.Token == "" {
		return ErrTokenRequired
	}
	if req.PublicKey == nil {
		return ErrPublicKeyRequired
	}
	if req.PrivateKey == nil {
		return ErrPrivateKeyRequired
	}
	return nil
}

func (c *Client) createProofOfPossession(token string, privateKey crypto.PrivateKey) ([]byte, error) {
	challenge, err := extractProofOfPossessionChallenge(token)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKeyType
	}

	signer, err := signature.LoadECDSASignerVerifier(ecdsaKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return signer.SignMessage(bytes.NewReader([]byte(challenge)))
}

func (c *Client) buildRequestBody(pubKey crypto.PublicKey, proof []byte) ([]byte, error) {
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return nil, err
	}

	reqBody := certificateRequestBody{
		PublicKeyRequest: publicKeyRequest{
			PublicKey: publicKey{
				Algorithm: "ecdsa",
				Content:   string(pubKeyPEM),
			},
			ProofOfPossession: base64.StdEncoding.EncodeToString(proof),
		},
	}

	return json.Marshal(reqBody)
}

func (c *Client) sendRequest(ctx context.Context, token string, body []byte) ([]byte, error) {
	requestURL := c.opts.FulcioURL + signingCertEndpoint

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetInsecure(c.opts.Insecure).
		SetBody(body).
		Post(requestURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	responseBody, err := resp.Bytes()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("certificate request failed with status %s: %s", resp.Status(), string(responseBody))
	}

	return responseBody, nil
}

func (c *Client) parseResponse(body []byte) (*x509.Certificate, error) {
	var certResp certificateResponse
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, err
	}

	var certPEM string
	switch {
	case len(certResp.SignedCertificateEmbeddedSct.Chain.Certificates) > 0:
		certPEM = certResp.SignedCertificateEmbeddedSct.Chain.Certificates[0]
	case len(certResp.SignedCertificateDetachedSct.Chain.Certificates) > 0:
		certPEM = certResp.SignedCertificateDetachedSct.Chain.Certificates[0]
	default:
		return nil, ErrNoCertificateInResponse
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEMFormat
	}

	return x509.ParseCertificate(block.Bytes)
}

// FetchTrustBundle fetches the trust bundle from Fulcio API.
func (c *Client) FetchTrustBundle(ctx context.Context) (*TrustBundle, error) {
	requestURL := c.opts.FulcioURL + trustBundleEndpoint

	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		SetInsecure(c.opts.Insecure).
		Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	responseBody, err := resp.Bytes()
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("trust bundle API returned status %s: %s", resp.Status(), string(responseBody))
	}

	var trustBundle TrustBundle
	if err := json.Unmarshal(responseBody, &trustBundle); err != nil {
		return nil, err
	}

	return &trustBundle, nil
}

// GetTrustRoots fetches the trust bundle and returns a CertPool containing the root certificates.
func (c *Client) GetTrustRoots(ctx context.Context) (*x509.CertPool, error) {
	trustBundle, err := c.FetchTrustBundle(ctx)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	addedCerts := 0

	for _, chain := range trustBundle.Chains {
		for _, certPEM := range chain.Certificates {
			if !pool.AppendCertsFromPEM([]byte(certPEM)) {
				certBytes, err := base64.StdEncoding.DecodeString(certPEM)
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					continue
				}
				pool.AddCert(cert)
				addedCerts++
			} else {
				addedCerts++
			}
		}
	}

	if addedCerts == 0 {
		return nil, ErrNoTrustRoots
	}

	return pool, nil
}

func newClient(ctx context.Context, opts Options) (ClientIface, error) {
	if opts.FulcioURL == "" {
		opts.FulcioURL = DefaultFulcioURL
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Logger == nil {
		opts.Logger = logger.NewNoop()
	}

	httpClient := httpclient.New(opts.Logger).SetTimeout(opts.Timeout)

	return &Client{
		httpClient: httpClient,
		opts:       opts,
	}, nil
}

// New is the constructor function for creating a Fulcio client.
// This variable can be replaced in tests for mocking.
var New = newClient
