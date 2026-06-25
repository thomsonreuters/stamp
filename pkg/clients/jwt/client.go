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

// Package jwt provides a JWT client for parsing, validating, and verifying JWT tokens.
// It uses lestrrat-go/jwx/v2 for JWT parsing, JWKS handling, and signature verification.
package jwt

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/thomsonreuters/stamp/pkg/crypto/keys"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/http/transport"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// ClientIface defines the interface for JWT operations.
type ClientIface interface {
	// ParseToken parses a JWT token and returns header and claims.
	ParseToken(token string) (*TokenInfo, error)

	// VerifySignature verifies the JWT signature and returns verification result.
	VerifySignature(ctx context.Context, token string) (*VerificationResult, error)

	// FetchJWKS fetches JWKS from a URL and returns the key set.
	FetchJWKS(ctx context.Context, url string) (jwk.Set, error)

	// DiscoverJWKS performs OIDC discovery and fetches JWKS.
	DiscoverJWKS(ctx context.Context, issuer string) (jwk.Set, error)

	// LoadPublicKey loads a public key from a PEM file.
	LoadPublicKey(filePath string) (crypto.PublicKey, error)

	// FindKey finds the appropriate key for verification from configured sources.
	FindKey(ctx context.Context, token string) (*KeyInfo, error)

	// HashToken computes SHA-256 hash of the token.
	HashToken(token string) string

	// ValidateAlgorithm checks if the algorithm is allowed.
	ValidateAlgorithm(algorithm string) error
}

// Client implements JWT operations using lestrrat-go/jwx.
type Client struct {
	logger     logger.Logger
	opts       Options
	httpClient *http.Client
}

// newClient creates a new JWT client with the given options.
func newClient(ctx context.Context, opts ...Option) (ClientIface, error) {
	options := DefaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	if options.Logger == nil {
		options.Logger = logger.NewNoop()
	}

	hc, err := transport.NewHTTPClient(transport.Options{
		Timeout:       options.HTTPTimeout,
		AllowInsecure: options.AllowInsecure,
		CACertFile:    options.CACertFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &Client{
		logger:     options.Logger,
		opts:       options,
		httpClient: hc,
	}, nil
}

// New is the constructor function (replaceable for testing).
var New = newClient

// ParseToken parses a JWT token and extracts header and claims.
func (c *Client) ParseToken(tokenString string) (*TokenInfo, error) {
	if tokenString == "" {
		return nil, ErrEmptyToken
	}

	token, err := jwt.ParseString(tokenString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, pkgerrors.WrapWithContext(ErrInvalidTokenFormat, "jwt_client", "parse", err.Error())
	}

	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return nil, pkgerrors.WrapWithContext(ErrInvalidHeader, "jwt_client", "parse_header", err.Error())
	}

	return &TokenInfo{
		Header: c.extractHeader(msg),
		Claims: c.extractClaims(token),
	}, nil
}

// extractHeader extracts header information from a JWS message.
func (c *Client) extractHeader(msg *jws.Message) Header {
	header := Header{}

	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return header
	}

	protectedHeaders := signatures[0].ProtectedHeaders()
	if protectedHeaders == nil {
		return header
	}

	if alg := protectedHeaders.Algorithm(); alg != "" {
		header.Algorithm = alg.String()
	}
	if typ := protectedHeaders.Type(); typ != "" {
		header.Type = typ
	}
	if kid := protectedHeaders.KeyID(); kid != "" {
		header.KeyID = kid
	}
	if x5c := protectedHeaders.X509CertChain(); x5c != nil {
		for i := range x5c.Len() {
			cert, ok := x5c.Get(i)
			if ok {
				header.X5C = append(header.X5C, string(cert))
			}
		}
	}
	if x5t := protectedHeaders.X509CertThumbprint(); x5t != "" {
		header.X5T = x5t
	}
	if x5ts256 := protectedHeaders.X509CertThumbprintS256(); x5ts256 != "" {
		header.X5TS256 = x5ts256
	}

	return header
}

// extractClaims extracts claims from a parsed JWT token.
func (c *Client) extractClaims(token jwt.Token) Claims {
	claims := Claims{
		CustomClaims: make(map[string]any),
	}

	if iss := token.Issuer(); iss != "" {
		claims.Issuer = iss
	}
	if sub := token.Subject(); sub != "" {
		claims.Subject = sub
	}
	if aud := token.Audience(); len(aud) > 0 {
		if len(aud) == 1 {
			claims.Audience = aud[0]
		} else {
			claims.Audience = aud
		}
	}
	if exp := token.Expiration(); !exp.IsZero() {
		claims.ExpiresAt = exp.Unix()
	}
	if nbf := token.NotBefore(); !nbf.IsZero() {
		claims.NotBefore = nbf.Unix()
	}
	if iat := token.IssuedAt(); !iat.IsZero() {
		claims.IssuedAt = iat.Unix()
	}
	if jti := token.JwtID(); jti != "" {
		claims.JWTID = jti
	}

	for key, val := range token.PrivateClaims() {
		if !slices.Contains(StandardClaims, key) {
			claims.CustomClaims[key] = val
		}
	}

	return claims
}

// VerifySignature verifies the JWT signature using configured key sources.
// Note: The lestrrat-go/jwx/v2 library validates exp, nbf, and iat by default.
func (c *Client) VerifySignature(ctx context.Context, tokenString string) (*VerificationResult, error) {
	result := &VerificationResult{VerifiedAt: time.Now()}

	keyInfo, err := c.FindKey(ctx, tokenString)
	if err != nil {
		result.Error = err
		return result, err
	}

	result.Method = keyInfo.Method
	result.Source = keyInfo.Source
	result.DiscoveryURL = keyInfo.DiscoveryURL
	result.KeyID = keyInfo.KeyID
	result.Algorithm = keyInfo.Algorithm

	var parseOpts []jwt.ParseOption
	if keyInfo.PublicKey != nil {
		alg := jwa.KeyAlgorithmFrom(keyInfo.Algorithm)
		parseOpts = append(parseOpts, jwt.WithKey(alg, keyInfo.PublicKey))
	}

	_, err = jwt.ParseString(tokenString, parseOpts...)
	if err != nil {
		result.Error = pkgerrors.WrapWithContext(ErrVerificationFailed, "jwt_client", "verify", err.Error())
		return result, result.Error
	}

	result.Verified = true
	return result, nil
}

// FetchJWKS fetches JWKS from a URL.
func (c *Client) FetchJWKS(ctx context.Context, url string) (jwk.Set, error) {
	c.logger.Debug("fetching JWKS", "url", url)

	keySet, err := jwk.Fetch(ctx, url, jwk.WithHTTPClient(c.httpClient))
	if err != nil {
		return nil, pkgerrors.WrapWithContext(ErrJWKSFetchFailed, "jwt_client", "fetch_jwks", err.Error())
	}

	if keySet.Len() == 0 {
		return nil, ErrNoKeysInJWKS
	}

	c.logger.Info("JWKS fetched successfully", "url", url, "key_count", keySet.Len())
	return keySet, nil
}

// DiscoverJWKS performs OIDC discovery and fetches JWKS.
func (c *Client) DiscoverJWKS(ctx context.Context, issuer string) (jwk.Set, error) {
	c.logger.Debug("performing OIDC discovery", "issuer", issuer)

	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	keySet, err := c.fetchJWKSFromOIDC(ctx, discoveryURL)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(ErrOIDCDiscoveryFailed, "jwt_client", "discover", err.Error())
	}

	return keySet, nil
}

func (c *Client) fetchJWKSFromOIDC(ctx context.Context, discoveryURL string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "jwt_client", "oidc_discovery", "failed to create request")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(ErrOIDCDiscoveryFetchFailed, "jwt_client", "oidc_discovery", err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, pkgerrors.WrapWithContext(ErrOIDCDiscoveryStatusError, "jwt_client", "oidc_discovery",
			fmt.Sprintf("status %d", resp.StatusCode))
	}

	var discoveryDoc struct {
		JWKSURI string `json:"jwks_uri"`
	}

	if err := parseJSONReader(resp.Body, &discoveryDoc); err != nil {
		return nil, pkgerrors.WrapWithContext(ErrOIDCDiscoveryParseFailed, "jwt_client", "oidc_discovery", err.Error())
	}

	if discoveryDoc.JWKSURI == "" {
		return nil, ErrMissingJWKSURI
	}

	c.logger.Info("OIDC discovery successful", "jwks_uri", discoveryDoc.JWKSURI)
	return c.FetchJWKS(ctx, discoveryDoc.JWKSURI)
}

// LoadPublicKey loads a public key from a PEM file using pkg/crypto/keys.
func (c *Client) LoadPublicKey(filePath string) (crypto.PublicKey, error) {
	c.logger.Debug("loading public key from file", "path", filePath)

	publicKey, err := keys.LoadPublicKeyFromFile(filePath)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(ErrInvalidPEMFormat, "jwt_client", "load_key", err.Error())
	}

	c.logger.Info("public key loaded successfully", "path", filePath)
	return publicKey, nil
}

// FindKey finds the appropriate key for verification.
func (c *Client) FindKey(ctx context.Context, tokenString string) (*KeyInfo, error) {
	keyInfo := &KeyInfo{VerifiedAt: time.Now()}

	tokenInfo, err := c.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	keyInfo.KeyID = tokenInfo.Header.KeyID
	keyInfo.Algorithm = tokenInfo.Header.Algorithm

	if c.opts.PublicKeyFile != "" {
		c.logger.Info("using static public key", "path", c.opts.PublicKeyFile)
		publicKey, err := c.LoadPublicKey(c.opts.PublicKeyFile)
		if err != nil {
			return nil, err
		}
		keyInfo.Method = "static-key"
		keyInfo.Source = c.opts.PublicKeyFile
		keyInfo.PublicKey = publicKey
		return keyInfo, nil
	}

	if c.opts.JWKSURL != "" {
		c.logger.Info("fetching JWKS from explicit URL", "url", c.opts.JWKSURL)
		keySet, err := c.FetchJWKS(ctx, c.opts.JWKSURL)
		if err != nil {
			return nil, err
		}
		return c.findKeyInSet(keySet, keyInfo, "jwks", c.opts.JWKSURL)
	}

	if c.opts.OIDCDiscoveryURL != "" {
		c.logger.Info("using explicit OIDC discovery", "url", c.opts.OIDCDiscoveryURL)
		keySet, err := c.fetchJWKSFromOIDC(ctx, c.opts.OIDCDiscoveryURL)
		if err != nil {
			return nil, err
		}
		keyInfo.DiscoveryURL = c.opts.OIDCDiscoveryURL
		return c.findKeyInSet(keySet, keyInfo, "oidc-discovery", c.opts.OIDCDiscoveryURL)
	}

	if tokenInfo.Claims.Issuer != "" {
		c.logger.Info("auto-discovering JWKS from token issuer", "issuer", tokenInfo.Claims.Issuer)
		keySet, err := c.DiscoverJWKS(ctx, tokenInfo.Claims.Issuer)
		if err != nil {
			return nil, err
		}
		keyInfo.DiscoveryURL = strings.TrimSuffix(tokenInfo.Claims.Issuer, "/") + "/.well-known/openid-configuration"
		return c.findKeyInSet(keySet, keyInfo, "oidc-discovery", tokenInfo.Claims.Issuer)
	}

	return nil, ErrNoVerificationKey
}

func (c *Client) findKeyInSet(keySet jwk.Set, keyInfo *KeyInfo, method, source string) (*KeyInfo, error) {
	keyInfo.Method = method
	keyInfo.Source = source

	var key jwk.Key
	var found bool

	if keyInfo.KeyID != "" {
		key, found = keySet.LookupKeyID(keyInfo.KeyID)
	}

	if !found && keySet.Len() > 0 {
		key, _ = keySet.Key(0)
		found = true
		c.logger.Debug("using first key from JWKS (no kid match)")
	}

	if !found {
		return nil, ErrKeyNotFound
	}

	var publicKey crypto.PublicKey
	if err := key.Raw(&publicKey); err != nil {
		return nil, pkgerrors.WrapWithContext(ErrUnsupportedKeyType, "jwt_client", "find_key", err.Error())
	}

	keyInfo.PublicKey = publicKey
	if kid := key.KeyID(); kid != "" {
		keyInfo.KeyID = kid
	}
	if alg := key.Algorithm().String(); alg != "" {
		keyInfo.Algorithm = alg
	}

	return keyInfo, nil
}

// HashToken computes SHA-256 hash of the token.
func (c *Client) HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// ValidateAlgorithm checks if the algorithm is allowed.
func (c *Client) ValidateAlgorithm(algorithm string) error {
	if slices.Contains(c.opts.DeniedAlgorithms, algorithm) {
		return pkgerrors.WrapWithContext(ErrAlgorithmDenied, "jwt_client", "validate_alg",
			fmt.Sprintf("algorithm %s is denied", algorithm))
	}

	if len(c.opts.AllowedAlgorithms) == 0 {
		return nil
	}

	if slices.Contains(c.opts.AllowedAlgorithms, algorithm) {
		return nil
	}

	return pkgerrors.WrapWithContext(ErrAlgorithmNotAllowed, "jwt_client", "validate_alg",
		fmt.Sprintf("algorithm %s not in allowed list", algorithm))
}
