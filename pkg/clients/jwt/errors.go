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

package jwt

import "errors"

var (
	ErrInvalidTokenFormat       = errors.New("invalid JWT token format")
	ErrEmptyToken               = errors.New("empty JWT token")
	ErrInvalidHeader            = errors.New("invalid JWT header")
	ErrInvalidClaims            = errors.New("invalid JWT claims")
	ErrAlgorithmDenied          = errors.New("algorithm is denied")
	ErrAlgorithmNotAllowed      = errors.New("algorithm not in allowed list")
	ErrUnsupportedAlgorithm     = errors.New("unsupported algorithm")
	ErrNoVerificationKey        = errors.New("no verification key available")
	ErrKeyNotFound              = errors.New("key not found in JWKS")
	ErrInvalidPEMFormat         = errors.New("invalid PEM format")
	ErrUnsupportedKeyType       = errors.New("unsupported key type")
	ErrJWKSFetchFailed          = errors.New("JWKS fetch failed")
	ErrJWKSParseError           = errors.New("JWKS parse error")
	ErrNoKeysInJWKS             = errors.New("no keys in JWKS")
	ErrOIDCDiscoveryFailed      = errors.New("OIDC discovery failed")
	ErrOIDCDiscoveryFetchFailed = errors.New("failed to fetch discovery document")
	ErrOIDCDiscoveryStatusError = errors.New("discovery document returned error status")
	ErrOIDCDiscoveryParseFailed = errors.New("failed to parse discovery document")
	ErrMissingJWKSURI           = errors.New("missing jwks_uri in discovery document")
	ErrMissingIssuer            = errors.New("missing issuer claim")
	ErrVerificationFailed       = errors.New("signature verification failed")
	ErrTokenExpired             = errors.New("token has expired")
	ErrTokenNotYetValid         = errors.New("token not yet valid")
)
