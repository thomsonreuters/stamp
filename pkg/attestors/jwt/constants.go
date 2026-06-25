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

import (
	"errors"
)

const (
	attestorID   = "jwt"
	attestorName = "JWT Token Attestor"
	attestorDesc = "Verifies and attests JWT tokens used in build/deployment processes"
)

const (
	SourceFile       = "file"
	SourceStdin      = "stdin"
	SourceEnv        = "env"
	SourceGitHub     = "auto:github-actions"
	SourceAWS        = "auto:aws-irsa"
	SourceKubernetes = "auto:kubernetes"
)

const (
	VerificationVerified   = "verified"
	VerificationUnverified = "unverified"
	VerificationSkipped    = "skipped"
)

const (
	KeyMethodStaticKey     = "static-key"
	KeyMethodJWKS          = "jwks"
	KeyMethodOIDCDiscovery = "oidc-discovery"
)

var (
	DefaultAllowedAlgorithms = []string{
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512",
	}

	DefaultDeniedAlgorithms = []string{
		"none",
		"HS256", "HS384", "HS512",
	}
)

// SupportedAlgorithms lists all JWT signing algorithms supported by this attestor.
// Note: "none" is intentionally excluded as it represents unsigned tokens and is a security risk.
var SupportedAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
	"HS256", "HS384", "HS512",
	"EdDSA",
}

// ValidAlgorithms is used for input validation. Includes "none" only for
// validation purposes (to provide clear error messages when explicitly denied).
var ValidAlgorithms = append(append([]string{}, SupportedAlgorithms...), "none")

// StandardClaims defines the registered claim names per RFC 7519.
var StandardClaims = []string{
	"iss", "sub", "aud",
	"exp", "iat", "nbf",
	"jti",
}

var (
	ErrNoTokenSource        = errors.New("no JWT token source configured")
	ErrMultipleTokenSources = errors.New("multiple JWT token sources configured")
	ErrTokenNotFound        = errors.New("JWT token not found")
	ErrEmptyToken           = errors.New("JWT token is empty")
	ErrInvalidTokenFormat   = errors.New("invalid JWT token format")
	ErrUnsupportedAlgorithm = errors.New("unsupported JWT algorithm")
)
