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

import "errors"

// Request validation errors.
var (
	// ErrTokenRequired is returned when OIDC token is missing.
	ErrTokenRequired = errors.New("OIDC token is required")

	// ErrPublicKeyRequired is returned when public key is missing.
	ErrPublicKeyRequired = errors.New("public key is required")

	// ErrPrivateKeyRequired is returned when private key is missing.
	ErrPrivateKeyRequired = errors.New("private key is required")

	// ErrUnsupportedKeyType is returned when a non-ECDSA key is used.
	ErrUnsupportedKeyType = errors.New("only ECDSA keys are supported for Fulcio")
)

// Certificate response errors.
var (
	// ErrNoCertificateInResponse is returned when Fulcio response contains no certificate.
	ErrNoCertificateInResponse = errors.New("no certificate found in Fulcio response")

	// ErrInvalidPEMFormat is returned when certificate PEM format is invalid.
	ErrInvalidPEMFormat = errors.New("invalid PEM certificate format in Fulcio response")

	// ErrNoTrustRoots is returned when no valid certificates found in trust bundle.
	ErrNoTrustRoots = errors.New("no valid certificates found in Fulcio trust bundle")
)

// Certificate validation errors.
var (
	// ErrInvalidValidityPeriod is returned when NotAfter is before NotBefore.
	ErrInvalidValidityPeriod = errors.New("certificate validity period is invalid: NotAfter before NotBefore")

	// ErrValidityPeriodTooLong is returned when certificate validity exceeds maximum allowed.
	ErrValidityPeriodTooLong = errors.New("certificate validity period too long")

	// ErrMissingDigitalSignature is returned when certificate lacks digital signature key usage.
	ErrMissingDigitalSignature = errors.New("certificate missing required digital signature key usage")

	// ErrInappropriateKeyUsage is returned when certificate has key usage flags inappropriate for code signing.
	ErrInappropriateKeyUsage = errors.New("certificate has inappropriate key usage flag for code signing")

	// ErrMissingCodeSigningUsage is returned when certificate lacks code signing extended key usage.
	ErrMissingCodeSigningUsage = errors.New("certificate missing required code signing extended key usage")

	// ErrInappropriateExtKeyUsage is returned when certificate has extended key usage inappropriate for code signing.
	ErrInappropriateExtKeyUsage = errors.New("certificate has inappropriate extended key usage for code signing")

	// ErrMissingSANIdentity is returned when Fulcio certificate lacks identity in SAN.
	ErrMissingSANIdentity = errors.New("fulcio certificate missing identity in SAN")

	// ErrMissingOIDCIssuer is returned when certificate lacks required OIDC issuer extension.
	ErrMissingOIDCIssuer = errors.New("certificate missing required OIDC issuer extension")
)

// JWT errors.
var (
	// ErrInvalidJWTClaims is returned when JWT claims format is invalid.
	ErrInvalidJWTClaims = errors.New("invalid JWT claims format")

	// ErrNoJWTSubject is returned when JWT token has no subject claim.
	ErrNoJWTSubject = errors.New("no subject claim found in JWT token")
)
