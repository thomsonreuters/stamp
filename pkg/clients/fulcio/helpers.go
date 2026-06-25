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
	"github.com/golang-jwt/jwt/v5"
)

// extractTokenSubject extracts the subject claim from a JWT token.
// It parses the token without validating the signature since we only need the claims.
func extractTokenSubject(tokenString string) (string, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidJWTClaims
	}

	subject, err := claims.GetSubject()
	if err != nil {
		return "", err
	}

	if subject == "" {
		return "", ErrNoJWTSubject
	}

	return subject, nil
}

// extractTokenEmail extracts the email claim from a JWT token.
// Returns empty string if email claim is not present.
func extractTokenEmail(tokenString string) (string, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidJWTClaims
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", nil // Email not present, not an error
	}

	return email, nil
}

// extractProofOfPossessionChallenge extracts the value to sign for proof of possession.
// Fulcio expects the email claim if present, otherwise the subject claim.
// This follows the Sigstore Fulcio v2 API specification.
func extractProofOfPossessionChallenge(tokenString string) (string, error) {
	// First try to get email
	email, err := extractTokenEmail(tokenString)
	if err != nil {
		return "", err
	}
	if email != "" {
		return email, nil
	}

	// Fall back to subject
	return extractTokenSubject(tokenString)
}
