// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"errors"
	"fmt"
	"slices"

	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
)

// OIDCVerifyOptions configures the OIDC token verification behavior.
type OIDCVerifyOptions struct {
	TrustedIssuers   []string
	ExpectedAudience string
}

// OIDCVerifyResult holds the outcome of an OIDC token verification.
type OIDCVerifyResult struct {
	TokenInfo    *jwtclient.TokenInfo
	TokenHash    string
	Verification *jwtclient.VerificationResult
}

// VerifyOIDCToken verifies an OIDC token's signature, issuer, and audience.
func VerifyOIDCToken(ctx context.Context, jwtClient jwtclient.ClientIface, rawToken string, opts OIDCVerifyOptions) (*OIDCVerifyResult, error) {
	tokenHash := jwtClient.HashToken(rawToken)

	tokenInfo, err := jwtClient.ParseToken(rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OIDC token: %w", err)
	}

	if issuerErr := ValidateIssuer(tokenInfo.Claims.Issuer, opts.TrustedIssuers); issuerErr != nil {
		return nil, fmt.Errorf("issuer validation failed: %w", issuerErr)
	}

	verifyResult, err := jwtClient.VerifySignature(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	if !verifyResult.Verified {
		return nil, errors.New("token signature is invalid")
	}

	if opts.ExpectedAudience != "" {
		if tokenInfo.Claims.Audience == nil {
			return nil, fmt.Errorf("OIDC token missing audience claim: expected %q", opts.ExpectedAudience)
		}
		if !AudienceContains(tokenInfo.Claims.Audience, opts.ExpectedAudience) {
			return nil, fmt.Errorf("OIDC token audience mismatch: expected %q, got %v", opts.ExpectedAudience, tokenInfo.Claims.Audience)
		}
	}

	return &OIDCVerifyResult{
		TokenInfo:    tokenInfo,
		TokenHash:    tokenHash,
		Verification: verifyResult,
	}, nil
}

// ValidateIssuer checks whether the issuer is in the allowed list.
func ValidateIssuer(issuer string, allowedIssuers []string) error {
	if len(allowedIssuers) == 0 {
		return nil
	}

	if !slices.Contains(allowedIssuers, issuer) {
		return fmt.Errorf("untrusted OIDC issuer: %q not in allowed list %v", issuer, allowedIssuers)
	}

	return nil
}

// AudienceContains checks whether the expected audience is present in aud.
func AudienceContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []string:
		return slices.Contains(v, expected)
	default:
		return false
	}
}
