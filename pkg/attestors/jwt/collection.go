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
	"context"
	"slices"
	"time"

	jwtclient "github.com/thomsonreuters/stamp/pkg/clients/jwt"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	jwtpredicate "github.com/thomsonreuters/stamp/pkg/predicates/jwt/v1"
)

func (a *Attestor) collectData(ctx context.Context, _ core.Config) (*jwtpredicate.Predicate, error) {
	if a.jwtClient == nil {
		client, err := jwtclient.New(ctx, a.buildClientOptions()...)
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, attestorID, "collect", "failed to create JWT client")
		}
		a.jwtClient = client
	}

	predicate := &jwtpredicate.Predicate{}

	token, tokenSource, err := a.acquireToken(ctx)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, attestorID, "collect", "failed to acquire JWT token")
	}

	a.token = token
	a.tokenSource = tokenSource
	predicate.Source = tokenSource
	predicate.Digest = a.jwtClient.HashToken(token)

	tokenInfo, parseErr := a.jwtClient.ParseToken(token)
	if parseErr != nil {
		return nil, pkgerrors.WrapWithContext(parseErr, attestorID, "collect", "failed to parse JWT token")
	}

	predicate.Header = a.convertHeader(tokenInfo.Header)
	predicate.Claims = a.convertClaims(tokenInfo.Claims)
	a.parsedClaims = predicate.Claims

	if a.config.SkipVerification {
		predicate.Verification = VerificationSkipped
		predicate.Claims.CustomClaims = a.filterClaims(predicate.Claims.CustomClaims)
		return predicate, nil
	}

	if err := a.jwtClient.ValidateAlgorithm(tokenInfo.Header.Algorithm); err != nil {
		return nil, pkgerrors.WrapWithContext(err, attestorID, "collect", "algorithm validation failed")
	}

	verifyResult, verifyErr := a.jwtClient.VerifySignature(ctx, token)
	if verifyErr != nil || !verifyResult.Verified {
		predicate.Verification = VerificationUnverified
		if verifyResult != nil {
			predicate.Key = a.convertKeyInfo(verifyResult)
		}
		predicate.Claims.CustomClaims = a.filterClaims(predicate.Claims.CustomClaims)
		return predicate, nil
	}

	predicate.Verification = VerificationVerified
	predicate.Key = a.convertKeyInfo(verifyResult)
	predicate.Claims.CustomClaims = a.filterClaims(predicate.Claims.CustomClaims)

	return predicate, nil
}

func (a *Attestor) convertHeader(h jwtclient.Header) jwtpredicate.JWTHeader {
	return jwtpredicate.JWTHeader{
		Algorithm: h.Algorithm,
		Type:      h.Type,
		KeyID:     h.KeyID,
		X5C:       h.X5C,
		X5T:       h.X5T,
		X5TS256:   h.X5TS256,
	}
}

func (a *Attestor) convertClaims(c jwtclient.Claims) jwtpredicate.JWTClaims {
	return jwtpredicate.JWTClaims{
		Issuer:       c.Issuer,
		Subject:      c.Subject,
		Audience:     c.Audience,
		ExpiresAt:    c.ExpiresAt,
		NotBefore:    c.NotBefore,
		IssuedAt:     c.IssuedAt,
		JWTID:        c.JWTID,
		CustomClaims: c.CustomClaims,
	}
}

func (a *Attestor) convertKeyInfo(r *jwtclient.VerificationResult) *jwtpredicate.Key {
	return &jwtpredicate.Key{
		Method:       r.Method,
		Source:       r.Source,
		DiscoveryURL: r.DiscoveryURL,
		VerifiedAt:   time.Now(),
	}
}

func (a *Attestor) filterClaims(customClaims map[string]any) map[string]any {
	allowlist := a.config.ClaimsAllowlist
	denylist := a.config.ClaimsDenylist
	redactList := a.config.RedactClaims

	if a.config.IncludeAllClaims && len(allowlist) == 0 && len(denylist) == 0 && len(redactList) == 0 {
		return customClaims
	}

	if !a.config.IncludeAllClaims && len(allowlist) == 0 && len(denylist) == 0 && len(redactList) == 0 {
		return make(map[string]any)
	}

	filtered := make(map[string]any)

	for key, value := range customClaims {
		isDenied := slices.Contains(denylist, key)
		if isDenied {
			continue
		}

		if len(allowlist) > 0 {
			if !slices.Contains(allowlist, key) {
				continue
			}
		}

		shouldRedact := slices.Contains(redactList, key)

		if shouldRedact {
			filtered[key] = "[REDACTED]"
		} else {
			filtered[key] = value
		}
	}

	return filtered
}
