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

package githubworkflow

import (
	"context"
	"time"

	"github.com/thomsonreuters/stamp/pkg/clients/github"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	ghworkflowpredicate "github.com/thomsonreuters/stamp/pkg/predicates/github-workflow/v1"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

const (
	// DefaultOIDCIssuer is the default OIDC issuer for GitHub Actions tokens.
	DefaultOIDCIssuer = github.DefaultOIDCIssuer
)

// fetchAndVerifyOIDCToken fetches a GitHub Actions OIDC token, verifies its signature and issuer,
// and returns OIDCInfo metadata along with verified custom claims.
func (a *Attestor) fetchAndVerifyOIDCToken(ctx context.Context) (*ghworkflowpredicate.OIDCInfo, map[string]any, error) {
	a.logger.InfoContext(ctx, "fetching OIDC token from GitHub Actions", "audience", a.config.OIDCAudience)

	if !github.IsOIDCEnvAvailable() {
		err := pkgerrors.NewWithContext(id, "oidc",
			"GitHub Actions OIDC environment not detected: workflow must have 'permissions.id-token: write'").Suggest(
			"Add to your workflow YAML:",
			"permissions:",
			"  id-token: write",
			"  contents: read",
		)
		a.logger.ErrorContext(ctx, "OIDC not available (REQUIRED)", "error", err.Error())
		return nil, nil, err
	}

	fetchedAt := time.Now()

	token, err := a.githubClient.FetchIDToken(ctx, a.config.OIDCAudience)
	if err != nil {
		err = pkgerrors.WrapWithContext(err, id, "oidc", "failed to fetch OIDC token")
		a.logger.ErrorContext(ctx, "failed to fetch OIDC token", "error", err.Error())
		return nil, nil, err
	}

	a.logger.DebugContext(ctx, "OIDC token fetched successfully")

	a.logger.InfoContext(ctx, "verifying OIDC token", "audience", a.config.OIDCAudience)

	result, err := utils.VerifyOIDCToken(ctx, a.jwtClient, token, utils.OIDCVerifyOptions{
		TrustedIssuers:   a.resolveOIDCIssuers(),
		ExpectedAudience: a.config.OIDCAudience,
	})
	if err != nil {
		a.logger.ErrorContext(ctx, "OIDC verification failed", "error", err.Error())
		return nil, nil, pkgerrors.WrapWithContext(err, id, "oidc", "token verification failed")
	}

	oidcInfo := &ghworkflowpredicate.OIDCInfo{
		TokenHash:    result.TokenHash,
		Issuer:       result.TokenInfo.Claims.Issuer,
		Subject:      result.TokenInfo.Claims.Subject,
		Audience:     result.TokenInfo.Claims.Audience,
		ExpiresAt:    result.TokenInfo.Claims.ExpiresAt,
		IssuedAt:     result.TokenInfo.Claims.IssuedAt,
		NotBefore:    result.TokenInfo.Claims.NotBefore,
		JWTID:        result.TokenInfo.Claims.JWTID,
		FetchedAt:    fetchedAt.Unix(),
		KeyID:        result.TokenInfo.Header.KeyID,
		Verified:     result.Verification.Verified,
		VerifiedAt:   result.Verification.VerifiedAt.Unix(),
		VerifyMethod: result.Verification.Method,
		VerifySource: result.Verification.Source,
		DiscoveryURL: result.Verification.DiscoveryURL,
		KeyAlgorithm: result.Verification.Algorithm,
	}

	a.logger.InfoContext(ctx, "OIDC token verified successfully",
		"method", result.Verification.Method,
		"source", result.Verification.Source,
		"algorithm", result.Verification.Algorithm,
		"issuer", result.TokenInfo.Claims.Issuer)

	return oidcInfo, result.TokenInfo.Claims.CustomClaims, nil
}

// resolveOIDCIssuers auto-derives the list of trusted OIDC issuers from GITHUB_SERVER_URL.
// For github.com it returns the default issuer; for GHES it derives the issuer from the server URL.
func (a *Attestor) resolveOIDCIssuers() []string {
	return github.DeriveOIDCIssuers()
}
