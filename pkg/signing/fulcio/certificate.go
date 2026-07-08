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
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/clients/fulcio"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/clients/spire"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/signing"
)

// ResolveToken resolves an OIDC token using the standard precedence:
//  1. Direct token from config.Token (--oidc-token)
//  2. Token from file (--oidc-token-file)
//  3. SPIRE workload API (--spire or --socket)
//  4. GitHub Actions (--github)
//  5. Auto-detection: GitHub environment or default SPIRE socket (last resort).
func ResolveToken(ctx context.Context, config signing.FulcioSignerConfig) (string, error) {
	if config.Token != "" {
		return config.Token, nil
	}

	if config.TokenPath != "" {
		tokenBytes, err := os.ReadFile(config.TokenPath)
		if err != nil {
			return "", pkgerrors.WrapWithContext(err, "fulcio", "resolve-token", fmt.Sprintf("failed to read token file %s", config.TokenPath))
		}
		return strings.TrimSpace(string(tokenBytes)), nil
	}

	if config.UseSpire || config.SpireAgentSocket != "" {
		token, err := getSpireWorkloadToken(ctx, config)
		if err != nil {
			return "", err
		}
		return token, nil
	}

	if config.UseGitHub {
		token, err := getGitHubActionsIDToken(ctx)
		if err != nil {
			return "", err
		}
		return token, nil
	}

	if github.IsGitHubActionsEnv() {
		token, err := getGitHubActionsIDToken(ctx)
		if err == nil {
			return token, nil
		}
	}

	if defaultSocket := spire.GetSocketPath(); defaultSocket != "" {
		autoConfig := config
		autoConfig.SpireAgentSocket = defaultSocket
		token, err := getSpireWorkloadToken(ctx, autoConfig)
		if err == nil {
			return token, nil
		}
	}

	return "", pkgerrors.NewWithContext("fulcio", "resolve-token",
		"no token source available").
		Suggest(
			"Provide explicit token source: --oidc-token, --oidc-token-file, --socket, --spire, or --github",
			"For SPIRE: ensure agent is running and SPIFFE_ENDPOINT_SOCKET is set",
			"For GitHub: ensure GITHUB_ACTIONS=true and GitHub OIDC is configured",
		)
}

// getGitHubActionsIDToken fetches a GitHub Actions OIDC token for Sigstore.
func getGitHubActionsIDToken(ctx context.Context) (string, error) {
	client, err := github.New(ctx, github.Options{})
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "fulcio", "github-token", "failed to create GitHub client")
	}

	token, err := client.FetchIDToken(ctx, github.DefaultAudience)
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "fulcio", "github-token", "failed to fetch GitHub Actions OIDC token")
	}

	return token, nil
}

func getSpireWorkloadToken(ctx context.Context, config signing.FulcioSignerConfig) (string, error) {
	audience, err := deriveAudienceFromURL(config.FulcioURL)
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "fulcio", "spire-token", "failed to derive audience from Fulcio URL")
	}

	client, err := spire.New(ctx, spire.Options{
		SocketPath: config.SpireAgentSocket,
	})
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "fulcio", "spire-token", "failed to create SPIRE client")
	}

	token, err := client.FetchJWTToken(ctx, audience)
	if err != nil {
		return "", pkgerrors.WrapWithContext(err, "fulcio", "spire-token", "failed to fetch JWT-SVID from SPIRE")
	}

	return token, nil
}

// getCertificateFromFulcio requests a certificate from Fulcio using the Fulcio client.
func getCertificateFromFulcio(
	ctx context.Context,
	fulcioURL, token string,
	publicKey crypto.PublicKey,
	allowInsecure bool,
	privateKey crypto.PrivateKey,
) (*x509.Certificate, error) {
	client, err := fulcio.New(ctx, fulcio.Options{
		FulcioURL: fulcioURL,
		Insecure:  allowInsecure,
	})
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "fulcio", "certificate", "failed to create Fulcio client")
	}

	cert, err := client.GetCertificate(ctx, fulcio.CertificateRequest{
		Token:      token,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	})
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "fulcio", "certificate", "failed to get certificate from Fulcio")
	}

	return cert, nil
}
