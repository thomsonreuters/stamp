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

	"github.com/thomsonreuters/stamp/pkg/clients/aws/eks"
	"github.com/thomsonreuters/stamp/pkg/clients/github"
	"github.com/thomsonreuters/stamp/pkg/clients/k8s"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

func (a *Attestor) discoverGitHubToken(ctx context.Context) (string, string, error) {
	a.logger.Debug("attempting GitHub Actions OIDC token discovery")

	if !github.IsOIDCEnvAvailable() {
		return "", "", pkgerrors.WrapWithContext(ErrTokenNotFound, attestorID, "discover",
			"GitHub Actions OIDC environment not detected")
	}

	client, err := github.New(ctx, github.Options{Logger: a.logger})
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "failed to create GitHub client")
	}

	audience := "https://github.com"
	if len(a.config.ExpectedAudience) > 0 {
		audience = a.config.ExpectedAudience[0]
	}

	token, err := client.FetchIDToken(ctx, audience)
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "GitHub OIDC token request failed")
	}

	if err := a.validateTokenFormat(token); err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "GitHub OIDC returned invalid JWT format")
	}

	a.logger.Debug("GitHub OIDC token acquired successfully", "audience", audience)
	return token, SourceGitHub, nil
}

func (a *Attestor) discoverAWSToken(ctx context.Context) (string, string, error) {
	a.logger.Debug("attempting AWS IRSA token discovery")

	if !eks.IsIRSAEnvAvailable() {
		return "", "", pkgerrors.WrapWithContext(ErrTokenNotFound, attestorID, "discover",
			"AWS IRSA environment not detected")
	}

	client, err := eks.New(ctx, eks.Options{Logger: a.logger})
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "failed to create EKS client")
	}

	token, err := client.FetchToken(ctx)
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "AWS IRSA token fetch failed")
	}

	if err := a.validateTokenFormat(token); err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "AWS IRSA token has invalid JWT format")
	}

	a.logger.Debug("AWS IRSA token acquired successfully", "path", client.GetTokenPath())
	return token, SourceAWS, nil
}

func (a *Attestor) discoverKubernetesToken(ctx context.Context) (string, string, error) {
	a.logger.Debug("attempting Kubernetes service account token discovery")

	if !k8s.IsServiceAccountEnvAvailable() {
		return "", "", pkgerrors.WrapWithContext(ErrTokenNotFound, attestorID, "discover",
			"Kubernetes service account environment not detected")
	}

	client, err := k8s.New(ctx, k8s.Options{Logger: a.logger})
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "failed to create K8s client")
	}

	token, err := client.FetchToken(ctx)
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "Kubernetes token fetch failed")
	}

	if err := a.validateTokenFormat(token); err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "discover", "Kubernetes token has invalid JWT format")
	}

	a.logger.Debug("Kubernetes service account token acquired successfully", "path", client.GetTokenPath())
	return token, SourceKubernetes, nil
}
