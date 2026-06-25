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
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

func (a *Attestor) acquireToken(ctx context.Context) (string, string, error) {
	a.logger.Debug("acquiring JWT token")

	sources := []struct {
		name      string
		condition func() bool
		acquire   func(context.Context) (string, string, error)
	}{
		{
			"file",
			func() bool { return a.config.TokenFile != "" },
			func(ctx context.Context) (string, string, error) { return a.acquireFromFile(a.config.TokenFile) },
		},
		{"stdin", func() bool { return a.config.FromStdin }, func(ctx context.Context) (string, string, error) { return a.acquireFromStdin() }},
		{
			"env",
			func() bool { return a.config.FromEnv != "" },
			func(ctx context.Context) (string, string, error) { return a.acquireFromEnv(a.config.FromEnv) },
		},
		{"github", func() bool { return a.config.AutoDiscoverGitHub }, a.discoverGitHubToken},
		{"aws", func() bool { return a.config.AutoDiscoverAWS }, a.discoverAWSToken},
		{"k8s", func() bool { return a.config.AutoDiscoverK8s }, a.discoverKubernetesToken},
	}

	for _, src := range sources {
		if src.condition() {
			a.logger.Debug("acquiring token", "source", src.name)
			return src.acquire(ctx)
		}
	}

	return "", "", ErrNoTokenSource
}

func (a *Attestor) acquireFromFile(filePath string) (string, string, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", "", pkgerrors.WrapWithContext(ErrTokenNotFound, attestorID, "acquire", filePath)
	}

	tokenBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "acquire", filePath)
	}

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return "", "", pkgerrors.WrapWithContext(ErrEmptyToken, attestorID, "acquire", filePath)
	}

	if err := a.validateTokenFormat(token); err != nil {
		return "", "", err
	}

	a.logger.Debug("token acquired from file", "path", filePath)
	return token, fmt.Sprintf("%s:%s", SourceFile, filePath), nil
}

func (a *Attestor) acquireFromStdin() (string, string, error) {
	tokenBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", "", pkgerrors.WrapWithContext(err, attestorID, "acquire", "stdin read failed")
	}

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return "", "", pkgerrors.WrapWithContext(ErrEmptyToken, attestorID, "acquire", "stdin empty")
	}

	if err := a.validateTokenFormat(token); err != nil {
		return "", "", err
	}

	a.logger.Debug("token acquired from stdin")
	return token, SourceStdin, nil
}

func (a *Attestor) acquireFromEnv(envVar string) (string, string, error) {
	token := strings.TrimSpace(os.Getenv(envVar))
	if token == "" {
		return "", "", pkgerrors.WrapWithContext(ErrTokenNotFound, attestorID, "acquire", envVar)
	}

	if err := a.validateTokenFormat(token); err != nil {
		return "", "", err
	}

	a.logger.Debug("token acquired from env", "var", envVar)
	return token, fmt.Sprintf("%s:%s", SourceEnv, envVar), nil
}

func (a *Attestor) validateTokenFormat(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidTokenFormat
	}
	if slices.Contains(parts, "") {
		return ErrInvalidTokenFormat
	}
	return nil
}
