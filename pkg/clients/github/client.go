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

// Package github provides a client for interacting with GitHub Actions OIDC tokens.
package github

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	httpclient "github.com/thomsonreuters/stamp/pkg/http/client"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Environment variable names for GitHub Actions OIDC.
const (
	EnvActionsIDTokenRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	EnvActionsIDTokenRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvGitHubActions              = "GITHUB_ACTIONS"
	EnvGitHubServerURL            = "GITHUB_SERVER_URL"

	// DefaultAudience is the default audience for OIDC tokens (used by Sigstore).
	DefaultAudience = "sigstore"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultServerURL is the public GitHub server URL.
	DefaultServerURL = "https://github.com"

	// DefaultOIDCIssuer is the default OIDC issuer for GitHub Actions tokens on github.com.
	DefaultOIDCIssuer = "https://token.actions.githubusercontent.com"
)

// ClientIface defines the interface for GitHub Actions OIDC client.
type ClientIface interface {
	// FetchIDToken fetches an OIDC ID token for the specified audience.
	FetchIDToken(ctx context.Context, audience string) (string, error)

	// IsGitHubActions returns true if running in GitHub Actions environment.
	IsGitHubActions() bool

	// IsOIDCAvailable returns true if OIDC token request is available.
	IsOIDCAvailable() bool
}

// Client is the GitHub Actions OIDC client.
type Client struct {
	httpClient *httpclient.Client
	opts       Options
}

// Options configures the GitHub Actions client.
type Options struct {
	RequestToken    string
	TokenRequestURL string
	Timeout         time.Duration
	Logger          logger.Logger
}

// tokenResponse represents the GitHub Actions OIDC token response.
type tokenResponse struct {
	Value string `json:"value"`
}

// FetchIDToken fetches an OIDC ID token for the specified audience.
func (c *Client) FetchIDToken(ctx context.Context, audience string) (string, error) {
	if c.opts.RequestToken == "" || c.opts.TokenRequestURL == "" {
		return "", ErrMissingEnvironmentConfig
	}

	if audience == "" {
		audience = DefaultAudience
	}

	var tokenResp tokenResponse
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetAuthToken(c.opts.RequestToken).
		SetHeader("Accept", "application/json").
		SetQueryParam("audience", audience).
		SetResult(&tokenResp).
		Get(c.opts.TokenRequestURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Close() }()

	if !resp.IsSuccess() {
		body, _ := resp.String()
		return "", fmt.Errorf("OIDC token request failed with status %s: %s", resp.Status(), body)
	}

	if tokenResp.Value == "" {
		return "", ErrEmptyToken
	}

	return tokenResp.Value, nil
}

// IsGitHubActions returns true if running in GitHub Actions environment.
func (c *Client) IsGitHubActions() bool {
	return IsGitHubActionsEnv()
}

// IsOIDCAvailable returns true if OIDC token request environment is available.
func (c *Client) IsOIDCAvailable() bool {
	return c.opts.RequestToken != "" && c.opts.TokenRequestURL != ""
}

// IsGitHubActionsEnv is a convenience function to check if running in GitHub Actions.
func IsGitHubActionsEnv() bool {
	return os.Getenv(EnvGitHubActions) == "true"
}

// IsOIDCEnvAvailable checks if OIDC environment variables are set.
func IsOIDCEnvAvailable() bool {
	return os.Getenv(EnvActionsIDTokenRequestToken) != "" && os.Getenv(EnvActionsIDTokenRequestURL) != ""
}

func newClient(ctx context.Context, opts Options) (ClientIface, error) {
	if opts.RequestToken == "" {
		opts.RequestToken = os.Getenv(EnvActionsIDTokenRequestToken)
	}
	if opts.TokenRequestURL == "" {
		opts.TokenRequestURL = os.Getenv(EnvActionsIDTokenRequestURL)
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Logger == nil {
		opts.Logger = logger.NewNoop()
	}

	httpClient := httpclient.New(opts.Logger).SetTimeout(opts.Timeout)

	return &Client{
		httpClient: httpClient,
		opts:       opts,
	}, nil
}

// DeriveOIDCIssuers returns the list of trusted OIDC issuers for GitHub Actions.
func DeriveOIDCIssuers() []string {
	serverURL := os.Getenv(EnvGitHubServerURL)
	issuers := []string{DefaultOIDCIssuer}

	if serverURL != "" && serverURL != DefaultServerURL {
		if derived := DeriveIssuerFromServerURL(serverURL); derived != "" {
			issuers = append(issuers, derived)
		}
	}

	return issuers
}

// DeriveIssuerFromServerURL derives the OIDC issuer from a non-default GitHub server URL.
// For GHES (self-hosted): https://HOSTNAME/_services/token
func DeriveIssuerFromServerURL(serverURL string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host + "/_services/token"
}

// New is the constructor function for creating a GitHub Actions client.
// This variable can be replaced in tests for mocking.
var New = newClient
