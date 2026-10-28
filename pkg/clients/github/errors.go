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

package github

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrNotFound matches an APIError with HTTP status 404.
	ErrNotFound = errors.New("GitHub resource not found")

	// ErrMissingInstallationToken is returned when no GitHub App installation token is provided.
	ErrMissingInstallationToken = errors.New("GitHub App installation token is required")

	// ErrNotInstallationToken is returned when the token is not a GitHub App installation token (for example a personal access token).
	ErrNotInstallationToken = errors.New("token is not a GitHub App installation token (expected prefix " + InstallationTokenPrefix + ")")

	// ErrMissingEnvironmentConfig is returned when GitHub Actions environment is not properly configured.
	ErrMissingEnvironmentConfig = errors.New(
		"GitHub Actions environment not properly configured: missing ACTIONS_ID_TOKEN_REQUEST_TOKEN or ACTIONS_ID_TOKEN_REQUEST_URL",
	)

	// ErrEmptyToken is returned when an empty token is received from GitHub Actions OIDC provider.
	ErrEmptyToken = errors.New("empty token received from GitHub Actions OIDC provider")
)

// APIError is a non-2xx response from the GitHub REST API.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("GitHub API %s %s returned HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// Is reports whether the error matches ErrNotFound for a 404 status.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}
