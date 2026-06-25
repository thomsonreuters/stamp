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

import "errors"

var (
	// ErrMissingEnvironmentConfig is returned when GitHub Actions environment is not properly configured.
	ErrMissingEnvironmentConfig = errors.New(
		"GitHub Actions environment not properly configured: missing ACTIONS_ID_TOKEN_REQUEST_TOKEN or ACTIONS_ID_TOKEN_REQUEST_URL",
	)

	// ErrEmptyToken is returned when an empty token is received from GitHub Actions OIDC provider.
	ErrEmptyToken = errors.New("empty token received from GitHub Actions OIDC provider")
)
