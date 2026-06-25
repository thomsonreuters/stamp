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
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of ClientIface.
type MockClient struct {
	mock.Mock
}

// FetchIDToken mocks fetching an OIDC ID token.
func (m *MockClient) FetchIDToken(ctx context.Context, audience string) (string, error) {
	args := m.Called(ctx, audience)
	return args.String(0), args.Error(1)
}

// IsGitHubActions mocks the GitHub Actions environment check.
func (m *MockClient) IsGitHubActions() bool {
	args := m.Called()
	return args.Bool(0)
}

// IsOIDCAvailable mocks the OIDC availability check.
func (m *MockClient) IsOIDCAvailable() bool {
	args := m.Called()
	return args.Bool(0)
}

// SetupMockClient replaces the global New function with a mock for testing.
func SetupMockClient(t *testing.T) *MockClient {
	t.Helper()

	mockClient := &MockClient{}

	original := New
	New = func(ctx context.Context, opts Options) (ClientIface, error) {
		return mockClient, nil
	}

	t.Cleanup(func() {
		New = original
	})

	return mockClient
}
