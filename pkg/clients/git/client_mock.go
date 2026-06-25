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

package git

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of ClientIface for testing using testify/mock.
type MockClient struct {
	mock.Mock
}

// GetInfo mocks the GetInfo method.
func (m *MockClient) GetInfo(ctx context.Context, path string) (*GitInfo, error) {
	args := m.Called(ctx, path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*GitInfo)
	return result, args.Error(1)
}

// IsGitRepository mocks the IsGitRepository method.
func (m *MockClient) IsGitRepository(ctx context.Context, path string) bool {
	args := m.Called(ctx, path)
	return args.Bool(0)
}

// GetCommitHash mocks the GetCommitHash method.
func (m *MockClient) GetCommitHash(ctx context.Context, path string) (string, error) {
	args := m.Called(ctx, path)
	return args.String(0), args.Error(1)
}

// GetBranch mocks the GetBranch method.
func (m *MockClient) GetBranch(ctx context.Context, path string) (string, error) {
	args := m.Called(ctx, path)
	return args.String(0), args.Error(1)
}

// IsDirty mocks the IsDirty method.
func (m *MockClient) IsDirty(ctx context.Context, path string) (bool, error) {
	args := m.Called(ctx, path)
	return args.Bool(0), args.Error(1)
}

// GetHTMLURL mocks the GetHTMLURL method.
func (m *MockClient) GetHTMLURL(remoteURL string) string {
	args := m.Called(remoteURL)
	return args.String(0)
}

// Ensure MockClient implements ClientIface.
var _ ClientIface = (*MockClient)(nil)

// NewMockClient creates a new MockClient instance.
func NewMockClient() *MockClient {
	return &MockClient{}
}

// SetupMockClient creates a MockClient and replaces the New function for testing.
// It automatically restores the original New function when the test completes.
func SetupMockClient(t *testing.T) *MockClient {
	t.Helper()
	mockClient := NewMockClient()
	original := New
	New = func(_ context.Context, _ ...Option) (ClientIface, error) {
		return mockClient, nil
	}
	t.Cleanup(func() {
		New = original
	})
	return mockClient
}
