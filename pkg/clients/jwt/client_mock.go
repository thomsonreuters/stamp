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
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of ClientIface for testing using testify/mock.
type MockClient struct {
	mock.Mock
}

// ParseToken mocks the ParseToken method.
func (m *MockClient) ParseToken(token string) (*TokenInfo, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*TokenInfo)
	return result, args.Error(1)
}

// VerifySignature mocks the VerifySignature method.
func (m *MockClient) VerifySignature(ctx context.Context, token string) (*VerificationResult, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*VerificationResult)
	return result, args.Error(1)
}

// FetchJWKS mocks the FetchJWKS method.
func (m *MockClient) FetchJWKS(ctx context.Context, url string) (jwk.Set, error) {
	args := m.Called(ctx, url)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(jwk.Set)
	return result, args.Error(1)
}

// DiscoverJWKS mocks the DiscoverJWKS method.
func (m *MockClient) DiscoverJWKS(ctx context.Context, issuer string) (jwk.Set, error) {
	args := m.Called(ctx, issuer)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(jwk.Set)
	return result, args.Error(1)
}

// LoadPublicKey mocks the LoadPublicKey method.
func (m *MockClient) LoadPublicKey(filePath string) (crypto.PublicKey, error) {
	args := m.Called(filePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(crypto.PublicKey)
	return result, args.Error(1)
}

// FindKey mocks the FindKey method.
func (m *MockClient) FindKey(ctx context.Context, token string) (*KeyInfo, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*KeyInfo)
	return result, args.Error(1)
}

// HashToken mocks the HashToken method.
func (m *MockClient) HashToken(token string) string {
	args := m.Called(token)
	return args.String(0)
}

// ValidateAlgorithm mocks the ValidateAlgorithm method.
func (m *MockClient) ValidateAlgorithm(algorithm string) error {
	args := m.Called(algorithm)
	return args.Error(0)
}

// Ensure MockClient implements ClientIface.
var _ ClientIface = (*MockClient)(nil)

// NewMockClient creates a new mock client.
func NewMockClient() *MockClient {
	return &MockClient{}
}

// SetupMockClient sets up the mock and replaces the New function.
// It automatically restores the original New function when the test completes.
func SetupMockClient(t *testing.T) *MockClient {
	t.Helper()
	mockClient := NewMockClient()
	original := New
	New = func(ctx context.Context, opts ...Option) (ClientIface, error) {
		return mockClient, nil
	}
	t.Cleanup(func() {
		New = original
	})
	return mockClient
}
