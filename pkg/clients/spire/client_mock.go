// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spire

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockSpireClient is a mock implementation of ClientIface.
type MockSpireClient struct {
	mock.Mock
}

func (m *MockSpireClient) FetchJWTToken(ctx context.Context, audience string) (string, error) {
	args := m.Called(ctx, audience)
	return args.String(0), args.Error(1)
}

func (m *MockSpireClient) Close() error {
	return m.Called().Error(0)
}

// SetupMockSpireClient replaces the global New function with a mock for testing.
func SetupMockSpireClient(t *testing.T) *MockSpireClient {
	t.Helper()

	mockClient := &MockSpireClient{}

	original := New
	New = func(ctx context.Context, options Options) (ClientIface, error) {
		return mockClient, nil
	}

	t.Cleanup(func() {
		New = original
	})

	return mockClient
}
