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

package v1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockClient is a mock implementation of ClientIface for testing.
type MockClient struct {
	mock.Mock
}

// GetLogInfo mocks the GetLogInfo method.
func (m *MockClient) GetLogInfo(ctx context.Context) (*LogInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*LogInfo)
	return result, args.Error(1)
}

// GetEntry mocks the GetEntry method.
func (m *MockClient) GetEntry(ctx context.Context, uuid string) (*LogEntry, error) {
	args := m.Called(ctx, uuid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*LogEntry)
	return result, args.Error(1)
}

// GetEntryByLogIndex mocks the GetEntryByLogIndex method.
func (m *MockClient) GetEntryByLogIndex(ctx context.Context, logIndex int64) (*LogEntry, error) {
	args := m.Called(ctx, logIndex)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*LogEntry)
	return result, args.Error(1)
}

// SearchByHash mocks the SearchByHash method.
func (m *MockClient) SearchByHash(ctx context.Context, hash string) ([]string, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).([]string)
	return result, args.Error(1)
}

// CreateEntry mocks the CreateEntry method.
func (m *MockClient) CreateEntry(ctx context.Context, entry *ProposedEntry, retry *RetryPolicy) (*LogEntry, error) {
	args := m.Called(ctx, entry, retry)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*LogEntry)
	return result, args.Error(1)
}

// GetInclusionProof mocks the GetInclusionProof method.
func (m *MockClient) GetInclusionProof(ctx context.Context, uuid string) (*InclusionProof, error) {
	args := m.Called(ctx, uuid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*InclusionProof)
	return result, args.Error(1)
}

// Ensure MockClient implements ClientIface.
var _ ClientIface = (*MockClient)(nil)

func SetupMockClient(t *testing.T) *MockClient {
	t.Helper()
	mockClient := &MockClient{}
	original := New
	New = func(opts Options) (ClientIface, error) {
		return mockClient, nil
	}
	t.Cleanup(func() {
		New = original
	})
	return mockClient
}
