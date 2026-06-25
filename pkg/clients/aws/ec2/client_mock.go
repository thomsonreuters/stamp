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

package ec2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// MockClient is a mock implementation of ClientInterface for testing.
type MockClient struct {
	mock.Mock
}

// GetIMDSMetadata mocks the GetIMDSMetadata method.
func (m *MockClient) GetIMDSMetadata(ctx context.Context, path string, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, path, opts)
	return args.String(0), args.Error(1)
}

// CheckIMDSAccessibility mocks the CheckIMDSAccessibility method.
func (m *MockClient) CheckIMDSAccessibility(ctx context.Context, opts *IMDSOptions) error {
	args := m.Called(ctx, opts)
	return args.Error(0)
}

// GetInstanceIdentityDocument mocks the GetInstanceIdentityDocument method.
func (m *MockClient) GetInstanceIdentityDocument(ctx context.Context, opts *IMDSOptions) (*InstanceIdentityDocument, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*InstanceIdentityDocument)
	return result, args.Error(1)
}

// GetMACAddress mocks the GetMACAddress method.
func (m *MockClient) GetMACAddress(ctx context.Context, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, opts)
	return args.String(0), args.Error(1)
}

// GetNetworkInfo mocks the GetNetworkInfo method.
func (m *MockClient) GetNetworkInfo(ctx context.Context, opts *IMDSOptions) (*NetworkInfo, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*NetworkInfo)
	return result, args.Error(1)
}

// GetIAMInfo mocks the GetIAMInfo method.
func (m *MockClient) GetIAMInfo(ctx context.Context, opts *IMDSOptions) (*IAMInfo, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(*IAMInfo)
	return result, args.Error(1)
}

// GetInstanceLifecycle mocks the GetInstanceLifecycle method.
func (m *MockClient) GetInstanceLifecycle(ctx context.Context, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, opts)
	return args.String(0), args.Error(1)
}

// GetTagKeys mocks the GetTagKeys method.
func (m *MockClient) GetTagKeys(ctx context.Context, opts *IMDSOptions) ([]string, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).([]string)
	return result, args.Error(1)
}

// GetTag mocks the GetTag method.
func (m *MockClient) GetTag(ctx context.Context, key string, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, key, opts)
	return args.String(0), args.Error(1)
}

// GetAllTags mocks the GetAllTags method.
func (m *MockClient) GetAllTags(ctx context.Context, opts *IMDSOptions) (map[string]string, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, _ := args.Get(0).(map[string]string)
	return result, args.Error(1)
}

// GetInstanceID mocks the GetInstanceID method.
func (m *MockClient) GetInstanceID(ctx context.Context, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, opts)
	return args.String(0), args.Error(1)
}

// GetInstanceType mocks the GetInstanceType method.
func (m *MockClient) GetInstanceType(ctx context.Context, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, opts)
	return args.String(0), args.Error(1)
}

// GetRegion mocks the GetRegion method.
func (m *MockClient) GetRegion(ctx context.Context, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, opts)
	return args.String(0), args.Error(1)
}

// GetAvailabilityZone mocks the GetAvailabilityZone method.
func (m *MockClient) GetAvailabilityZone(ctx context.Context, opts *IMDSOptions) (string, error) {
	args := m.Called(ctx, opts)
	return args.String(0), args.Error(1)
}

// Ensure MockClient implements ClientInterface.
var _ ClientInterface = (*MockClient)(nil)

func SetupMockClient(t *testing.T) *MockClient {
	mockClient := &MockClient{}
	original := New
	New = func(log logger.Logger) ClientInterface {
		return mockClient
	}
	t.Cleanup(func() {
		New = original
		mockClient.AssertExpectations(t)
	})
	return mockClient
}
