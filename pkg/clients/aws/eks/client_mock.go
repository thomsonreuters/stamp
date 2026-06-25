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

package eks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) FetchToken(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockClient) IsIRSAAvailable() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockClient) GetTokenPath() string {
	args := m.Called()
	return args.String(0)
}

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
