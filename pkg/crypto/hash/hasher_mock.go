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

package hash

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockHasher is a mock implementation of the Hasher interface.
type MockHasher struct {
	mock.Mock
}

// Compile-time check that MockHasher implements Hasher interface.
var _ Hasher = (*MockHasher)(nil)

func (m *MockHasher) Hash(ctx context.Context, reader io.Reader, name string) (Result, error) {
	args := m.Called(ctx, reader, name)
	result, _ := args.Get(0).(Result)
	return result, args.Error(1)
}

func (m *MockHasher) HashBytes(ctx context.Context, data []byte, name string) (Result, error) {
	args := m.Called(ctx, data, name)
	result, _ := args.Get(0).(Result)
	return result, args.Error(1)
}

func (m *MockHasher) HashFile(ctx context.Context, filePath string) (Result, error) {
	args := m.Called(ctx, filePath)
	result, _ := args.Get(0).(Result)
	return result, args.Error(1)
}

func (m *MockHasher) HashFiles(ctx context.Context, files []string) ([]Result, error) {
	args := m.Called(ctx, files)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	results, _ := args.Get(0).([]Result)
	return results, args.Error(1)
}

// NewMockHasher creates a new MockHasher instance.
func NewMockHasher() *MockHasher {
	return &MockHasher{}
}

func SetMockHasher(t *testing.T) {
	mockHasher := NewMockHasher()
	originalHasher := newHasher
	New = func(config Config) Hasher {
		return mockHasher
	}
	t.Cleanup(func() {
		New = originalHasher
		mockHasher.AssertExpectations(t)
	})
}
