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

package buildenv

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockBuildEnvironment is a mock implementation of BuildEnvironment for testing.
type MockBuildEnvironment struct {
	mock.Mock
}

func (m *MockBuildEnvironment) Type() EnvironmentType {
	args := m.Called()
	return args.Get(0).(EnvironmentType)
}

func (m *MockBuildEnvironment) BuilderID(ctx context.Context) string {
	args := m.Called(ctx)
	return args.String(0)
}

func (m *MockBuildEnvironment) SourceURI() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockBuildEnvironment) SourceDigest() map[string]string {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(map[string]string)
}

func (m *MockBuildEnvironment) InternalParameters() map[string]any {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(map[string]any)
}

func (m *MockBuildEnvironment) ResolvedDependencies() []ResourceDescriptor {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]ResourceDescriptor)
}

func (m *MockBuildEnvironment) InvocationID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockBuildEnvironment) WorkflowInputs() any {
	args := m.Called()
	return args.Get(0)
}
