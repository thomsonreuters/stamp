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

package executor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
)

// MockCommandExecutor is a mock implementation of CommandExecutor for testing.
type MockCommandExecutor struct {
	mock.Mock
}

func (m *MockCommandExecutor) CommandContext(ctx context.Context, name string, args ...string) Command {
	callArgs := []any{ctx, name}
	for _, arg := range args {
		callArgs = append(callArgs, arg)
	}
	ret := m.Called(callArgs...)
	if ret.Get(0) == nil {
		return nil
	}
	if cmd, ok := ret.Get(0).(Command); ok {
		return cmd
	}
	return nil
}

// MockCommand is a mock implementation of Command for testing.
type MockCommand struct {
	mock.Mock
}

func NewMockCommand() *MockCommand {
	return &MockCommand{}
}

func (m *MockCommand) Output() ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if output, ok := args.Get(0).([]byte); ok {
		return output, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockCommand) CombinedOutput() ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if output, ok := args.Get(0).([]byte); ok {
		return output, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockCommand) Run() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCommand) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCommand) Wait() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCommand) StdoutPipe() (any, error) {
	args := m.Called()
	return args.Get(0), args.Error(1)
}

func (m *MockCommand) StderrPipe() (any, error) {
	args := m.Called()
	return args.Get(0), args.Error(1)
}

func (m *MockCommand) SetDir(dir string) {
	m.Called(dir)
}

func (m *MockCommand) SetEnv(env []string) {
	m.Called(env)
}

func (m *MockCommand) SetStdout(stdout any) {
	m.Called(stdout)
}

func (m *MockCommand) SetStderr(stderr any) {
	m.Called(stderr)
}

func (m *MockCommand) GetProcess() any {
	args := m.Called()
	return args.Get(0)
}

func (m *MockCommand) GetProcessState() any {
	args := m.Called()
	return args.Get(0)
}

func NewMockCommandExecutor() *MockCommandExecutor {
	return &MockCommandExecutor{}
}

func SetupMockCommandExecutor(t *testing.T) *MockCommandExecutor {
	t.Helper()

	mockExec := NewMockCommandExecutor()
	original := NewOSCommandExecutor

	NewOSCommandExecutor = func() CommandExecutor {
		return mockExec
	}

	t.Cleanup(func() {
		NewOSCommandExecutor = original
	})

	return mockExec
}
