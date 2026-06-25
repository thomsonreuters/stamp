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

package logger

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, args ...any) {
	m.Called(msg, args)
}

func (m *MockLogger) Info(msg string, args ...any) {
	m.Called(msg, args)
}

func (m *MockLogger) Warn(msg string, args ...any) {
	m.Called(msg, args)
}

func (m *MockLogger) Error(msg string, args ...any) {
	m.Called(msg, args)
}

func (m *MockLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	m.Called(ctx, msg, args)
}

func (m *MockLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	m.Called(ctx, msg, args)
}

func (m *MockLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	m.Called(ctx, msg, args)
}

func (m *MockLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	m.Called(ctx, msg, args)
}

func (m *MockLogger) With(args ...any) Logger {
	callArgs := m.Called(args)
	if callArgs.Get(0) == nil {
		return nil
	}
	if logger, ok := callArgs.Get(0).(Logger); ok {
		return logger
	}
	return nil
}

func (m *MockLogger) WithGroup(name string) Logger {
	callArgs := m.Called(name)
	if callArgs.Get(0) == nil {
		return nil
	}
	if logger, ok := callArgs.Get(0).(Logger); ok {
		return logger
	}
	return nil
}

// NewMockLogger creates a new mock logger with default no-op expectations.
func NewMockLogger() *MockLogger {
	m := &MockLogger{}

	m.On("Debug", mock.Anything, mock.Anything).Return()
	m.On("Info", mock.Anything, mock.Anything).Return()
	m.On("Warn", mock.Anything, mock.Anything).Return()
	m.On("Error", mock.Anything, mock.Anything).Return()

	m.On("DebugContext", mock.Anything, mock.Anything, mock.Anything).Return()
	m.On("InfoContext", mock.Anything, mock.Anything, mock.Anything).Return()
	m.On("WarnContext", mock.Anything, mock.Anything, mock.Anything).Return()
	m.On("ErrorContext", mock.Anything, mock.Anything, mock.Anything).Return()

	m.On("With", mock.Anything).Return(m)
	m.On("WithGroup", mock.Anything).Return(m)

	return m
}
