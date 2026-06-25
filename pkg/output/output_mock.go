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

package output

import (
	"io"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// MockOutput is a mock implementation of OutputIface for testing using testify/mock.
type MockOutput struct {
	mock.Mock
}

// Info mocks the Info method.
func (m *MockOutput) Info(message string, args ...any) {
	m.Called(message, args)
}

// Success mocks the Success method.
func (m *MockOutput) Success(message string, args ...any) {
	m.Called(message, args)
}

// Warning mocks the Warning method.
func (m *MockOutput) Warning(message string, args ...any) {
	m.Called(message, args)
}

// Error mocks the Error method.
func (m *MockOutput) Error(message string, args ...any) {
	m.Called(message, args)
}

// Progress mocks the Progress method.
func (m *MockOutput) Progress(message string, args ...any) {
	m.Called(message, args)
}

// Debug mocks the Debug method.
func (m *MockOutput) Debug(message string, args ...any) {
	m.Called(message, args)
}

// Heading mocks the Heading method.
func (m *MockOutput) Heading(text string) {
	m.Called(text)
}

// List mocks the List method.
func (m *MockOutput) List(text string, args ...any) {
	m.Called(text, args)
}

// NewLine mocks the NewLine method.
func (m *MockOutput) NewLine() {
	m.Called()
}

// Bold mocks the Bold method.
func (m *MockOutput) Bold(text string) string {
	args := m.Called(text)
	return args.String(0)
}

// Data mocks the Data method.
func (m *MockOutput) Data(log logger.Logger, message string, data any) error {
	args := m.Called(log, message, data)
	return args.Error(0)
}

// DataBatch mocks the DataBatch method.
func (m *MockOutput) DataBatch(items []any) error {
	args := m.Called(items)
	return args.Error(0)
}

// SetQuiet mocks the SetQuiet method.
func (m *MockOutput) SetQuiet(quiet bool) {
	m.Called(quiet)
}

// IsQuiet mocks the IsQuiet method.
func (m *MockOutput) IsQuiet() bool {
	args := m.Called()
	return args.Bool(0)
}

// SetNoColor mocks the SetNoColor method.
func (m *MockOutput) SetNoColor(noColor bool) {
	m.Called(noColor)
}

// IsNoColor mocks the IsNoColor method.
func (m *MockOutput) IsNoColor() bool {
	args := m.Called()
	return args.Bool(0)
}

// SetDebug mocks the SetDebug method.
func (m *MockOutput) SetDebug(debug bool) {
	m.Called(debug)
}

// IsDebug mocks the IsDebug method.
func (m *MockOutput) IsDebug() bool {
	args := m.Called()
	return args.Bool(0)
}

// SetFormat mocks the SetFormat method.
func (m *MockOutput) SetFormat(format string) {
	m.Called(format)
}

// GetFormat mocks the GetFormat method.
func (m *MockOutput) GetFormat() string {
	args := m.Called()
	return args.String(0)
}

// SetDataEnabled mocks the SetDataEnabled method.
func (m *MockOutput) SetDataEnabled(enabled bool) {
	m.Called(enabled)
}

// IsDataOutputEnabled mocks the IsDataOutputEnabled method.
func (m *MockOutput) IsDataOutputEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

// GetDataFormat mocks the GetDataFormat method.
func (m *MockOutput) GetDataFormat() string {
	args := m.Called()
	return args.String(0)
}

// IsConfigured mocks the IsConfigured method.
func (m *MockOutput) IsConfigured() bool {
	args := m.Called()
	return args.Bool(0)
}

// Close mocks the Close method.
func (m *MockOutput) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Writer mocks the Writer method.
func (m *MockOutput) Writer() io.Writer {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	result, _ := args.Get(0).(io.Writer)
	return result
}

// Ensure MockOutput implements OutputIface.
var _ OutputIface = (*MockOutput)(nil)

// NewMockOutput creates a new MockOutput instance.
func NewMockOutput() *MockOutput {
	return &MockOutput{}
}

// SetupMockOutput creates a MockOutput and configures a silent global output for testing.
func SetupMockOutput(t *testing.T) *MockOutput {
	t.Helper()
	mockOutput := NewMockOutput()

	return mockOutput
}
