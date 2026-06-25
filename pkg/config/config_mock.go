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

package config

import (
	"time"

	"github.com/stretchr/testify/mock"
)

// MockConfiguration is a mock implementation of ConfigurationIface for testing.
type MockConfiguration struct {
	mock.Mock
}

// Ensure MockConfiguration implements ConfigurationIface.
var _ ConfigurationIface = (*MockConfiguration)(nil)

// GetString returns the value associated with the key as a string.
func (m *MockConfiguration) GetString(key string) string {
	args := m.Called(key)
	return args.String(0)
}

// GetInt returns the value associated with the key as an integer.
func (m *MockConfiguration) GetInt(key string) int {
	args := m.Called(key)
	return args.Int(0)
}

// GetBool returns the value associated with the key as a boolean.
func (m *MockConfiguration) GetBool(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

// GetDuration returns the value associated with the key as a duration.
func (m *MockConfiguration) GetDuration(key string) time.Duration {
	args := m.Called(key)
	if args.Get(0) == nil {
		return 0
	}
	if d, ok := args.Get(0).(time.Duration); ok {
		return d
	}
	return 0
}

// GetStringSlice returns the value associated with the key as a slice of strings.
func (m *MockConfiguration) GetStringSlice(key string) []string {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil
	}
	if s, ok := args.Get(0).([]string); ok {
		return s
	}
	return nil
}

// GetStringMapString returns the value associated with the key as a map of strings.
func (m *MockConfiguration) GetStringMapString(key string) map[string]string {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil
	}
	if m, ok := args.Get(0).(map[string]string); ok {
		return m
	}
	return nil
}

// IsSet checks if a key is present in the configuration.
func (m *MockConfiguration) IsSet(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

// Set sets the value for the given key.
func (m *MockConfiguration) Set(key string, value any) {
	m.Called(key, value)
}

// UnmarshalKey unmarshals a specific key into a custom struct.
func (m *MockConfiguration) UnmarshalKey(key string, rawVal any) error {
	args := m.Called(key, rawVal)
	return args.Error(0)
}

// AllSettings returns all settings as a map.
func (m *MockConfiguration) AllSettings() map[string]any {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	if settings, ok := args.Get(0).(map[string]any); ok {
		return settings
	}
	return nil
}

// NewMockConfiguration creates a new MockConfiguration instance.
func NewMockConfiguration() *MockConfiguration {
	return &MockConfiguration{}
}
