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

package core

import (
	"context"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/mock"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// MockAttestor is a mock implementation of the Attestor interface for testing.
type MockAttestor struct {
	mock.Mock
}

func (m *MockAttestor) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAttestor) PredicateURI() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAttestor) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAttestor) Description() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAttestor) ConfigSchema() []ConfigField {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	if fields, ok := args.Get(0).([]ConfigField); ok {
		return fields
	}
	return nil
}

func (m *MockAttestor) ValidateConfig(config Config) error {
	args := m.Called(config)
	return args.Error(0)
}

func (m *MockAttestor) PreAttest(ctx context.Context, config Config) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockAttestor) Attest(ctx context.Context, config Config) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockAttestor) PostAttest(ctx context.Context, config Config) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockAttestor) SetLogger(log logger.Logger) {
	m.Called(log)
}

func (m *MockAttestor) GeneratePredicate(config Config) (any, error) {
	args := m.Called(config)
	return args.Get(0), args.Error(1)
}

func (m *MockAttestor) Subjects(config Config) []intoto.Subject {
	args := m.Called(config)
	if args.Get(0) == nil {
		return nil
	}
	if subjects, ok := args.Get(0).([]intoto.Subject); ok {
		return subjects
	}
	return nil
}

func (m *MockAttestor) Schema() *jsonschema.Schema {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	if schema, ok := args.Get(0).(*jsonschema.Schema); ok {
		return schema
	}
	return nil
}

// NewMockAttestor creates a new mock attestor with sensible default expectations.
// You can override any default behavior after creation:
//
//	mock := NewMockAttestor("test", "uri", "name", "desc")
//	mock.On("Attest", mock.Anything, mock.Anything).Return(errors.New("failed"))
func NewMockAttestor(id, predicateURI, name, description string) *MockAttestor {
	m := &MockAttestor{}

	m.On("ID").Return(id)
	m.On("PredicateURI").Return(predicateURI)
	m.On("Name").Return(name)
	m.On("Description").Return(description)
	m.On("ConfigSchema").Return([]ConfigField{})
	m.On("Schema").Return((*jsonschema.Schema)(nil))

	m.On("ValidateConfig", mock.Anything).Return(nil)
	m.On("PreAttest", mock.Anything, mock.Anything).Return(nil)
	m.On("Attest", mock.Anything, mock.Anything).Return(nil)
	m.On("PostAttest", mock.Anything, mock.Anything).Return(nil)
	m.On("SetLogger", mock.Anything).Return()

	m.On("GeneratePredicate", mock.Anything).Return(nil, nil)
	m.On("Subjects", mock.Anything).Return([]intoto.Subject{})

	return m
}
