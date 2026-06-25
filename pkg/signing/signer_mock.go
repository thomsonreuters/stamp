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

package signing

import (
	"context"
	"crypto"
	"errors"
)

// MockSigner is a mock implementation of Signer for testing.
type MockSigner struct {
	IDValue        string
	ValidateErr    error
	ValidateCalls  int
	PreSignErr     error
	SignOutput     []byte
	SignErr        error
	PostSignErr    error
	KeyIDValue     string
	KeyIDErr       error
	PublicKeyValue crypto.PublicKey
	PublicKeyErr   error
}

func (m *MockSigner) ID() string { return m.IDValue }

func (m *MockSigner) Validate(config SignerConfig) error {
	m.ValidateCalls++
	return m.ValidateErr
}

func (m *MockSigner) PreSign(ctx context.Context, config SignerConfig) error {
	return m.PreSignErr
}

func (m *MockSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if m.SignErr != nil {
		return nil, m.SignErr
	}
	if m.SignOutput != nil {
		return m.SignOutput, nil
	}
	return []byte("signature"), nil
}

func (m *MockSigner) PostSign(ctx context.Context) error {
	return m.PostSignErr
}

func (m *MockSigner) KeyID() (string, error) {
	if m.KeyIDErr != nil {
		return "", m.KeyIDErr
	}
	if m.KeyIDValue != "" {
		return m.KeyIDValue, nil
	}
	return "mock-key-id", nil
}

func (m *MockSigner) PublicKey() (crypto.PublicKey, error) {
	return m.PublicKeyValue, m.PublicKeyErr
}

// NewMockSigner creates a new MockSigner with the given ID.
func NewMockSigner(id string) *MockSigner {
	return &MockSigner{IDValue: id}
}

// MockSignerFactory creates a FactoryFunc that returns the given MockSigner.
func MockSignerFactory(signer *MockSigner) FactoryFunc {
	return func(ctx context.Context, config SignerConfig) (Signer, error) {
		return signer, nil
	}
}

// NewMockSignerFactory creates a FactoryFunc that returns a new MockSigner with the given ID.
func NewMockSignerFactory(id string) FactoryFunc {
	return func(ctx context.Context, config SignerConfig) (Signer, error) {
		return NewMockSigner(id), nil
	}
}

// FailingMockSignerFactory creates a FactoryFunc that always returns an error.
func FailingMockSignerFactory(err error) FactoryFunc {
	return func(ctx context.Context, config SignerConfig) (Signer, error) {
		return nil, err
	}
}

// ErrMockFactory is a standard error for failing mock factories.
var ErrMockFactory = errors.New("mock factory error")
