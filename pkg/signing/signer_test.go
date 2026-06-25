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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSigner_InvalidConfig(t *testing.T) {
	signer, err := NewSigner(t.Context(), SignerConfig{})

	require.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "invalid config")
}

func TestNewSigner_ProviderNotFound(t *testing.T) {
	signer, err := NewSigner(t.Context(), SignerConfig{
		Provider: "nonexistent-provider-xyz",
	})

	require.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "not found")
}

func TestNewSigner_ValidationFails(t *testing.T) {
	// Create a test registry with a signer that fails validation
	registry := NewRegistry()
	mockSigner := &MockSigner{
		IDValue:     "test-validation-fail",
		ValidateErr: errors.New("validation failed"),
	}
	err := registry.Register("test-validation-fail", MockSignerFactory(mockSigner))
	require.NoError(t, err)

	// Replace global registry temporarily
	originalRegistry := globalRegistry
	globalRegistry = registry
	defer func() { globalRegistry = originalRegistry }()

	signer, err := NewSigner(t.Context(), SignerConfig{
		Provider: "test-validation-fail",
	})

	require.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "invalid config for signer")
}

func TestNewSigner_Success(t *testing.T) {
	// Create a test registry with a valid signer
	registry := NewRegistry()
	mockSigner := &MockSigner{
		IDValue:     "test-success",
		ValidateErr: nil,
	}
	err := registry.Register("test-success", MockSignerFactory(mockSigner))
	require.NoError(t, err)

	// Replace global registry temporarily
	originalRegistry := globalRegistry
	globalRegistry = registry
	defer func() { globalRegistry = originalRegistry }()

	signer, err := NewSigner(t.Context(), SignerConfig{
		Provider: "test-success",
	})

	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "test-success", signer.ID())
	assert.Equal(t, 1, mockSigner.ValidateCalls)
}

func TestSigner_Interface(t *testing.T) {
	// Verify that the interface methods exist by using a mock implementation
	var signer Signer = NewMockSigner("test")

	assert.Equal(t, "test", signer.ID())

	err := signer.Validate(SignerConfig{})
	require.NoError(t, err)

	err = signer.PreSign(t.Context(), SignerConfig{})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), []byte("payload"))
	require.NoError(t, err)
	assert.Equal(t, []byte("signature"), sig)

	err = signer.PostSign(t.Context())
	require.NoError(t, err)

	keyID, err := signer.KeyID()
	require.NoError(t, err)
	assert.Equal(t, "mock-key-id", keyID)

	pubKey, err := signer.PublicKey()
	require.NoError(t, err)
	assert.Nil(t, pubKey)
}

func TestCertificateSigner_Interface(t *testing.T) {
	// Verify MockSigner can be used as a Signer
	mockSigner := NewMockSigner("cert-test")

	var signer Signer = mockSigner
	assert.Equal(t, "cert-test", signer.ID())
}

func TestFactoryFunc_Type(t *testing.T) {
	// Verify FactoryFunc signature
	factory := NewMockSignerFactory("factory-test")

	signer, err := factory(t.Context(), SignerConfig{})

	require.NoError(t, err)
	assert.Equal(t, "factory-test", signer.ID())
}
