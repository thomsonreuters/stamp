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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()

	assert.NotNil(t, registry)
	assert.NotNil(t, registry.signers)
	assert.Empty(t, registry.signers)
}

func TestRegistry_Register_Success(t *testing.T) {
	registry := NewRegistry()

	err := registry.Register("test-signer", NewMockSignerFactory("test-signer"))

	require.NoError(t, err)
	assert.True(t, registry.Has("test-signer"))
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	registry := NewRegistry()

	err := registry.Register("test-signer", NewMockSignerFactory("test-signer"))
	require.NoError(t, err)

	err = registry.Register("test-signer", NewMockSignerFactory("test-signer"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegistry_Register_EmptyID(t *testing.T) {
	registry := NewRegistry()

	err := registry.Register("", NewMockSignerFactory("test-signer"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer ID cannot be empty")
}

func TestRegistry_Get_Success(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register("test-signer", NewMockSignerFactory("test-signer"))
	require.NoError(t, err)

	signer, err := registry.Get(t.Context(), "test-signer", SignerConfig{})

	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "test-signer", signer.ID())
}

func TestRegistry_Get_NotFound(t *testing.T) {
	registry := NewRegistry()

	signer, err := registry.Get(t.Context(), "nonexistent", SignerConfig{})

	require.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_List_Empty(t *testing.T) {
	registry := NewRegistry()

	list := registry.List()

	assert.Empty(t, list)
}

func TestRegistry_List_WithSigners(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register("signer-a", NewMockSignerFactory("signer-a"))
	require.NoError(t, err)
	err = registry.Register("signer-b", NewMockSignerFactory("signer-b"))
	require.NoError(t, err)

	list := registry.List()

	assert.Len(t, list, 2)
	assert.Contains(t, list, "signer-a")
	assert.Contains(t, list, "signer-b")
}

func TestRegistry_Has_Exists(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register("test-signer", NewMockSignerFactory("test-signer"))
	require.NoError(t, err)

	assert.True(t, registry.Has("test-signer"))
}

func TestRegistry_Has_NotExists(t *testing.T) {
	registry := NewRegistry()

	assert.False(t, registry.Has("nonexistent"))
}

// Tests for global registry functions
// Note: These tests use the global registry which may have signers registered
// from init() functions in other packages (like fulcio).

func TestGlobal_Has(t *testing.T) {
	// The global registry should have at least the fulcio signer from init()
	// We just verify Has doesn't panic and returns a boolean
	result := Has("nonexistent-signer-xyz")
	assert.False(t, result)
}

func TestGlobal_List(t *testing.T) {
	// List should return a slice of registered signer IDs
	list := List()
	assert.NotNil(t, list)
}

func TestGlobal_Get_NotFound(t *testing.T) {
	signer, err := Get(t.Context(), "nonexistent-signer-xyz", SignerConfig{})

	require.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "not found")
}

func TestEntry_Fields(t *testing.T) {
	factory := NewMockSignerFactory("test")
	entry := Entry{
		ID:      "test-id",
		Factory: factory,
	}

	assert.Equal(t, "test-id", entry.ID)
	assert.NotNil(t, entry.Factory)
}
