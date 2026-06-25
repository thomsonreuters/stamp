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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestRegisterAttestor(t *testing.T) {
	tests := []struct {
		name          string
		factory       FactoryFunc
		expectError   bool
		errorContains string
		expectedID    string
		expectedURI   string
	}{
		{
			name: "successful registration",
			factory: func(log logger.Logger) Attestor {
				return NewMockAttestor(
					"test-attestor",
					"https://example.com/predicate",
					"Test Attestor",
					"Test attestor for unit tests",
				)
			},
			expectError: false,
			expectedID:  "test-attestor",
			expectedURI: "https://example.com/predicate",
		},
		{
			name: "duplicate ID registration",
			factory: func(log logger.Logger) Attestor {
				return NewMockAttestor("duplicate", "https://example.com/predicate1", "Duplicate", "Duplicate attestor")
			},
			expectError:   true,
			errorContains: "already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &Registry{
				attestorsByID:           make(map[string]Entry),
				attestorsByPredicateURI: make(map[string][]Entry),
			}

			// Register duplicate first if needed
			if tt.name == "duplicate ID registration" {
				_ = registry.RegisterAttestor(tt.factory)
			}

			err := registry.RegisterAttestor(tt.factory)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)

				attestor, getErr := registry.GetAttestorByID(tt.expectedID, logger.NewNoop())
				require.NoError(t, getErr)
				assert.Equal(t, tt.expectedID, attestor.ID())
				assert.Equal(t, tt.expectedURI, attestor.PredicateURI())
			}
		})
	}
}

func TestGetAttestorByID(t *testing.T) {
	registry := &Registry{
		attestorsByID:           make(map[string]Entry),
		attestorsByPredicateURI: make(map[string][]Entry),
	}

	// Register some test attestors
	_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
		return NewMockAttestor(
			"attestor1",
			"https://example.com/predicate1",
			"Attestor 1",
			"Test attestor 1",
		)
	})

	_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
		return NewMockAttestor(
			"attestor2",
			"https://example.com/predicate2",
			"Attestor 2",
			"Test attestor 2",
		)
	})

	tests := []struct {
		name        string
		id          string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "existing attestor",
			id:          "attestor1",
			expectError: false,
		},
		{
			name:        "another existing attestor",
			id:          "attestor2",
			expectError: false,
		},
		{
			name:        "non-existent attestor",
			id:          "nonexistent",
			expectError: true,
			errorMsg:    `attestor with ID "nonexistent" not found`,
		},
		{
			name:        "empty ID",
			id:          "",
			expectError: true,
			errorMsg:    `attestor with ID "" not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor, err := registry.GetAttestorByID(tt.id, logger.NewNoop())

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, attestor)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attestor)
				assert.Equal(t, tt.id, attestor.ID())
			}
		})
	}
}

func TestListAttestors(t *testing.T) {
	registry := &Registry{
		attestorsByID:           make(map[string]Entry),
		attestorsByPredicateURI: make(map[string][]Entry),
	}

	// Register multiple attestors
	attestors := []struct {
		id           string
		predicateURI string
		name         string
		description  string
	}{
		{"git", "https://example.com/git", "Git Attestor", "Git attestor description"},
		{"sbom", "https://example.com/sbom", "SBOM Attestor", "SBOM attestor description"},
		{"vuln", "https://example.com/vuln", "Vulnerability Attestor", "Vulnerability scanner"},
	}

	for _, a := range attestors {
		id, uri, name, desc := a.id, a.predicateURI, a.name, a.description
		_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
			return NewMockAttestor(id, uri, name, desc)
		})
	}

	entries := registry.ListAttestors()

	assert.Len(t, entries, 3)

	ids := make(map[string]bool)
	for _, entry := range entries {
		ids[entry.ID] = true
		assert.NotEmpty(t, entry.Name)
		assert.NotEmpty(t, entry.Description)
		assert.NotEmpty(t, entry.PredicateURI)
	}

	assert.True(t, ids["git"])
	assert.True(t, ids["sbom"])
	assert.True(t, ids["vuln"])
}

func TestListAttestorsByPredicateURI(t *testing.T) {
	registry := &Registry{
		attestorsByID:           make(map[string]Entry),
		attestorsByPredicateURI: make(map[string][]Entry),
	}

	// Register attestors with some sharing predicate URIs
	_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
		return NewMockAttestor("attestor1", "https://example.com/predicate1", "Attestor 1", "Test attestor 1")
	})

	_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
		return NewMockAttestor("attestor2", "https://example.com/predicate1", "Attestor 2", "Test attestor 2")
	})

	_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
		return NewMockAttestor("attestor3", "https://example.com/predicate2", "Attestor 3", "Test attestor 3")
	})

	tests := []struct {
		name         string
		predicateURI string
		expectedIDs  []string
	}{
		{
			name:         "multiple attestors with same predicate",
			predicateURI: "https://example.com/predicate1",
			expectedIDs:  []string{"attestor1", "attestor2"},
		},
		{
			name:         "single attestor with unique predicate",
			predicateURI: "https://example.com/predicate2",
			expectedIDs:  []string{"attestor3"},
		},
		{
			name:         "non-existent predicate URI",
			predicateURI: "https://example.com/nonexistent",
			expectedIDs:  []string{},
		},
		{
			name:         "empty predicate URI",
			predicateURI: "",
			expectedIDs:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := registry.ListAttestorsByPredicateURI(tt.predicateURI)

			assert.Len(t, entries, len(tt.expectedIDs))

			ids := make([]string, 0, len(entries))
			for _, entry := range entries {
				ids = append(ids, entry.ID)
				assert.Equal(t, tt.predicateURI, entry.PredicateURI)
			}

			for _, expectedID := range tt.expectedIDs {
				assert.Contains(t, ids, expectedID)
			}
		})
	}
}

func TestGlobalRegistry(t *testing.T) {
	// Test that global functions work with the global registry
	// Note: This test may be affected by other tests if they use the global registry

	testID := "global-test-attestor-unique"
	testURI := "https://example.com/global-test"

	defer func() {
		_, _ = GetAttestorByID(testID, logger.NewNoop())
	}()

	_ = RegisterAttestor(func(log logger.Logger) Attestor {
		return NewMockAttestor(
			testID,
			testURI,
			"Global Test Attestor",
			"Testing global registry",
		)
	})

	attestor, err := GetAttestorByID(testID, logger.NewNoop())
	require.NoError(t, err)
	assert.Equal(t, testID, attestor.ID())
	assert.Equal(t, testURI, attestor.PredicateURI())

	entries := ListAttestors()
	found := false
	for _, entry := range entries {
		if entry.ID == testID {
			found = true
			assert.Equal(t, testURI, entry.PredicateURI)
			break
		}
	}
	assert.True(t, found, "Attestor should be in global list")

	entriesByURI := ListAttestorsByPredicateURI(testURI)
	foundByURI := false
	for _, entry := range entriesByURI {
		if entry.ID == testID {
			foundByURI = true
			break
		}
	}
	assert.True(t, foundByURI, "Attestor should be found by predicate URI")
}

func TestRegistryThreadSafety(t *testing.T) {
	// This is a basic concurrency test to ensure no obvious race conditions
	// Run with -race flag to detect data races
	registry := &Registry{
		attestorsByID:           make(map[string]Entry),
		attestorsByPredicateURI: make(map[string][]Entry),
	}

	for i := range 10 {
		id := string(rune('a' + i))
		uri := "https://example.com/" + id
		_ = registry.RegisterAttestor(func(log logger.Logger) Attestor {
			return NewMockAttestor(id, uri, "Test "+id, "Test attestor "+id)
		})
	}

	done := make(chan bool)
	for i := range 10 {
		go func(idx int) {
			id := string(rune('a' + idx))
			_, _ = registry.GetAttestorByID(id, logger.NewNoop())
			_ = registry.ListAttestors()
			_ = registry.ListAttestorsByPredicateURI("https://example.com/" + id)
			done <- true
		}(i)
	}

	for range 10 {
		<-done
	}
}

func TestAttestorInterfaceCompliance(t *testing.T) {
	var _ Attestor = (*MockAttestor)(nil)

	mock := NewMockAttestor(
		"test",
		"https://example.com/test",
		"Test",
		"Test description",
	)

	assert.Equal(t, "test", mock.ID())
	assert.Equal(t, "https://example.com/test", mock.PredicateURI())
	assert.Equal(t, "Test", mock.Name())
	assert.Equal(t, "Test description", mock.Description())
	assert.NotNil(t, mock.ConfigSchema())
	assert.NoError(t, mock.ValidateConfig(Config{}))
	assert.NoError(t, mock.PreAttest(context.Background(), Config{}))
	assert.NoError(t, mock.Attest(context.Background(), Config{}))
	assert.NoError(t, mock.PostAttest(context.Background(), Config{}))

	predicate, err := mock.GeneratePredicate(Config{})
	require.NoError(t, err)
	assert.Nil(t, predicate)

	subjects := mock.Subjects(Config{})
	assert.NotNil(t, subjects)
	assert.Empty(t, subjects)

	schema := mock.Schema()
	assert.Nil(t, schema)
}
