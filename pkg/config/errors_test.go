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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentinelErrors_FlagDefinition(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrEmptyFlagName", ErrEmptyFlagName, "flag name cannot be empty"},
		{"ErrEmptyConfigPath", ErrEmptyConfigPath, "config path cannot be empty"},
		{"ErrEmptyHelp", ErrEmptyHelp, "help text cannot be empty"},
		{"ErrInvalidDefaultType", ErrInvalidDefaultType, "default value type mismatch"},
		{"ErrUnsupportedFlagType", ErrUnsupportedFlagType, "unsupported flag type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestSentinelErrors_FlagGroup(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrFlagNameMismatch", ErrFlagNameMismatch, "flag group key does not match flag name"},
		{"ErrFlagValidation", ErrFlagValidation, "flag validation failed"},
		{"ErrFlagGroupValidation", ErrFlagGroupValidation, "flag group validation failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestSentinelErrors_Workflow(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrEmptyWorkflowName", ErrEmptyWorkflowName, "workflow name is required"},
		{"ErrNoAttestors", ErrNoAttestors, "workflow must have at least one attestor"},
		{"ErrInvalidFailurePolicy", ErrInvalidFailurePolicy, "invalid failure policy"},
		{"ErrInvalidOutputMode", ErrInvalidOutputMode, "invalid output mode"},
		{"ErrDuplicateAttestor", ErrDuplicateAttestor, "duplicate attestor name"},
		{"ErrEmptyAttestorName", ErrEmptyAttestorName, "attestor name is required"},
		{"ErrEmptyAttestorType", ErrEmptyAttestorType, "attestor type is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestSentinelErrors_Wrapping(t *testing.T) {
	t.Run("ErrEmptyFlagName wrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("context: %w", ErrEmptyFlagName)
		require.ErrorIs(t, wrapped, ErrEmptyFlagName)
	})

	t.Run("ErrFlagValidation wrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("%w: flag test: %w", ErrFlagValidation, ErrEmptyConfigPath)
		require.ErrorIs(t, wrapped, ErrFlagValidation)
		require.ErrorIs(t, wrapped, ErrEmptyConfigPath)
	})

	t.Run("ErrFlagGroupValidation wrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("%w: group test: %w", ErrFlagGroupValidation, ErrFlagValidation)
		require.ErrorIs(t, wrapped, ErrFlagGroupValidation)
		require.ErrorIs(t, wrapped, ErrFlagValidation)
	})

	t.Run("ErrNoAttestors wrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("%w: spec test", ErrNoAttestors)
		require.ErrorIs(t, wrapped, ErrNoAttestors)
	})

	t.Run("ErrInvalidFailurePolicy wrapped", func(t *testing.T) {
		wrapped := fmt.Errorf("%w: spec %q has %q", ErrInvalidFailurePolicy, "test", "invalid")
		require.ErrorIs(t, wrapped, ErrInvalidFailurePolicy)
		assert.Contains(t, wrapped.Error(), "invalid failure policy")
	})
}
