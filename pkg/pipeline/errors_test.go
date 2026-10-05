// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pipeline

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrUnsupportedSigningBackend", ErrUnsupportedSigningBackend, "unsupported signing backend"},
		{"ErrSignerInitFailed", ErrSignerInitFailed, "failed to initialize signer"},
		{"ErrSigningFailed", ErrSigningFailed, "failed to sign envelope"},
		{"ErrGetSignerFailed", ErrGetSignerFailed, "failed to get signer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestAttestorErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrAttestorNotFound", ErrAttestorNotFound, "attestor not found"},
		{"ErrAttestorConfigFailed", ErrAttestorConfigFailed, "failed to get attestor configuration"},
		{"ErrAttestorConfigUnmarshalFailed", ErrAttestorConfigUnmarshalFailed, "failed to unmarshal attestor configuration"},
		{"ErrAttestorConfigValidationFailed", ErrAttestorConfigValidationFailed, "attestor configuration validation failed"},
		{"ErrSetFlagsParsingFailed", ErrSetFlagsParsingFailed, "failed to parse --set flags"},
		{"ErrPreAttestFailed", ErrPreAttestFailed, "pre-attest phase failed"},
		{"ErrAttestFailed", ErrAttestFailed, "attest phase failed"},
		{"ErrPostAttestFailed", ErrPostAttestFailed, "post-attest phase failed"},
		{"ErrPredicateGenerationFailed", ErrPredicateGenerationFailed, "predicate generation failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestEnvelopeErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrStatementCreateFailed", ErrStatementCreateFailed, "failed to create statement"},
		{"ErrEnvelopeCreateFailed", ErrEnvelopeCreateFailed, "failed to create envelope"},
		{"ErrEnvelopeConvertFailed", ErrEnvelopeConvertFailed, "failed to convert envelope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestOutputErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrStdoutWriteFailed", ErrStdoutWriteFailed, "failed to write to stdout"},
		{"ErrInvalidOutputMode", ErrInvalidOutputMode, "invalid output mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestWorkflowErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrWorkflowLoadFailed", ErrWorkflowLoadFailed, "failed to load workflows"},
		{"ErrWorkflowNotFound", ErrWorkflowNotFound, "workflow not found"},
		{"ErrWorkflowExecutionFailed", ErrWorkflowExecutionFailed, "workflow execution failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestCollectionErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrCollectionCreateFailed", ErrCollectionCreateFailed, "failed to create collection"},
		{"ErrCollectionSignFailed", ErrCollectionSignFailed, "failed to sign collection"},
		{"ErrNoAttestationsForCollection", ErrNoAttestationsForCollection, "no attestations available for collection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestErrorsIs(t *testing.T) {
	// Test that errors can be wrapped and unwrapped correctly
	wrappedErr := fmt.Errorf("context: %w", ErrUnsupportedSigningBackend)
	require.ErrorIs(t, wrappedErr, ErrUnsupportedSigningBackend)
	assert.NotErrorIs(t, wrappedErr, ErrSignerInitFailed)
}

func TestErrorsUniqueness(t *testing.T) {
	// Ensure all errors are distinct
	allErrors := []error{
		ErrUnsupportedSigningBackend,
		ErrSignerInitFailed,
		ErrSigningFailed,
		ErrGetSignerFailed,
		ErrAttestorNotFound,
		ErrAttestorConfigFailed,
		ErrAttestorConfigUnmarshalFailed,
		ErrAttestorConfigValidationFailed,
		ErrSetFlagsParsingFailed,
		ErrPreAttestFailed,
		ErrAttestFailed,
		ErrPostAttestFailed,
		ErrPredicateGenerationFailed,
		ErrStatementCreateFailed,
		ErrEnvelopeCreateFailed,
		ErrEnvelopeConvertFailed,
		ErrStdoutWriteFailed,
		ErrInvalidOutputMode,
		ErrWorkflowLoadFailed,
		ErrWorkflowNotFound,
		ErrWorkflowExecutionFailed,
		ErrCollectionCreateFailed,
		ErrCollectionSignFailed,
		ErrNoAttestationsForCollection,
	}

	seen := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}
