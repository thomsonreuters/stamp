// Copyright 2025 Thomson Reuters
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

package sigstore

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNewSigner(t *testing.T) {
	s := NewSigner(logger.NewNoop())
	require.NotNil(t, s)
	assert.NotNil(t, s.logger)
}

func TestSigner_SignBundle_InvalidOptions(t *testing.T) {
	s := NewSigner(logger.NewNoop())
	_, err := s.SignBundle(context.Background(), []byte("payload"), "application/vnd.in-toto+json", Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one of Key or Fulcio is required")
}

func TestWrapSignBundleError(t *testing.T) {
	tests := []struct {
		name        string
		underlying  error
		rekor       bool
		wantContain string
	}{
		{
			name: "rekor TextConsumer failure gets a policy hint",
			underlying: errors.New(
				`&{0 } (*models.Error) is not supported by the TextConsumer, can be resolved by supporting TextUnmarshaler interface`,
			),
			rekor:       true,
			wantContain: "Rekor rejected the upload with a non-JSON response",
		},
		{
			name:        "rekor generic failure passes through",
			underlying:  errors.New("connection refused"),
			rekor:       true,
			wantContain: "sigstore sign: sign.Bundle",
		},
		{
			name:        "TextConsumer without rekor enabled is generic",
			underlying:  errors.New(`(*models.Error) is not supported by the TextConsumer`),
			rekor:       false,
			wantContain: "sigstore sign: sign.Bundle",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapSignBundleError(tt.underlying, tt.rekor)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantContain)
			assert.ErrorIs(t, err, tt.underlying, "wrapped error must expose the underlying via errors.Is/Unwrap")
		})
	}
}
