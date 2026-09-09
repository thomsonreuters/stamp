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

package fulcio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveAudienceFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "HTTPS URL with path",
			url:      "https://fulcio.sigstore.dev/api/v2",
			expected: "fulcio.sigstore.dev",
		},
		{
			name:     "HTTPS URL without path",
			url:      "https://fulcio.sigstore.dev",
			expected: "fulcio.sigstore.dev",
		},
		{
			name:     "HTTPS URL with port",
			url:      "https://fulcio.example.com:8443/api",
			expected: "fulcio.example.com:8443",
		},
		{
			name:     "HTTP URL",
			url:      "http://localhost:5555",
			expected: "localhost:5555",
		},
		{
			name:     "URL with trailing slash",
			url:      "https://fulcio.example.com/",
			expected: "fulcio.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audience, err := deriveAudienceFromURL(tt.url)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, audience)
		})
	}
}

func TestDeriveAudienceFromURL_EmptyURL(t *testing.T) {
	audience, err := deriveAudienceFromURL("")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "Fulcio URL is required")
}

func TestDeriveAudienceFromURL_InvalidURL(t *testing.T) {
	audience, err := deriveAudienceFromURL("://invalid-url")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "failed to parse Fulcio URL")
}

func TestDeriveAudienceFromURL_NoHost(t *testing.T) {
	audience, err := deriveAudienceFromURL("file:///path/to/file")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "Fulcio URL has no host")
}
