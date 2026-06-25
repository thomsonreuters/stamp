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

package transparency

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rekor "github.com/thomsonreuters/stamp/pkg/clients/rekor/v1"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		insecure    bool
		setupMock   func()
		wantErr     bool
		wantBaseURL string
	}{
		{
			name:        "success with custom URL",
			baseURL:     "https://custom.rekor.example.com",
			insecure:    false,
			wantErr:     false,
			wantBaseURL: "https://custom.rekor.example.com",
		},
		{
			name:        "success with empty URL uses default",
			baseURL:     "",
			insecure:    false,
			wantErr:     false,
			wantBaseURL: rekor.DefaultRekorURL,
		},
		{
			name:     "success with insecure flag",
			baseURL:  "http://localhost:3000",
			insecure: true,
			wantErr:  false,
		},
		{
			name:    "error from rekor.New",
			baseURL: "https://rekor.example.com",
			setupMock: func() {
				rekor.New = func(opts rekor.Options) (rekor.ClientIface, error) { //nolint:reassign // Test mock: intentional reassignment for dependency injection
					return nil, errors.New("connection failed")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original and restore after test
			originalNew := rekor.New
			defer func() { rekor.New = originalNew }() //nolint:reassign // Test cleanup: restoring original dependency

			if tt.setupMock != nil {
				tt.setupMock()
			}

			client, err := NewClient(tt.baseURL, tt.insecure, logger.NewNoop())

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, client)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)

			if tt.wantBaseURL != "" {
				assert.Equal(t, tt.wantBaseURL, client.baseURL)
			}
		})
	}
}

func TestNewClient_WithNilLogger(t *testing.T) {
	client, err := NewClient("https://rekor.example.com", false, nil)
	require.NoError(t, err)
	require.NotNil(t, client)
}
