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

package jwt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestAcquireToken_NoSource(t *testing.T) {
	attestor := &Attestor{
		logger: logger.NewNoop(),
		config: Config{},
	}

	_, _, err := attestor.acquireToken(t.Context())
	assert.ErrorIs(t, err, ErrNoTokenSource)
}

func TestAcquireFromFile(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"

	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		expectError bool
		expectedErr error
	}{
		{
			name: "valid token file",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "token")
				err := os.WriteFile(path, []byte(validToken), 0600)
				require.NoError(t, err)
				return path
			},
			expectError: false,
		},
		{
			name: "token with whitespace",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "token")
				err := os.WriteFile(path, []byte("  "+validToken+"\n\t"), 0600)
				require.NoError(t, err)
				return path
			},
			expectError: false,
		},
		{
			name: "file not found",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/token"
			},
			expectError: true,
			expectedErr: ErrTokenNotFound,
		},
		{
			name: "empty file",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "token")
				err := os.WriteFile(path, []byte(""), 0600)
				require.NoError(t, err)
				return path
			},
			expectError: true,
			expectedErr: ErrEmptyToken,
		},
		{
			name: "invalid token format",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "token")
				err := os.WriteFile(path, []byte("not-a-jwt"), 0600)
				require.NoError(t, err)
				return path
			},
			expectError: true,
			expectedErr: ErrInvalidTokenFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile(t)
			attestor := &Attestor{logger: logger.NewNoop()}

			token, source, err := attestor.acquireFromFile(filePath)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectedErr != nil {
					require.ErrorIs(t, err, tt.expectedErr)
				}
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.Equal(t, validToken, token)
				assert.Contains(t, source, SourceFile)
			}
		})
	}
}

func TestAcquireFromEnv(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"

	tests := []struct {
		name        string
		envVar      string
		envValue    string
		expectError bool
		expectedErr error
	}{
		{
			name:        "valid token in env",
			envVar:      "TEST_JWT_TOKEN",
			envValue:    validToken,
			expectError: false,
		},
		{
			name:        "env var not set",
			envVar:      "NONEXISTENT_VAR",
			envValue:    "",
			expectError: true,
			expectedErr: ErrTokenNotFound,
		},
		{
			name:        "invalid token format",
			envVar:      "TEST_JWT_INVALID",
			envValue:    "not-a-jwt",
			expectError: true,
			expectedErr: ErrInvalidTokenFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(tt.envVar, tt.envValue)
			} else {
				_ = os.Unsetenv(tt.envVar)
			}

			attestor := &Attestor{logger: logger.NewNoop()}

			token, source, err := attestor.acquireFromEnv(tt.envVar)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectedErr != nil {
					require.ErrorIs(t, err, tt.expectedErr)
				}
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.Equal(t, validToken, token)
				assert.Contains(t, source, SourceEnv)
			}
		})
	}
}

func TestValidateTokenFormat(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "valid JWT format",
			token:       "header.payload.signature",
			expectError: false,
		},
		{
			name:        "valid real JWT",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature",
			expectError: false,
		},
		{
			name:        "missing parts",
			token:       "header.payload",
			expectError: true,
		},
		{
			name:        "too many parts",
			token:       "a.b.c.d",
			expectError: true,
		},
		{
			name:        "no dots",
			token:       "notajwt",
			expectError: true,
		},
		{
			name:        "empty parts",
			token:       "..signature",
			expectError: true,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}
			err := attestor.validateTokenFormat(tt.token)

			if tt.expectError {
				assert.ErrorIs(t, err, ErrInvalidTokenFormat)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAcquireToken_PriorityOrder(t *testing.T) {
	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenPath, []byte(validToken), 0600)
	require.NoError(t, err)

	tests := []struct {
		name           string
		config         Config
		expectedSource string
	}{
		{
			name: "file takes priority",
			config: Config{
				TokenFile: tokenPath,
			},
			expectedSource: SourceFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: tt.config,
			}

			_, source, err := attestor.acquireToken(t.Context())
			require.NoError(t, err)
			assert.Contains(t, source, tt.expectedSource)
		})
	}
}
