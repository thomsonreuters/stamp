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
	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        core.Config
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config with token file",
			config: core.Config{
				"jwt-token-file": createTempFile(t, "token"),
			},
			expectError: false,
		},
		{
			name: "valid config with from-stdin",
			config: core.Config{
				"jwt-from-stdin": true,
			},
			expectError: false,
		},
		{
			name: "valid config with from-env",
			config: core.Config{
				"jwt-from-env": "JWT_TOKEN",
			},
			expectError: false,
		},
		{
			name: "valid config with github auto-discover",
			config: core.Config{
				"jwt-auto-discover-github": true,
			},
			expectError: false,
		},
		{
			name: "valid config with aws auto-discover",
			config: core.Config{
				"jwt-auto-discover-aws": true,
			},
			expectError: false,
		},
		{
			name: "valid config with kubernetes auto-discover",
			config: core.Config{
				"jwt-auto-discover-kubernetes": true,
			},
			expectError: false,
		},
		{
			name:          "no token source configured",
			config:        core.Config{},
			expectError:   true,
			errorContains: "no JWT token source",
		},
		{
			name: "multiple token sources configured",
			config: core.Config{
				"jwt-token-file": "/path/to/token",
				"jwt-from-stdin": true,
			},
			expectError:   true,
			errorContains: "multiple JWT token sources",
		},
		{
			name: "token file does not exist",
			config: core.Config{
				"jwt-token-file": "/nonexistent/path/token",
			},
			expectError:   true,
			errorContains: "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{logger: logger.NewNoop()}
			err := attestor.ValidateConfig(tt.config)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTokenSource(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		expectedErr error
	}{
		{
			name:        "no source configured",
			config:      Config{},
			expectError: true,
			expectedErr: ErrNoTokenSource,
		},
		{
			name: "single source - token file",
			config: Config{
				TokenFile: "/path/to/token",
			},
			expectError: false,
		},
		{
			name: "single source - stdin",
			config: Config{
				FromStdin: true,
			},
			expectError: false,
		},
		{
			name: "single source - env",
			config: Config{
				FromEnv: "JWT_TOKEN",
			},
			expectError: false,
		},
		{
			name: "single source - github",
			config: Config{
				AutoDiscoverGitHub: true,
			},
			expectError: false,
		},
		{
			name: "multiple sources",
			config: Config{
				TokenFile: "/path/to/token",
				FromStdin: true,
			},
			expectError: true,
			expectedErr: ErrMultipleTokenSources,
		},
		{
			name: "three sources",
			config: Config{
				TokenFile:          "/path/to/token",
				FromEnv:            "JWT_TOKEN",
				AutoDiscoverGitHub: true,
			},
			expectError: true,
			expectedErr: ErrMultipleTokenSources,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: tt.config,
			}

			err := attestor.validateTokenSource()

			if tt.expectError {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFilePaths(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  func(t *testing.T) Config
		expectError bool
	}{
		{
			name: "all files exist",
			setupFiles: func(t *testing.T) Config {
				return Config{
					TokenFile:     createTempFile(t, "token"),
					PublicKeyFile: createTempFile(t, "key"),
					CACert:        createTempFile(t, "ca"),
				}
			},
			expectError: false,
		},
		{
			name: "token file does not exist",
			setupFiles: func(t *testing.T) Config {
				return Config{
					TokenFile: "/nonexistent/token",
				}
			},
			expectError: true,
		},
		{
			name: "public key file does not exist",
			setupFiles: func(t *testing.T) Config {
				return Config{
					PublicKeyFile: "/nonexistent/key.pem",
				}
			},
			expectError: true,
		},
		{
			name: "ca cert does not exist",
			setupFiles: func(t *testing.T) Config {
				return Config{
					CACert: "/nonexistent/ca.pem",
				}
			},
			expectError: true,
		},
		{
			name: "empty paths are valid",
			setupFiles: func(t *testing.T) Config {
				return Config{}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupFiles(t)
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: config,
			}

			err := attestor.validateFilePaths()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAlgorithms(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectError   bool
		errorContains string
	}{
		{
			name:        "no algorithms configured",
			config:      Config{},
			expectError: false,
		},
		{
			name: "valid allowed algorithms",
			config: Config{
				AllowedAlgorithms: []string{"RS256", "ES256"},
			},
			expectError: false,
		},
		{
			name: "valid denied algorithms",
			config: Config{
				DeniedAlgorithms: []string{"none", "HS256"},
			},
			expectError: false,
		},
		{
			name: "invalid allowed algorithm",
			config: Config{
				AllowedAlgorithms: []string{"INVALID"},
			},
			expectError:   true,
			errorContains: "invalid algorithm",
		},
		{
			name: "invalid denied algorithm",
			config: Config{
				DeniedAlgorithms: []string{"NOTREAL"},
			},
			expectError:   true,
			errorContains: "invalid algorithm",
		},
		{
			name: "algorithm in both lists",
			config: Config{
				AllowedAlgorithms: []string{"RS256", "ES256"},
				DeniedAlgorithms:  []string{"RS256"},
			},
			expectError:   true,
			errorContains: "both allow and deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: tt.config,
			}

			err := attestor.validateAlgorithms()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateClaimsFiltering(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectError   bool
		errorContains string
	}{
		{
			name:        "no claims filtering",
			config:      Config{},
			expectError: false,
		},
		{
			name: "valid allowlist",
			config: Config{
				ClaimsAllowlist: []string{"custom1", "custom2"},
			},
			expectError: false,
		},
		{
			name: "valid denylist",
			config: Config{
				ClaimsDenylist: []string{"internal", "debug"},
			},
			expectError: false,
		},
		{
			name: "both allowlist and denylist",
			config: Config{
				ClaimsAllowlist: []string{"custom1"},
				ClaimsDenylist:  []string{"internal"},
			},
			expectError:   true,
			errorContains: "cannot specify both",
		},
		{
			name: "valid redact claims",
			config: Config{
				RedactClaims: []string{"email", "phone"},
			},
			expectError: false,
		},
		{
			name: "standard claim in allowlist (warning only)",
			config: Config{
				ClaimsAllowlist: []string{"iss", "sub"},
			},
			expectError: false, // Only warns, doesn't error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &Attestor{
				logger: logger.NewNoop(),
				config: tt.config,
			}

			err := attestor.validateClaimsFiltering()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "testfile")
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)
	return path
}
