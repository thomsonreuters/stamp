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

package validation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
)

func TestValidateSignerConfig(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*viper.Viper)
		wantErr bool
	}{
		{
			name: "empty signer type",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "")
			},
			wantErr: true,
		},
		{
			name: "invalid signer type",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "invalid")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateSignerConfig(cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFulcioSigner(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*viper.Viper)
		wantErr bool
	}{
		{
			name: "valid fulcio with oidc token",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
				v.Set(flags.OIDCToken, "test-token")
			},
			wantErr: false,
		},
		{
			name: "valid fulcio with oidc token file",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
				v.Set(flags.OIDCTokenFile, "/path/to/token")
			},
			wantErr: false,
		},
		{
			name: "valid fulcio with spire flag",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
				v.Set(flags.UseSpire, true)
			},
			wantErr: false,
		},
		{
			name: "valid fulcio with spire socket",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
				v.Set(flags.SPIRESocket, "/path/to/socket")
			},
			wantErr: false,
		},
		{
			name: "valid fulcio with github flag",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
				v.Set(flags.UseGitHub, true)
			},
			wantErr: false,
		},
		{
			name: "missing fulcio url",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.OIDCToken, "test-token")
			},
			wantErr: true,
		},
		{
			name: "missing token source",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment variables that might affect auto-detection
			t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
			t.Setenv("GITHUB_ACTIONS", "")

			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateSignerConfig(cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFulcioSignerWithAutoDetection(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*viper.Viper)
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "auto-detect spire from environment",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
			},
			envVars: map[string]string{
				"SPIFFE_ENDPOINT_SOCKET": "/run/spire/socket",
			},
			wantErr: false,
		},
		{
			name: "auto-detect github actions",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "fulcio")
				v.Set(flags.FulcioURL, "https://fulcio.sigstore.dev")
			},
			envVars: map[string]string{
				"GITHUB_ACTIONS": "true",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateSignerConfig(cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFileSigner(t *testing.T) {
	tmpDir := t.TempDir()
	validKeyFile := filepath.Join(tmpDir, "key.pem")
	err := os.WriteFile(validKeyFile, []byte("test key content"), 0600)
	require.NoError(t, err, "Failed to create test key file")

	tests := []struct {
		name    string
		setup   func(*viper.Viper)
		wantErr bool
	}{
		{
			name: "valid file signer with existing key",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "key")
				v.Set(flags.PrivateKey, validKeyFile)
			},
			wantErr: false,
		},
		{
			name: "missing private key path",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "key")
			},
			wantErr: true,
		},
		{
			name: "non-existent key file",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "key")
				v.Set(flags.PrivateKey, filepath.Join(tmpDir, "nonexistent.pem"))
			},
			wantErr: true,
		},
		{
			name: "directory instead of key file",
			setup: func(v *viper.Viper) {
				v.Set(flags.Signer, "key")
				v.Set(flags.PrivateKey, tmpDir)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			tt.setup(v)
			cfg := config.NewConfiguration(v)

			err := ValidateSignerConfig(cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
