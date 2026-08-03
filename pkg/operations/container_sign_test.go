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

package operations

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
	"github.com/thomsonreuters/stamp/pkg/signing/container"
	"github.com/thomsonreuters/stamp/pkg/signing/sigstore"
)

// writeTempECDSAKey writes an unencrypted PKCS#8 P-256 private key to a
// temp file and returns its path. Cleanup is handled by t.TempDir.
func writeTempECDSAKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestNewContainerSignOp(t *testing.T) {
	cfg := config.NewMockConfiguration()
	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	require.NotNil(t, op)
	assert.Same(t, cfg, op.config)
}

func TestRegistryCredsFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		pass     string
		wantNil  bool
		wantUser string
		wantPass string
	}{
		{"both unset", "", "", true, "", ""},
		{"username only", "user", "", true, "", ""},
		{"password only", "", "pw", true, "", ""},
		{"both set", "user", "pw", false, "user", "pw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envRegistryUsername, tt.user)
			t.Setenv(envRegistryPassword, tt.pass)

			got := registryCredsFromEnv()
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantUser, got.Username)
			assert.Equal(t, tt.wantPass, got.Password)
		})
	}
}

func TestContainerSignOp_Validate(t *testing.T) {
	tests := []struct {
		name       string
		imageRef   string
		signer     string
		privateKey string
		fulcioURL  string
		rekorOn    bool
		rekorURL   string
		envUser    string
		envPass    string
		wantErr    string
	}{
		{
			name:     "missing image ref",
			imageRef: "",
			signer:   "key", privateKey: "/tmp/k",
			envUser: "u", envPass: "p",
			wantErr: "image reference is required",
		},
		{
			name:     "empty signer",
			imageRef: "registry/app:v1", signer: "",
			envUser: "u", envPass: "p",
			wantErr: "--signer is required",
		},
		{
			name:     "unsupported signer",
			imageRef: "registry/app:v1", signer: "kms",
			envUser: "u", envPass: "p",
			wantErr: `unsupported signer "kms"`,
		},
		{
			name:     "key signer missing private key",
			imageRef: "registry/app:v1", signer: "key",
			envUser: "u", envPass: "p",
			wantErr: "--private-key is required",
		},
		{
			name:     "fulcio signer with malformed URL",
			imageRef: "registry/app:v1", signer: "fulcio", fulcioURL: "not-a-url",
			envUser: "u", envPass: "p",
			wantErr: "invalid Fulcio URL",
		},
		{
			name:     "rekor enabled with malformed URL",
			imageRef: "registry/app:v1", signer: "key", privateKey: "/tmp/k",
			rekorOn: true, rekorURL: "not-a-url",
			envUser: "u", envPass: "p",
			wantErr: "invalid Rekor URL",
		},
		{
			name:     "both registry env vars unset is valid (anonymous / keychain)",
			imageRef: "registry/app:v1", signer: "key", privateKey: "/tmp/k",
		},
		{
			name:     "registry password without username is rejected",
			imageRef: "registry/app:v1", signer: "key", privateKey: "/tmp/k",
			envPass: "p",
			wantErr: "must be set together",
		},
		{
			name:     "registry username without password is rejected",
			imageRef: "registry/app:v1", signer: "key", privateKey: "/tmp/k",
			envUser: "u",
			wantErr: "must be set together",
		},
		{
			name:     "valid key mode with creds",
			imageRef: "registry/app:v1", signer: "key", privateKey: "/tmp/k",
			envUser: "u", envPass: "p",
		},
		{
			name:     "valid fulcio mode with creds",
			imageRef: "registry/app:v1", signer: "fulcio", fulcioURL: "https://fulcio.example.com",
			envUser: "u", envPass: "p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envRegistryUsername, tt.envUser)
			t.Setenv(envRegistryPassword, tt.envPass)

			cfg := config.NewMockConfiguration()
			cfg.On("GetString", flags.Signer).Return(tt.signer)
			cfg.On("GetString", flags.PrivateKey).Return(tt.privateKey).Maybe()
			cfg.On("GetString", flags.FulcioURL).Return(tt.fulcioURL).Maybe()
			cfg.On("GetBool", flags.Insecure).Return(false).Maybe()
			cfg.On("GetBool", flags.TransparencyEnable).Return(tt.rekorOn)
			cfg.On("GetString", flags.RekorURL).Return(tt.rekorURL).Maybe()

			op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
			err := op.Validate(tt.imageRef)

			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			var v *pkgerrors.ValidationError
			require.ErrorAs(t, err, &v)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestContainerSignOp_buildSignOptions_KeyMode(t *testing.T) {
	t.Setenv(envRegistryUsername, "u")
	t.Setenv(envRegistryPassword, "p")

	keyPath := writeTempECDSAKey(t)

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("key")
	cfg.On("GetString", flags.PrivateKey).Return(keyPath)
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false)
	cfg.On("GetBool", flags.TransparencyEnable).Return(false).Maybe()
	cfg.On("GetString", flags.TSAURL).Return("").Maybe()

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	opts, err := op.buildSignOptions(context.Background())

	require.NoError(t, err)
	require.NotNil(t, opts.Key)
	require.NotNil(t, opts.Key.Signer)
	require.NotEmpty(t, opts.Key.Hint)
	require.NotNil(t, opts.Registry)
	cfg.AssertExpectations(t)
}

func TestContainerSignOp_buildSignOptions_FulcioMode(t *testing.T) {
	t.Setenv(envRegistryUsername, "u")
	t.Setenv(envRegistryPassword, "p")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("fulcio")
	cfg.On("GetString", flags.FulcioURL).Return("https://fulcio.example.com")
	cfg.On("GetString", flags.OIDCToken).Return("direct-token")
	cfg.On("GetString", flags.OIDCTokenFile).Return("")
	cfg.On("GetBool", flags.UseSpire).Return(false)
	cfg.On("GetString", flags.SPIRESocket).Return("")
	cfg.On("GetBool", flags.UseGitHub).Return(false)
	cfg.On("GetBool", flags.Insecure).Return(false)
	cfg.On("GetBool", flags.TransparencyEnable).Return(true)
	cfg.On("GetString", flags.RekorURL).Return("https://rekor.example.com")
	cfg.On("GetInt", flags.RekorVersion).Return(1).Maybe()
	cfg.On("GetString", flags.TSAURL).Return("").Maybe()

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	opts, err := op.buildSignOptions(context.Background())

	require.NoError(t, err)
	require.Nil(t, opts.Key)
	require.NotNil(t, opts.Fulcio)
	assert.Equal(t, "https://fulcio.example.com", opts.Fulcio.URL)
	assert.Equal(t, "direct-token", opts.Fulcio.IDToken)
	require.NotNil(t, opts.Rekor)
	assert.Equal(t, "https://rekor.example.com", opts.Rekor.URL)
	require.NotNil(t, opts.Registry)
	assert.Equal(t, "u", opts.Registry.Username)
	assert.Equal(t, "p", opts.Registry.Password)
	cfg.AssertExpectations(t)
}

func TestContainerSignOp_buildSignOptions_NoRegistryEnv(t *testing.T) {
	t.Setenv(envRegistryUsername, "")
	t.Setenv(envRegistryPassword, "")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("fulcio")
	cfg.On("GetString", flags.FulcioURL).Return("https://fulcio.example.com")
	cfg.On("GetString", flags.OIDCToken).Return("direct-token")
	cfg.On("GetString", flags.OIDCTokenFile).Return("")
	cfg.On("GetBool", flags.UseSpire).Return(false)
	cfg.On("GetString", flags.SPIRESocket).Return("")
	cfg.On("GetBool", flags.UseGitHub).Return(false)
	cfg.On("GetBool", flags.Insecure).Return(false)
	cfg.On("GetBool", flags.TransparencyEnable).Return(false)
	cfg.On("GetString", flags.TSAURL).Return("").Maybe()

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	opts, err := op.buildSignOptions(context.Background())

	require.NoError(t, err)
	assert.Nil(t, opts.Registry, "Registry should stay nil when env vars are unset (Validate is what enforces the requirement)")
	cfg.AssertExpectations(t)
}

func TestContainerSignOp_Execute_BuildSignOptionsError(t *testing.T) {
	t.Setenv(envRegistryUsername, "u")
	t.Setenv(envRegistryPassword, "p")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.Signer).Return("key")
	cfg.On("GetString", flags.PrivateKey).Return("/nonexistent/key.pem")
	cfg.On("GetString", flags.CryptographyKeyPassword).Return("")
	cfg.On("GetString", flags.CryptographyKeyPasswordFile).Return("")
	cfg.On("GetBool", flags.CryptographyKeyPasswordPrompt).Return(false)
	cfg.On("GetBool", flags.TransparencyEnable).Return(false).Maybe()

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	err := op.Execute(context.Background(), "registry.example.com/app:v1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load private key")
	cfg.AssertExpectations(t)
}

func TestContainerSignOp_writeBundle_File(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bundle.json")

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.ContainerSignOutput).Return(dest)
	cfg.On("GetBool", flags.ContainerSignOverwrite).Return(false).Maybe()

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	require.NoError(t, op.writeBundle(context.Background(), &container.Result{
		Result: sigstore.Result{BundleJSON: []byte(`{"ok":true}`)},
	}))

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, `{"ok":true}`, string(got))

	info, err := os.Stat(dest)
	require.NoError(t, err)
	// Windows doesn't honor Unix perm bits (always 0666 for writable files).
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "bundle must be 0600 to match cosign convention")
	}
}

func TestContainerSignOp_writeBundle_RefusesToOverwriteWithoutFlag(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(dest, []byte("existing"), 0o600))

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.ContainerSignOutput).Return(dest)
	cfg.On("GetBool", flags.ContainerSignOverwrite).Return(false)

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	err := op.writeBundle(context.Background(), &container.Result{
		Result: sigstore.Result{BundleJSON: []byte(`{"new":true}`)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "existing", string(got), "original bundle must be preserved")
}

func TestContainerSignOp_writeBundle_OverwritesWithFlag(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(dest, []byte("existing"), 0o600))

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.ContainerSignOutput).Return(dest)
	cfg.On("GetBool", flags.ContainerSignOverwrite).Return(true)

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	require.NoError(t, op.writeBundle(context.Background(), &container.Result{
		Result: sigstore.Result{BundleJSON: []byte(`{"new":true}`)},
	}))

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, `{"new":true}`, string(got))
}

func TestContainerSignOp_writeBundle_Stdout(t *testing.T) {
	// Redirect os.Stdout to a temp file for the duration of the call so
	// we can capture what writeBundle emits. Reassigning os.Stdout is a
	// test-only pattern; the reassign lint is silenced accordingly.
	orig := os.Stdout
	t.Cleanup(func() { os.Stdout = orig }) //nolint:reassign // test-only stdout capture; restored on cleanup

	tmp := filepath.Join(t.TempDir(), "stdout.txt")
	f, err := os.Create(tmp)
	require.NoError(t, err)
	os.Stdout = f //nolint:reassign // test-only stdout capture; restored on cleanup

	cfg := config.NewMockConfiguration()
	cfg.On("GetString", flags.ContainerSignOutput).Return("")

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	require.NoError(t, op.writeBundle(context.Background(), &container.Result{
		Result: sigstore.Result{BundleJSON: []byte(`{"bundle":true}`)},
	}))
	require.NoError(t, f.Close())

	got, err := os.ReadFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, "{\"bundle\":true}\n", string(got))
}

func TestContainerSignOp_writeBundle_FileError(t *testing.T) {
	cfg := config.NewMockConfiguration()
	// Point at a nonexistent directory to force an os.OpenFile failure.
	cfg.On("GetString", flags.ContainerSignOutput).Return("/nonexistent-dir/bundle.json")
	cfg.On("GetBool", flags.ContainerSignOverwrite).Return(false).Maybe()

	op := NewContainerSignOp(cfg, logger.NewNoop(), output.NewNoop())
	err := op.writeBundle(context.Background(), &container.Result{Result: sigstore.Result{BundleJSON: []byte("x")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open bundle for writing")
}
