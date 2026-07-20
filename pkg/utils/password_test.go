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

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadPasswordFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "password.txt")
	err := os.WriteFile(passwordFile, []byte("file-password\n"), 0600)
	require.NoError(t, err)

	password, err := ReadPasswordFromFile(passwordFile)
	require.NoError(t, err)
	assert.Equal(t, "file-password", password)
}

func TestReadPasswordFromFile_WithWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "password.txt")
	err := os.WriteFile(passwordFile, []byte("  trimmed-password  \n"), 0600)
	require.NoError(t, err)

	password, err := ReadPasswordFromFile(passwordFile)
	require.NoError(t, err)
	assert.Equal(t, "trimmed-password", password)
}

func TestReadPasswordFromFile_NotFound(t *testing.T) {
	password, err := ReadPasswordFromFile("/nonexistent/password.txt")
	require.Error(t, err)
	assert.Empty(t, password)
	require.ErrorIs(t, err, ErrPasswordFileFailed)
}

func TestResolveKeyPassword_Precedence(t *testing.T) {
	// --password wins over --password-file wins over --prompt. A prompt
	// call would fail in `go test` (no TTY), so an incorrect precedence
	// that falls through to prompt would surface as an error — the
	// direct-and-file cases proving they never reach prompt.
	pwFile := filepath.Join(t.TempDir(), "pw.txt")
	require.NoError(t, os.WriteFile(pwFile, []byte("from-file"), 0o600))

	tests := []struct {
		name string
		cfg  KeyPasswordConfig
		want string
	}{
		{
			name: "direct wins over file and prompt",
			cfg:  KeyPasswordConfig{Password: "direct-value", PasswordFile: pwFile, PromptEnabled: true},
			want: "direct-value",
		},
		{
			name: "file used when direct is empty",
			cfg:  KeyPasswordConfig{PasswordFile: pwFile},
			want: "from-file",
		},
		{
			name: "empty when nothing is set (unencrypted key)",
			cfg:  KeyPasswordConfig{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveKeyPassword(tt.cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrNotTerminal", ErrNotTerminal, "not running in a terminal"},
		{"ErrEmptyPassword", ErrEmptyPassword, "password cannot be empty"},
		{"ErrPasswordMismatch", ErrPasswordMismatch, "passwords do not match"},
		{"ErrPasswordReadFailed", ErrPasswordReadFailed, "failed to read password"},
		{"ErrPasswordFileFailed", ErrPasswordFileFailed, "failed to read password file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}
