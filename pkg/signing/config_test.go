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

package signing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerConfig_Validate_Success(t *testing.T) {
	config := SignerConfig{
		Provider: "key",
	}

	err := config.Validate()

	require.NoError(t, err)
}

func TestSignerConfig_Validate_MissingProvider(t *testing.T) {
	config := SignerConfig{}

	err := config.Validate()

	require.Error(t, err)
	require.ErrorIs(t, err, ErrProviderRequired)
}

func TestSignerConfig_Validate_EmptyProvider(t *testing.T) {
	config := SignerConfig{
		Provider: "",
	}

	err := config.Validate()

	require.Error(t, err)
	require.ErrorIs(t, err, ErrProviderRequired)
}

func TestSignerConfig_Validate_WithKeyConfig(t *testing.T) {
	config := SignerConfig{
		Provider: "key",
		Key: &KeySignerConfig{
			KeyPath: "/path/to/key",
		},
	}

	err := config.Validate()

	require.NoError(t, err)
}

func TestSignerConfig_Validate_WithFulcioConfig(t *testing.T) {
	config := SignerConfig{
		Provider: "fulcio",
		Fulcio: &FulcioSignerConfig{
			FulcioURL: "https://fulcio.example.com",
		},
	}

	err := config.Validate()

	require.NoError(t, err)
}

func TestKeySignerConfig_Fields(t *testing.T) {
	config := KeySignerConfig{
		KeyPath:         "/path/to/key",
		KeyPassword:     "secret",
		KeyPasswordFile: "/path/to/password",
	}

	assert.Equal(t, "/path/to/key", config.KeyPath)
	assert.Equal(t, "secret", config.KeyPassword)
	assert.Equal(t, "/path/to/password", config.KeyPasswordFile)
}

func TestFulcioSignerConfig_Fields(t *testing.T) {
	config := FulcioSignerConfig{
		FulcioURL:        "https://fulcio.example.com",
		Token:            "token123",
		TokenPath:        "/path/to/token",
		UseSpire:         true,
		SpireAgentSocket: "unix:///tmp/spire.sock",
		UseGitHub:        true,
		Insecure:         true,
	}

	assert.Equal(t, "https://fulcio.example.com", config.FulcioURL)
	assert.Equal(t, "token123", config.Token)
	assert.Equal(t, "/path/to/token", config.TokenPath)
	assert.True(t, config.UseSpire)
	assert.Equal(t, "unix:///tmp/spire.sock", config.SpireAgentSocket)
	assert.True(t, config.UseGitHub)
	assert.True(t, config.Insecure)
}

func TestErrProviderRequired(t *testing.T) {
	assert.Equal(t, "provider is required", ErrProviderRequired.Error())
}
