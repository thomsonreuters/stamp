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

//go:build windows

package spire

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// Note: Unlike Unix tests, we cannot easily create a real named pipe for testing
// on Windows. The following tests cover error cases only. Valid pipe tests would
// require a running SPIRE agent or complex Windows API calls to create named pipes.

func TestNew_InvalidSocketPath(t *testing.T) {
	client, err := New(t.Context(), Options{SocketPath: "npipe:\\nonexistent\\pipe"})

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
	assert.Nil(t, client)
}

func TestNew_WithCustomSocketPath_Invalid(t *testing.T) {
	customPath := "npipe:\\custom\\nonexistent\\pipe"

	client, err := New(t.Context(), Options{SocketPath: customPath})

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
	assert.Nil(t, client)
}

func TestNew_DefaultSocketPath_NotExists(t *testing.T) {
	t.Setenv(SocketPathEnvVar, "npipe:\\nonexistent\\default\\pipe")

	client, err := New(t.Context(), Options{})

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
	assert.Nil(t, client)
}

func TestOptions_Validate_InvalidSocket(t *testing.T) {
	opts := Options{SocketPath: "npipe:\\nonexistent\\path"}
	err := opts.Validate()

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
}

func TestOptions_Validate_NotAPipe(t *testing.T) {
	// Create a regular file, not a named pipe
	tmpFile, err := os.CreateTemp(t.TempDir(), "spire-test-*.txt")
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	// Try to validate a regular file path as a named pipe
	opts := Options{SocketPath: "npipe:" + tmpFile.Name()}
	err = opts.Validate()

	// Should fail because it's not a named pipe
	assert.Error(t, err)
}
