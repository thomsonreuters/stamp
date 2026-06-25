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

//go:build linux || darwin

package spire

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// createTestSocket creates a temporary Unix socket for testing.
// Uses /tmp directly to avoid path length issues on macOS.
func createTestSocket(t *testing.T) string {
	t.Helper()

	// Use a short path in /tmp to avoid Unix socket path length limits
	socketPath := fmt.Sprintf("/tmp/spire-test-%d.sock", time.Now().UnixNano())

	listener, err := net.Listen("unix", socketPath) //nolint:noctx // Test fixture: context not needed for test socket setup
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})

	return "unix://" + socketPath
}

func TestNew(t *testing.T) {
	socketPath := createTestSocket(t)

	client, err := New(t.Context(), Options{SocketPath: socketPath})

	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNew_WithCustomSocketPath(t *testing.T) {
	socketPath := createTestSocket(t)

	client, err := New(t.Context(), Options{SocketPath: socketPath})

	require.NoError(t, err)
	assert.NotNil(t, client)

	c, _ := client.(*Client)
	assert.Equal(t, socketPath, c.opts.SocketPath)
}

func TestNew_InvalidSocketPath(t *testing.T) {
	client, err := New(t.Context(), Options{SocketPath: "unix:///nonexistent/path.sock"})

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
	assert.Nil(t, client)
}

func TestNew_DefaultSocketPath_NotExists(t *testing.T) {
	t.Setenv(SocketPathEnvVar, "unix:///nonexistent/default.sock")

	client, err := New(t.Context(), Options{})

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
	assert.Nil(t, client)
}

func TestOptions_Validate_ValidSocket(t *testing.T) {
	socketPath := createTestSocket(t)

	opts := Options{SocketPath: socketPath}
	err := opts.Validate()

	require.NoError(t, err)
}

func TestOptions_Validate_InvalidSocket(t *testing.T) {
	opts := Options{SocketPath: "unix:///nonexistent/path.sock"}
	err := opts.Validate()

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
}

func TestOptions_Validate_NotASocket(t *testing.T) {
	// Create a regular file, not a socket
	tmpFile, err := os.CreateTemp("/tmp", "spire-test-*.txt")
	require.NoError(t, err)
	_ = tmpFile.Close()
	t.Cleanup(func() {
		_ = os.Remove(tmpFile.Name())
	})

	opts := Options{SocketPath: "unix://" + tmpFile.Name()}
	err = opts.Validate()

	require.Error(t, err)
	require.ErrorIs(t, err, utils.ErrSocketNotFound)
}
